#!/usr/bin/env bash
# Boot one Firecracker microVM with networking (dev only: host NAT, no isolation).
#
#   scripts/p1/boot.sh            # build rootfs if missing, set up tap0 + NAT, boot, wait for SSH
#   scripts/p1/boot.sh --no-net   # boot without a network card (serial console only)
#
# Firecracker runs as the calling user (/dev/kvm is 0666, tap0 is user-owned).
# Network setup uses sudo for ip, firewall-cmd and nft only. Undo everything with teardown.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/env.sh"

NET=1
[ "${1:-}" = "--no-net" ] && NET=0

TAP=tap0
HOST_IP=172.16.0.1
GUEST_IP=172.16.0.2
GUEST_MAC=06:00:AC:10:00:02   # the CI rootfs derives 172.16.0.2 from this MAC
TAG=urljail-p1                # comment on our nft rules, so teardown can find them

SOCK="$WORK_DIR/fc.socket"
ROOTFS="$WORK_DIR/ubuntu-24.04.ext4"
KEY="$WORK_DIR/id_ed25519"
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=1 "root@$GUEST_IP")

log() { printf '[boot] %s\n' "$*"; }
die() { printf '[boot] error: %s\n' "$*" >&2; exit 1; }

if [ -e "$WORK_DIR/fc.pid" ] && kill -0 "$(cat "$WORK_DIR/fc.pid")" 2>/dev/null; then
    die "a VM is already running (pid $(cat "$WORK_DIR/fc.pid")); run teardown.sh first"
fi

mkdir -p "$WORK_DIR"
urljail_p1_verify || die "artifact checksums don't match env.sh"

# --- rootfs: unpack CI squashfs, add SSH key, build ext4 (rootless via a user namespace) ---
if [ ! -e "$ROOTFS" ]; then
    log "building rootfs"
    [ -e "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "$TAG" -f "$KEY"
    (cd "$WORK_DIR" && podman unshare sh -ec '
        unsquashfs -q -d squashfs-root "$1" >/dev/null
        mkdir -p squashfs-root/root/.ssh
        cp "$2.pub" squashfs-root/root/.ssh/authorized_keys
        chown -R 0:0 squashfs-root/root/.ssh
        chmod 700 squashfs-root/root/.ssh
        chmod 600 squashfs-root/root/.ssh/authorized_keys
        truncate -s 1G "$3"
        mkfs.ext4 -q -d squashfs-root -F "$3"
        rm -rf squashfs-root
    ' _ "$ROOTFS_SQUASHFS" "$KEY" "$ROOTFS")
fi

# --- network: user-owned TAP, firewalld NAT, Docker's leftover FORWARD drop ---
if [ "$NET" = 1 ]; then
    if ! ip link show "$TAP" >/dev/null 2>&1; then
        log "creating $TAP"
        sudo -n ip tuntap add dev "$TAP" mode tap user "$USER" group "$USER"
        sudo -n ip addr add "$HOST_IP/30" dev "$TAP"
        sudo -n ip link set "$TAP" up
    fi
    [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || sudo -n sysctl -q -w net.ipv4.ip_forward=1

    if systemctl is-active -q firewalld; then
        zone=$(sudo -n firewall-cmd --get-default-zone)
        sudo -n firewall-cmd -q --zone=trusted --query-interface="$TAP" \
            || sudo -n firewall-cmd -q --zone=trusted --add-interface="$TAP"
        if ! sudo -n firewall-cmd -q --zone="$zone" --query-masquerade; then
            sudo -n firewall-cmd -q --zone="$zone" --add-masquerade
            echo "$zone" > "$WORK_DIR/masquerade.zone"   # only undo what we added
        fi
    fi

    # Stopping Docker leaves its ip filter FORWARD chain (policy drop) loaded.
    if sudo -n nft list chain ip filter DOCKER-USER >/dev/null 2>&1 \
        && ! sudo -n nft list chain ip filter DOCKER-USER | grep -q "$TAG"; then
        sudo -n nft add rule ip filter DOCKER-USER iifname "$TAP" counter accept comment "\"$TAG\""
        sudo -n nft add rule ip filter DOCKER-USER oifname "$TAP" ct state related,established counter accept comment "\"$TAG\""
    fi
fi

# --- VMM: serial console on a FIFO so commands can be written to it ---
cd "$WORK_DIR"
rm -f "$SOCK" serial.in serial.out fc.log fc.pid holder.pid
mkfifo serial.in
touch fc.log
# setsid may fork, so $! isn't reliable: each child writes its own PID, then execs.
setsid sh -c 'echo $$ > holder.pid; exec sleep infinity' > serial.in 2>/dev/null &
setsid sh -c 'echo $$ > fc.pid; exec "$0" --api-sock "$1" --enable-pci' "$FC_BIN" "$SOCK" \
    < serial.in > serial.out 2>&1 &
for _ in $(seq 50); do [ -s fc.pid ] && [ -s holder.pid ] && break; sleep 0.05; done
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || die "API socket never appeared; see $WORK_DIR/serial.out"

api() {
    local code
    code=$(curl -sS -o "$WORK_DIR/api.err" -w '%{http_code}' -X PUT --unix-socket "$SOCK" \
        -H 'Content-Type: application/json' --data "$2" "http://localhost/$1")
    [ "$code" = 204 ] || die "PUT /$1 returned $code: $(cat "$WORK_DIR/api.err")"
}

api logger "{\"log_path\":\"$WORK_DIR/fc.log\",\"level\":\"Info\",\"show_level\":true}"
api boot-source "{\"kernel_image_path\":\"$KERNEL\",\"boot_args\":\"console=ttyS0 reboot=k panic=1\"}"
api drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"$ROOTFS\",\"is_root_device\":true,\"is_read_only\":false}"
[ "$NET" = 1 ] && api network-interfaces/net1 "{\"iface_id\":\"net1\",\"guest_mac\":\"$GUEST_MAC\",\"host_dev_name\":\"$TAP\"}"
api machine-config '{"vcpu_count":2,"mem_size_mib":1024}'

t0=$(date +%s%N)
api actions '{"action_type":"InstanceStart"}'
log "started (pid $(cat fc.pid)); console log: $WORK_DIR/serial.out"

if [ "$NET" = 0 ]; then
    log "no network: write commands with  echo '<cmd>' > $WORK_DIR/serial.in"
    exit 0
fi

for _ in $(seq 150); do "${SSH[@]}" true 2>/dev/null && break; sleep 0.1; done
"${SSH[@]}" true 2>/dev/null || die "SSH not ready after 15 s"
t1=$(date +%s%N)
log "SSH ready $(( (t1 - t0) / 1000000 )) ms after InstanceStart"

"${SSH[@]}" "ip route replace default via $HOST_IP dev eth0 && echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
log "guest has default route + DNS. Connect with:"
log "  ssh -i $KEY root@$GUEST_IP"
