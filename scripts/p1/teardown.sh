#!/usr/bin/env bash
# Stop the P1 microVM and undo everything boot.sh set up. Safe to run repeatedly.
#
#   scripts/p1/teardown.sh           # stop VM, remove tap0, firewalld and nft changes
#   scripts/p1/teardown.sh --keep-net  # stop VM only
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/env.sh"

TAP=tap0
TAG=urljail-p1
SOCK="$WORK_DIR/fc.socket"

log() { printf '[teardown] %s\n' "$*"; }

alive() { [ -e "$WORK_DIR/$1" ] && kill -0 "$(cat "$WORK_DIR/$1")" 2>/dev/null; }

# --- VM: ask the guest to reboot (with reboot=k Firecracker then exits), then force ---
if alive fc.pid; then
    pid=$(cat "$WORK_DIR/fc.pid")
    [ -S "$SOCK" ] && curl -sS -o /dev/null -X PUT --unix-socket "$SOCK" \
        -H 'Content-Type: application/json' --data '{"action_type":"SendCtrlAltDel"}' \
        http://localhost/actions 2>/dev/null
    for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then
        log "VM didn't exit after Ctrl-Alt-Del; killing pid $pid"
        kill -KILL "$pid"
    else
        log "VM exited"
    fi
fi
for pid in $(pgrep -u "$USER" -x firecracker); do
    if tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q -- "--api-sock $SOCK"; then
        log "stray firecracker (pid $pid) not in fc.pid; killing"
        kill -KILL "$pid"
    fi
done
alive holder.pid && kill "$(cat "$WORK_DIR/holder.pid")"
rm -f "$SOCK" "$WORK_DIR/serial.in" "$WORK_DIR/fc.pid" "$WORK_DIR/holder.pid" "$WORK_DIR/api.err"

[ "${1:-}" = "--keep-net" ] && exit 0

# --- network ---
if sudo -n nft list chain ip filter DOCKER-USER >/dev/null 2>&1; then
    sudo -n nft -a list chain ip filter DOCKER-USER | grep "$TAG" | grep -oE 'handle [0-9]+$' |
        while read -r _ h; do sudo -n nft delete rule ip filter DOCKER-USER handle "$h"; done
fi

if systemctl is-active -q firewalld; then
    sudo -n firewall-cmd -q --zone=trusted --query-interface="$TAP" \
        && sudo -n firewall-cmd -q --zone=trusted --remove-interface="$TAP"
    if [ -e "$WORK_DIR/masquerade.zone" ]; then
        sudo -n firewall-cmd -q --zone="$(cat "$WORK_DIR/masquerade.zone")" --remove-masquerade
        rm -f "$WORK_DIR/masquerade.zone"
    fi
fi

if ip link show "$TAP" >/dev/null 2>&1; then
    sudo -n ip link del "$TAP"
    log "removed $TAP"
fi
log "done"
