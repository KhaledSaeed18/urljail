#!/usr/bin/env bash
# Build the Debian 13 + Google Chrome guest image, rootless (ADR 0009, ADR 0012).
#
#   images/debian-chrome/build.sh
#
# Output: ~/.local/share/urljail/images/debian13-chrome-<version>/
#   rootfs.ext4     the guest root filesystem
#   vmlinux         symlink to the pinned Firecracker CI kernel
#   manifest.json   versions and SHA-256s of every input and output
set -euo pipefail

REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/urljail"

# --- pinned inputs ---
BASE=docker.io/library/debian@sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483  # trixie-slim, 2026-10-05
CHROME_VERSION=155.0.8059.39-1
CHROME_SHA256=c58aa0f2cd66179c9f050e062c882d27aa9b9f8c2b7c73fee3498560b5ed0b38  # Google's apt Packages index
KERNEL="$DATA/ci/20261008-40f3a4819490-0/vmlinux-6.18.51"
KERNEL_SHA256=946e164b5a50675341a5d0a6ac2b516711806267ed0c73e17c6289c97aad81ea

DEB="$DATA/cache/google-chrome-stable_${CHROME_VERSION}_amd64.deb"
NAME="debian13-chrome-${CHROME_VERSION%-*}"
OUT="$DATA/images/$NAME"
TAG="localhost/urljail-guest:${CHROME_VERSION%-*}"

log() { printf '[image] %s\n' "$*"; }

log "verifying inputs"
if [ ! -e "$DEB" ]; then
    mkdir -p "$(dirname "$DEB")"
    curl -sSfL -o "$DEB.part" "https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/$(basename "$DEB")"
    mv "$DEB.part" "$DEB"
fi
sha256sum -c --quiet <<SUMS
$CHROME_SHA256  $DEB
$KERNEL_SHA256  $KERNEL
SUMS

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT

log "building guest binaries"
export PATH="$HOME/.local/go/bin:$PATH"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$CTX/" ./cmd/urljail-init ./cmd/urljail-agent)
cp "$REPO/images/debian-chrome/Containerfile" "$REPO/images/debian-chrome/chrome-policy.json" "$CTX/"
cp --reflink=auto "$DEB" "$CTX/chrome.deb"

log "podman build $TAG"
podman build -q --build-arg BASE="$BASE" -t "$TAG" -f "$CTX/Containerfile" "$CTX" >/dev/null

log "creating ext4 image"
mkdir -p "$OUT"
CTR="$(podman create "$TAG")"
trap 'podman rm -f "$CTR" >/dev/null 2>&1 || true; rm -rf "$CTX"' EXIT
# Inside the user namespace, files show their in-image owners (root, urljail), and
# mkfs.ext4 -d records those.
podman unshare bash -euo pipefail -c '
    mnt="$(podman mount "$1")"
    # Files the container runtime manages at run time; set them for the VM instead.
    ln -sfn /proc/net/pnp "$mnt/etc/resolv.conf"   # DNS server from the kernel ip= argument
    echo urljail-guest > "$mnt/etc/hostname"
    printf "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 urljail-guest\n" > "$mnt/etc/hosts"
    size_mb=$(( $(du -sm "$mnt" | cut -f1) * 13 / 10 + 256 ))
    rm -f "$2"
    truncate -s "${size_mb}M" "$2"
    mkfs.ext4 -q -L urljail-root -d "$mnt" -F "$2"
    podman umount "$1" >/dev/null
' _ "$CTR" "$OUT/rootfs.ext4.tmp"
mv "$OUT/rootfs.ext4.tmp" "$OUT/rootfs.ext4"
ln -sfn "$KERNEL" "$OUT/vmlinux"

log "writing manifest"
python3 - "$OUT/manifest.json" <<PY
import hashlib, json, sys, datetime, subprocess
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
rev = subprocess.run(["git", "-C", "$REPO", "describe", "--always", "--dirty"], capture_output=True, text=True).stdout.strip()
json.dump({
    "name": "$NAME",
    "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "urljail": rev,
    "base": "$BASE",
    "browser": {"package": "google-chrome-stable", "version": "$CHROME_VERSION", "sha256": "$CHROME_SHA256"},
    "kernel": {"name": "vmlinux-6.18.51", "sha256": "$KERNEL_SHA256"},
    "init": "/sbin/urljail-init",
    "binaries": {"urljail-init": sha("$CTX/urljail-init"), "urljail-agent": sha("$CTX/urljail-agent")},
    "rootfs_sha256": sha("$OUT/rootfs.ext4"),
}, open(sys.argv[1], "w"), indent=2)
PY
log "done: $OUT ($(du -h --apparent-size "$OUT/rootfs.ext4" | cut -f1))"
