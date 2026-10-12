# Pinned P1 inputs. Source it: `. scripts/p1/env.sh`
# Artifacts live outside the repo; see docs/journal/p1-boot.md for how they were fetched.

FC_VERSION=v1.17.0
FC_BIN="$HOME/.local/bin/firecracker"
JAILER_BIN="$HOME/.local/bin/jailer"

CI_PREFIX=firecracker-ci/20261008-40f3a4819490-0
CI_DIR="$HOME/.local/share/urljail/ci/20261008-40f3a4819490-0"
KERNEL="$CI_DIR/vmlinux-6.18.51"
KERNEL_CONFIG="$CI_DIR/vmlinux-6.18.51.config"
ROOTFS_SQUASHFS="$CI_DIR/ubuntu-24.04.squashfs"

KERNEL_SHA256=946e164b5a50675341a5d0a6ac2b516711806267ed0c73e17c6289c97aad81ea
KERNEL_CONFIG_SHA256=47194037099c5ca0645c7b0530c40c2d40033cfa067bd20b6f5367bcd5206b58
ROOTFS_SQUASHFS_SHA256=1d50b8fff4410e9fbe29de5b65f4a4b74efb901ab14071288cd8fb4a753f0fdd

# Writable P1 state: built ext4 image, throwaway SSH key, API socket, logs
WORK_DIR="$HOME/.local/share/urljail/p1"

urljail_p1_verify() {
    sha256sum -c --quiet <<SUMS
$KERNEL_SHA256  $KERNEL
$KERNEL_CONFIG_SHA256  $KERNEL_CONFIG
$ROOTFS_SQUASHFS_SHA256  $ROOTFS_SQUASHFS
SUMS
}
