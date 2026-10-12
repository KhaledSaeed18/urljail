# 0009: Debian 13 slim guest, CI kernel until P4, new headless as baseline

- Status: Accepted
- Date: 2026-10-12

## Context
The guest has to run a realistic desktop Chromium, boot and restore quickly, and support clone safety (VMGenID) from P4. Early phases should be spent learning Firecracker, not tuning kernels (open questions Q2, Q3, Q15).

## Decision
- **Rootfs:** Debian 13 ("trixie") slim, built with debootstrap into an ext4 image (read-only base plus a per-run writable overlay).
- **Kernel:** Firecracker's CI guest kernel for P1–P3. From P4, your own config based on Firecracker's recommended guest config, with `CONFIG_VMGENID` enabled.
- **Display:** `--headless=new` with no display server is the baseline through P5. Headful under Xvfb or cage is added in P6 as an anti-cloaking profile, and its RAM and boot cost is measured then.

## Alternatives considered
- **Alpine:** smaller, but Chromium on musl drifts from what real users run, which undermines the authentic-fingerprint goal.
- **Ubuntu minimal:** workable, but larger than Debian slim and adds snap-related friction for browser packages.
- **Your own kernel from day one:** delays P1 for no benefit until snapshots exist.
- **Headful from the start:** costs RAM and boot time on a 7 GiB laptop before you know it changes any outcome.

## Consequences
- The P4 kernel config must keep virtio-net, virtio-block and virtio-vsock and add `CONFIG_VMGENID`. Firecracker-side VMGenID support is checked in P1 (Q7).
- Headless vs headful becomes a measured research variable ([research/anti-cloaking.md](../research/anti-cloaking.md)) rather than a design assumption.
- Still open: Debian's `chromium` package vs Google's official Chrome build (Q17).
