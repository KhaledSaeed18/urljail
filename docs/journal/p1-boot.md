# P1: Boot a microVM by hand

- Status: **ready to start**
- Started: _(date)_
- Closed: _(date)_
- Roadmap: [P1](../roadmap.md#p1-boot-a-microvm-by-hand)
- Exit: reproducible shell script that boots a VM with networking; this entry filled in with timings and every gotcha.

## Safety for this phase

There is **no network isolation** until P3. A guest using host NAT can reach the home LAN and router. Only Firecracker's CI rootfs and benign URLs (example.com and similar). Nothing from a phishing feed, not even "just to try it".

## Pinned inputs

Installed 2026-10-12, user-local (no root). Paths and hashes are also in [scripts/p1/env.sh](../../scripts/p1/env.sh).

| Item | Version | Where | SHA-256 |
| ---- | ------- | ----- | ------- |
| Go | 1.27.2 | `~/.local/go` (PATH via `~/.bashrc.d/go.sh`) | `ecbadb99…6045fe5` (tarball, matched go.dev) |
| Firecracker + jailer | v1.17.0 | `~/.local/share/urljail/firecracker/release-v1.17.0-x86_64/`, symlinked in `~/.local/bin` | `06094a11…9ade558` (tarball, matched the release's `.sha256.txt`; every binary matched `SHA256SUMS`) |
| Guest kernel | 6.18.51 (Firecracker CI) | `~/.local/share/urljail/ci/20261008-40f3a4819490-0/vmlinux-6.18.51` | `946e164b…aad81ea` (+ `.config`: `47194037…5206b58`) |
| Guest rootfs | Ubuntu 24.04 squashfs (Firecracker CI) | `~/.local/share/urljail/ci/20261008-40f3a4819490-0/ubuntu-24.04.squashfs` | `1d50b8ff…53f0fdd` |

CI artifacts come from the dated prefix `firecracker-ci/20261008-40f3a4819490-0/`, which the v1.17.0 getting-started guide selects with "latest `YYYYMMDD-*` prefix". S3 only provides multipart ETags for them, so the SHA-256s above are our own pins, taken at download (integrity relies on TLS to S3). Sizes matched the S3 listing. Re-check any time with `. scripts/p1/env.sh && urljail_p1_verify`.

## Host state at start

| Check | State |
| ----- | ----- |
| `/dev/kvm` | present, `0666` |
| SELinux | Enforcing |
| Docker | **active**: stop it for P1 (see checklist) |
| RAM available | ~5 GiB |
| `squashfs-tools` | **missing**: needs `sudo dnf install squashfs-tools` |

## Checklist

- [ ] `sudo dnf install squashfs-tools` (for `unsquashfs`)
- [ ] Stop Docker for the phase: `sudo systemctl stop docker docker.socket`; note what changes in `nft list ruleset`
- [ ] Q7 quick look: `grep VMGENID vmlinux-6.18.51.config` (CI kernel config) + Firecracker v1.17.0 CHANGELOG
- [ ] Unsquash the rootfs, add a throwaway SSH key, build `ubuntu-24.04.ext4`
- [ ] Create `tap0` by hand; boot through the API socket with `curl --unix-socket`
- [ ] Serial console + SSH into the guest
- [ ] Host NAT for the guest (dev only); `curl https://example.com` from the guest
- [ ] Q7: `dmesg | grep -i vmgenid` in the guest
- [ ] Measure cold boot time (API `InstanceStart` → login prompt / SSH ready), at least 5 runs
- [ ] SELinux denials: `sudo ausearch -m avc -ts recent` after each step
- [ ] Turn the steps into `scripts/p1/boot.sh` (+ `teardown.sh`) and run them from a clean state
- [ ] Review all docs against what was learned (carried over from P0)
- [ ] Restart Docker; confirm it doesn't break anything here

## Timings

| Run | Boot to SSH ready | Notes |
| --- | ----------------- | ----- |

## Gotchas

_(one bullet per surprise: symptom → cause → fix)_

## SELinux denials

_(denial, context, how it was resolved; never `setenforce 0`)_

## Docker interaction

## Design changes

_(anything that changes architecture, network, guest-image or an ADR; link the doc update)_
