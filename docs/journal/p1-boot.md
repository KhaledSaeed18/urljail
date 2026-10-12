# P1: Boot a microVM by hand

- Status: **in progress**
- Started: 2026-10-12
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
| Docker | stopped for P1 (`docker`, `docker.socket`) |
| firewalld | **running** (zone `FedoraWorkstation` on `wlp2s0`); its forward chain also decides whether guest NAT works |
| `ip_forward` | already `1` (set by Docker) |
| auditd | active: SELinux denials go to `/var/log/audit/audit.log` (root only), not the journal |
| sudo | scoped NOPASSWD rule `/etc/sudoers.d/urljail-dev` for `ip`, `firewall-cmd`, `nft`, `sysctl` only. Remove with `sudo rm /etc/sudoers.d/urljail-dev` |
| RAM available | ~5 GiB |
| `squashfs-tools` | installed |

## Checklist

- [x] `sudo dnf install squashfs-tools` (for `unsquashfs`)
- [x] Stop Docker for the phase: `sudo systemctl stop docker docker.socket`
- [x] Q7 quick look: CI kernel has `CONFIG_VMGENID=y`; Firecracker CHANGELOG: x86_64 VMGenID added in 1.8.0, HID fixed in 1.16.0
- [x] Unsquash the rootfs, add a throwaway SSH key, build `ubuntu-24.04.ext4` (rootless, ~5 s)
- [x] Boot through the API socket with `curl --unix-socket`, no network, Firecracker unprivileged
- [x] Create `tap0` by hand (user-owned); boot with networking
- [x] Serial console (autologin as root)
- [x] SSH into the guest
- [x] Host NAT for the guest (dev only); `curl https://example.com` from the guest → HTTP 200. Guest's public IP = home IP, as expected in dev mode
- [x] Q7: device `VMGENCTR:00` present, bound to the `vmgenid` platform driver. Reseed-on-restore is tested in P4
- [x] Measure cold boot time (API `InstanceStart` → SSH ready), 5 runs
- [ ] SELinux denials: journal has none, but auditd keeps them in `audit.log`; confirm with `sudo ausearch -m avc -ts today` (needs your terminal)
- [x] Turn the steps into `scripts/p1/boot.sh` + `teardown.sh`; 5 boot/teardown cycles from a clean state, nothing left over
- [ ] Review all docs against what was learned (carried over from P0)
- [ ] Restart Docker; confirm it doesn't break anything here

## Timings

| Run | Boot to SSH ready | Notes |
| --- | ----------------- | ----- |
| 0 | n/a (no network) | `systemd-analyze`: 790 ms kernel + 629 ms userspace = 1.42 s; 2 vCPU, 1024 MiB, `--enable-pci`. Guest sees 984 MiB, 144 MiB used at the prompt |
| hand | 1852 ms | first networked boot, typed by hand |
| 1 | 2104 ms | `boot.sh`; teardown 1611 ms |
| 2 | 2142 ms | teardown 1678 ms |
| 3 | 2082 ms | teardown 1640 ms |
| 4 | 2157 ms | teardown 1648 ms |
| 5 | 2096 ms | teardown 1540 ms |

Cold boot to SSH is a steady **~2.1 s** (spread 75 ms). That includes up to ~100 ms of polling granularity in `boot.sh`. Teardown is ~1.6 s, mostly the guest's own shutdown after Ctrl-Alt-Del. For P4's target (restore-to-navigation < 1 s), cold boot alone already rules out booting per run, which is the case for snapshots.

## Gotchas

_(one bullet per surprise: symptom → cause → fix)_

- **CI bucket TLS error:** `https://spec.ccfc.min.s3.amazonaws.com` fails certificate checks because the bucket name has dots → use path-style `https://s3.amazonaws.com/spec.ccfc.min/...`.
- **CI layout changed:** no `firecracker-ci/v1.17/` folder; artifacts live under dated prefixes (`firecracker-ci/YYYYMMDD-<sha>-N/`). The v1.17 getting-started guide picks the latest one. S3 gives only multipart ETags, so pin your own SHA-256s.
- **Rootfs without sudo:** the guide uses `sudo chown` + `sudo mkfs.ext4`. `podman unshare` (uid 0 inside a user namespace) does the same rootless; `mkfs.ext4 -d` records the in-namespace ownership. Every file in the upstream squashfs is `0/0`, including `/etc/shadow`, so nothing is lost.
- **Firecracker needs no root here:** `/dev/kvm` is `0666` and there's no TAP yet, so the VMM ran as the normal user. Networking is the first step that needs root.
- **Driving the serial console from scripts:** stdin from a FIFO, with a background `sleep` holding the write end open; write commands with `echo ... > serial.in`. Don't wait for `root@`: the kernel banner (`Linux version ... (root@<builder>)`) matches it. Wait for the actual prompt instead.
- **VMGenID driver location:** on 6.10+ kernels it's a platform driver (`/sys/bus/platform/drivers/vmgenid`), not under `/sys/bus/acpi/drivers/`.
- **Shutdown:** `reboot` in the guest, or the API action `SendCtrlAltDel`, makes Firecracker exit cleanly (`exit_code=0`) with `reboot=k`.
- **`$!` after `setsid` lies:** `setsid` forks when it's already a process-group leader, so `$!` was the PID of a short-lived `setsid`, and teardown missed a running Firecracker. Fix: each child writes its own PID (`sh -c 'echo $$ > fc.pid; exec firecracker ...'`). `teardown.sh` also scans for any `firecracker` with our `--api-sock` as a backstop. Lesson for the daemon: track VMMs by more than a PID file (pidfd / cgroup).
- **Deleting the API socket orphans the VM:** after the socket file is removed, the running VMM can't be reached for a graceful shutdown; only a signal works. Delete the socket only after the process is gone.
- **The guest has no default route or DNS** after boot (the CI image only configures the address from the MAC). `boot.sh` adds both over SSH.
- **sudo can't prompt through Claude Code's `!` prefix** (no TTY), and Fedora's sudo caches credentials per TTY. Solved with a scoped NOPASSWD sudoers drop-in (see host state).
- **Cleanup trap:** `pkill -f "sleep 3600"` matched the shell running it and killed it. Track helper PIDs in files instead.

## SELinux denials

_(denial, context, how it was resolved; never `setenforce 0`)_

- None seen in the journal. Not conclusive: auditd is active, so AVCs go to `audit.log`. Firecracker runs as `unconfined_t` from a `data_home_t` binary in P1, so few denials are expected; the real SELinux work is P5 (jailer as root, chroot, mknod).

## Docker interaction

- **Stopping Docker doesn't remove its rules.** Its `ip filter` table stays loaded with `chain FORWARD { policy drop; }` at priority `filter` (0). firewalld's forward chain (priority `filter + 10`) accepted `tap0 → wlp2s0`, but Docker's chain had already dropped the packets: in netfilter, a drop in any base chain on a hook is final, while an accept only ends that chain.
- Fix: two rules in Docker's documented `DOCKER-USER` chain (`iifname tap0 accept`, `oifname tap0 ct state established,related accept`), tagged with the comment `urljail-p1` so `teardown.sh` deletes exactly those.
- So the guide's step 2 ("stop Docker") alone wasn't enough; with Docker running, the same `DOCKER-USER` rules should do the job. Still to check: restart Docker, run `boot.sh`, confirm egress.
- **firewalld** also filters forwarding. `tap0` goes in zone `trusted` (runtime only), and masquerade is enabled on the default zone only if it wasn't already on. `trusted` also lets the guest reach the host and LAN, which is acceptable for P1 only.

## Design changes

_(anything that changes architecture, network, guest-image or an ADR; link the doc update)_

- **Q3 / [ADR 0009](../decisions/0009-debian-guest-ci-kernel.md):** the CI kernel already has `CONFIG_VMGENID=y` and the driver binds, so VMGenID alone no longer forces your own kernel in P4. Your own config may still be worth it for trimming and restore speed; decide in P4 with measurements.
- **Docker isn't the only forward filter:** firewalld runs on this host too, and Docker's tables outlive the Docker service. The netns design keeps the VM's forwarding inside dedicated namespaces (each netns has its own netfilter hooks), so neither should apply there. But the host-side hop out of `uj-egress` (dev mode NAT, and WireGuard's UDP) still crosses the host's hooks. `urljail doctor` should report firewalld, Docker's tables (even with Docker stopped) and their forward policies.
