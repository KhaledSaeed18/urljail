# Guest image

Status: **design draft**. What runs inside the microVM, and how the snapshot is produced.

## Components

| Piece | Choice (draft) | Notes |
| ----- | -------------- | ----- |
| Boot args | `console=ttyS0 reboot=k panic=1 clocksource=kvm-clock init=/sbin/urljail-init ip=...` | `clocksource=kvm-clock`: Linux otherwise switches to `tsc` and a restored guest's wall clock resumes from snapshot time (found in P4) |
| Kernel | Minimal x86_64 config based on Firecracker's recommended guest config | Needs virtio-net, virtio-block, virtio-vsock, `CONFIG_VMGENID` (Firecracker v1.17.0 exposes VMGenID; confirmed in P1), `CONFIG_PTP_1588_CLOCK_VMCLOCK`. Firecracker CI kernel for P1–P3, this config from P4 ([ADR 0009](./decisions/0009-debian-guest-ci-kernel.md)). A **Linux ≥ 7.0** base is wanted in P4: VMClock's `vm_generation_counter` and `poll()` for userspace landed in 7.0, and they let the guest agent detect a restore (see [snapshot entropy](./research/snapshot-entropy.md)) |
| Rootfs | Debian 13 ("trixie") slim (ext4 image), read-only base + per-run writable overlay | Debian packages Chromium and its many deps reliably; Alpine/musl is smaller but Chromium on musl adds risk |
| Init | Tiny init (or systemd-free shell init) | Fast boot; no extra listeners. For scale: the CI Ubuntu image with systemd took 629 ms of userspace boot in P1 |
| Transport | VirtIO over PCI (`--enable-pci`), available since Firecracker 1.13 and recommended by its getting-started guide | Used in P1; needs PCI support in the guest kernel (Firecracker `kernel-policy.md`) |
| IPv6 | disabled in the guest | v1 has no IPv6 egress; the CI image brings up link-local IPv6 by default |
| Browser | Google Chrome stable from Google's `.deb`, version pinned, `.deb` archived with its SHA-256, self-update removed ([ADR 0012](./decisions/0012-google-chrome-stable-in-guest.md)) | Rebuild image on every Chrome stable release |
| Guest agent | Go, `CGO_ENABLED=0`, static | Talks AF_VSOCK to host; drives Chromium via chromedp |
| Fonts | Liberation, DejaVu, Noto (incl. CJK and color emoji) | Missing fonts are a fingerprint signal (see [anti-cloaking](./research/anti-cloaking.md)); M4's first screenshot showed tofu for CJK until `fonts-noto-cjk` was added |
| Init | `urljail-init` (Go, PID 1): mounts, loopback, `/dev/vsock` for the agent's group, reaper, Ctrl-Alt-Del → reboot | No systemd; agent reachable 1.38 s after VMM start |

## Chromium configuration

Enterprise policy (`/etc/opt/chrome/policies/managed/urljail.json`) + flags.

| Setting | Value | Why |
| ------- | ----- | --- |
| `--remote-debugging-pipe` | on | CDP over a pipe, **no TCP debug port**, so nothing for a page to reach via DNS rebinding to localhost. Client: [ADR 0013](./decisions/0013-own-cdp-client-over-pipe.md); only `Network` + `Page` enabled, no `Runtime.enable` |
| `--disable-background-networking` | on | Cuts Chrome's background requests to Google (component updates, variations, most GCM) that would be noise in the host capture; not observable by pages. Some GCM traffic (`mtalk.google.com`) remains, as in real Chrome: the report should label it, not hide it |
| `--window-size` | 1920,1080 | Common desktop size; headless-new reports a realistic smaller viewport (1920×993 in M4) |
| Tab | the tab Chrome opens at startup | A tab from `Target.createTarget` is a background tab: `visibilityState` hidden, throttled timers, no paint until a screenshot forces one (found in M4) |
| Sandbox | on, as uid 1000 | Guest kernel has user/PID/net namespaces + seccomp; never `--no-sandbox` |
| `--disable-quic` | on | Keep traffic on TCP so SNI/TLS is observable (also dropped at firewall) |
| `EncryptedClientHelloEnabled` policy | false | ECH would hide the real SNI behind the CDN's public name |
| `DnsOverHttpsMode` policy | off | All DNS must go to our resolver |
| `SSLKEYLOGFILE` env | `/run/urljail/sslkeys.log` | Offline decryption of host pcap; no MITM |
| Headless mode | `--headless=new`, no display server, through P5; headful under Xvfb or cage added in P6 as an anti-cloaking profile, RAM/boot cost measured then | New headless is the real browser; old headless is trivially detected |
| Profile | fresh temp profile per snapshot, created before snapshot | No history, cookies, caches from earlier runs |
| Safe Browsing / telemetry / updates | off | Don't phone home; don't let Google's verdict change page behavior |
| Downloads | to `/run/urljail/downloads`, `noexec` | Hashed and shipped, never opened |

No GPU device exists in Firecracker, so WebGL is software-rendered (SwiftShader). This is a known bot signal and a planned research variable, not something to hide in v1.

## Snapshot procedure (Phase 4)

As built (P4 M1, `internal/daemon/snapshot.go`; the daemon builds it at start when missing or stale):

1. Reflink the image's rootfs into `snapshots/<image>-baseline.build/rootfs.ext4`.
2. Boot in an **isolated** namespace `uj-vm-build`: `tap0` configured exactly as in every VM namespace (same address, same fixed MAC `06:00:AC:10:00:01`), but no link out. Whatever the guest sends goes nowhere (34 packets during a build: DNS attempts and Chrome's startup requests).
3. Agent `Prepare`: launch Chrome, attach to its startup tab, enable `Network`/`Page`/lifecycle, set download behavior. Wait 2 s for Chrome to settle.
4. Pause, full snapshot (`vmstate`, `mem`), kill. The disk as it is now becomes the snapshot's `rootfs.ext4`; files `0600`.
5. Manifest: image name and rootfs SHA-256, Firecracker version, vCPUs, memory, boot args. Any difference at daemon start means a rebuild.

**Restore per run** (`vm.Restore`): reflink the snapshot's disk into the run's work directory and start Firecracker *in that directory*: the snapshot recorded `rootfs.ext4` and `v.sock` as relative paths, which Firecracker resolves "at the same relative paths" on restore, so each clone opens its own disk. `vsock_override` gives each clone its own socket; `clock_realtime` advances kvmclock to now; the memory file is mapped `MAP_PRIVATE` and shared through the page cache.

Original plan:

```
1. Cold-boot VM (kernel + rootfs) with the fixed per-clone network config (172.16.0.2/30, fixed MAC)
2. Guest agent starts, launches Chromium, opens about:blank, waits until idle
3. NO network activity yet (no DNS cache, no TLS sessions, no cookies in the snapshot)
4. Host: pause VM → create snapshot (vmstate + memory file) → record snapshot id + versions
5. Clones: restore from (vmstate, memory) in their own netns; host sends SyncClock + Reseed
```

Snapshot "profiles" = different browser configurations (baseline, stealth variants) for the anti-cloaking experiments. Each profile is a separate snapshot.

## Clone-safety checklist (each restore)

- [x] Wall clock right before navigation: `clock_realtime` + `clocksource=kvm-clock`; skew recorded per run (~214 ms) and checked by the self-test
- [x] Kernel RNG reseeded: VMGenID, logged by the guest kernel, recorded per run, checked by the self-test
- [x] TLS randomness independent: 0 repeats of client random, session ID or X25519 key share over 34,955 ClientHellos from 2,614 restores (BoringSSL reads the reseeded kernel) ([research/snapshot-entropy.md](./research/snapshot-entropy.md))
- [ ] Page JavaScript randomness (`Math.random()`): **cloned** in a renderer from before the snapshot (22 Google Analytics client IDs repeated across 46 runs, 2026-10-19). Fix: the agent replaces the snapshot's renderers before navigating ([renderer.go](../cmd/urljail-agent/renderer.go)); written and tested against Chrome 155 on the host, not yet in the image. Check after the rebuild: GA client IDs never repeat
- [x] Disk is fresh per run: reflink of the snapshot's disk in the run's work directory
- [x] Network identity unique outside: each clone's own VM namespace, SNAT to `10.200.<n>.2`

## Image build

Reproducible script in `images/` (later): build kernel → debootstrap rootfs → install Chromium + fonts + policy → copy guest agent → produce `rootfs.ext4` + `vmlinux` + a manifest with hashes and versions. Built rootless where possible (e.g. inside podman), output artifacts only.
