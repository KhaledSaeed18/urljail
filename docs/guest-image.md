# Guest image

Status: **design draft**. What runs inside the microVM, and how the snapshot is produced.

## Components

| Piece | Choice (draft) | Notes |
| ----- | -------------- | ----- |
| Kernel | Minimal x86_64 config based on Firecracker's recommended guest config | Needs virtio-net, virtio-block, virtio-vsock, `CONFIG_VMGENID` _(verify Firecracker exposes VMGenID on this version)_. Firecracker CI kernel for P1–P3, this config from P4 ([ADR 0009](./decisions/0009-debian-guest-ci-kernel.md)) |
| Rootfs | Debian 13 ("trixie") slim (ext4 image), read-only base + per-run writable overlay | Debian packages Chromium and its many deps reliably; Alpine/musl is smaller but Chromium on musl adds risk |
| Init | Tiny init (or systemd-free shell init) | Fast boot; no extra listeners |
| Browser | Chromium, version pinned and recorded. Distro package vs Google's official build is still open (Q17 in [open-questions.md](./open-questions.md)) | Rebuild image on every Chromium security release |
| Guest agent | Go, `CGO_ENABLED=0`, static | Talks AF_VSOCK to host; drives Chromium via chromedp |
| Fonts | A realistic desktop font set | Missing fonts are a fingerprint signal (see [anti-cloaking](./research/anti-cloaking.md)) |

## Chromium configuration

Enterprise policy (`/etc/chromium/policies/managed/urljail.json`) + flags.

| Setting | Value | Why |
| ------- | ----- | --- |
| `--remote-debugging-pipe` | on | CDP over a pipe, **no TCP debug port**, so nothing for a page to reach via DNS rebinding to localhost |
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

```
1. Cold-boot VM (kernel + rootfs) with the fixed per-clone network config (172.16.0.2/30, fixed MAC)
2. Guest agent starts, launches Chromium, opens about:blank, waits until idle
3. NO network activity yet (no DNS cache, no TLS sessions, no cookies in the snapshot)
4. Host: pause VM → create snapshot (vmstate + memory file) → record snapshot id + versions
5. Clones: restore from (vmstate, memory) in their own netns; host sends SyncClock + Reseed
```

Snapshot "profiles" = different browser configurations (baseline, stealth variants) for the anti-cloaking experiments. Each profile is a separate snapshot.

## Clone-safety checklist (each restore)

- [ ] Wall clock synced from host (`SyncClock`) before navigation
- [ ] Kernel RNG reseeded (VMGenID if available + `Reseed` over vsock)
- [ ] Userspace RNG state: open research question (Chromium/BoringSSL state is cloned): [research/snapshot-entropy.md](./research/snapshot-entropy.md)
- [ ] Writable overlay is fresh (per-run)
- [ ] Network identity unique outside (SNAT in VM netns)

## Image build

Reproducible script in `images/` (later): build kernel → debootstrap rootfs → install Chromium + fonts + policy → copy guest agent → produce `rootfs.ext4` + `vmlinux` + a manifest with hashes and versions. Built rootless where possible (e.g. inside podman), output artifacts only.
