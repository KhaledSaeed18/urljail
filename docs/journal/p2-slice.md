# P2: Vertical slice: `urljail detonate`

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P2](../roadmap.md#p2-vertical-slice-urljail-detonate-next)
- Exit: `urljail detonate https://example.com` → report + screenshot; VM always torn down (including on Ctrl-C and timeout).

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Go module, protobuf API (buf), `urljaild` + `urljail` over gRPC on a Unix socket, URL policy | done |
| M2 | Hand-written Firecracker client ([ADR 0011](../decisions/0011-hand-written-firecracker-client.md)), dev host networking, cold boot + guaranteed teardown | done |
| M3 | Debian 13 rootfs with Chrome stable, tiny init + guest agent answering `Hello` over vsock, built rootless | done |
| M4 | Guest agent drives Chrome over CDP, streams events, screenshot | |
| M5 | `report.json`; exit criterion | |

## Toolchain

Go 1.27.2, buf 1.73.0, protoc-gen-go 1.36.12, protoc-gen-go-grpc 1.6.2 (all user-local via `go install`). Generated code is committed under `gen/`, so building doesn't need buf. `make all` = lint (buf lint STANDARD, go vet, gofmt) + tests + build.

## M1 notes

- The URL policy (`internal/policy`) is the egress-mode interlock from [network.md](../network.md#egress-modes), enforced at preflight before any VM exists. Dev mode allows only RFC 2606 domains by default; `live` is refused at daemon start until the live gate. Ports other than 80/443 are refused up front, since egress only allows those.
- Daemon socket: `$XDG_RUNTIME_DIR/urljail/urljaild.sock`, created `0600` (umask, not chmod afterwards) in a `0700` directory. A stale socket is removed; a live one stops a second daemon.

## M2 notes

- **Per-run disks are free on btrfs:** a reflink (`FICLONE`) copy of the 1 GiB rootfs takes ~4 ms, so every run gets a private writable disk, deleted at teardown.
- **Guest networking from the boot line:** the kernel has `CONFIG_IP_PNP`, so `ip=<guest>::<host>:255.255.255.252::eth0:off` sets address and default route. Slot *n* gets `uj<n>`, `172.16.n.0/30` and MAC `06:00:AC:10:<n>:02`, which matches how the CI rootfs derives its IP from the MAC.
- **Host-wide vs per-run:** masquerade and two `DOCKER-USER` rules matching `uj*` are added once at daemon start and removed at exit (tagged `urljaild`); each run only adds its TAP and its firewalld `trusted` binding.
- **Reaping at start:** orphaned Firecracker processes on our socket directory, `uj*` TAPs and per-run work directories are removed before serving.
- **Process tracking:** Go tracks children with a pidfd on Linux, so `Kill` can't hit a reused PID (the PID-file problem from P1). `Pdeathsig` is a first line only (Linux ties it to the forking thread); reaping is the backstop.
- Cold boot through the daemon: guest reachable **1.86–2.10 s** after VMM start; whole run ~3.3 s with teardown.

### Failure paths (tested)

| Case | Result |
| ---- | ------ |
| Stale `uj0` from a failed teardown | Replaced, run completes |
| Timeout 800 ms (guest still booting) | Torn down, `status: timeout`, nothing left |
| Client Ctrl-C during boot | Torn down, `status: cancelled` |
| Three runs, `-max-vms 2` | Two in parallel on `uj0`/`uj1`, third refused "all 2 VM slots are busy" |
| Daemon SIGTERM mid-run | Run torn down, then `DOCKER-USER` and masquerade restored |

**Bug found and fixed:** teardown first shared one 15 s deadline. A guest still booting ignores Ctrl-Alt-Del, so the graceful shutdown used up the whole budget and `RemoveTap` then ran on an expired context, leaving the TAP behind. Now the shutdown has a 3 s grace before SIGKILL, and each cleanup step gets its own fresh deadline. Lesson for P4/P5: never let cleanup steps share a deadline.

## M3 notes

Plan change: the Debian image has no SSH, so the "guest is up" check moved onto the agent in M3 (a `Hello` RPC over vsock) instead of waiting for M4.

- **Rootless image build** (`images/debian-chrome/build.sh`, ~4 min cold, ~17 s with podman's layer cache): `podman build` from `debian:trixie-slim` pinned by digest, then inside `podman unshare` the container is `podman mount`ed and `mkfs.ext4 -d` reads it directly, so files keep their in-image owners (root, `urljail` = 1000) with no tar step and no sudo. `/etc/resolv.conf`, `hostname` and `hosts` are set on the mount, because the container runtime manages them during `podman build`.
- **Pinned and verified:** Chrome `155.0.8059.39-1` `.deb` checked against the SHA-256 in Google's apt `Packages` index, then archived in `~/.local/share/urljail/cache/`. `manifest.json` records base digest, Chrome, kernel, both guest binaries and the rootfs hash. The image is 1.4 GiB (~960 MiB used). Chrome's apt source and cron job are removed.
- **Tiny init as PID 1** (`cmd/urljail-init`): mounts `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm` (Chrome needs it), `/run`, `/tmp`; loopback up via ioctl; `CAD_OFF` so Ctrl-Alt-Del arrives as SIGINT; starts the agent as uid 1000; reaps every child itself (no `os/exec` Wait, which would race with PID 1's reaper); shuts down if the agent dies. The agent is the only process that touches page content; init never does.
- **DNS from the boot line:** `ip=...:eth0:off:1.1.1.1` puts the server in `/proc/net/pnp`, and the image links `/etc/resolv.conf` there. Nothing in the guest configures networking.
- **Guest kernel supports Chrome's sandbox** (`CONFIG_USER_NS`, `PID_NS`, `NET_NS`, `SECCOMP_FILTER`), so Chrome can run sandboxed as an unprivileged user. Checked in M4.
- **vsock readiness:** gRPC over the `CONNECT 1024` handshake (unit-tested against a fake Firecracker, including that the handshake doesn't swallow stream bytes). gRPC's default reconnect backoff grows to tens of seconds, so the dialer uses a 50–250 ms backoff while the guest boots.
- **Timing:** agent `Hello` answered **1.38 s** after VMM start (3 runs, ±5 ms), versus 1.86 s for the CI image's systemd boot to sshd. Kernel reaches init at 0.97 s, so the kernel is now most of the cost.

**Bug found:** the agent exited with `open /dev/vsock: permission denied`. With no udev, devtmpfs device nodes stay root-only. Init now sets `/dev/vsock` to `root:urljail 0660`. The failure path behaved as designed: agent died → init shut down → daemon reported "VM exited before the guest agent answered".

**Follow-up (hardening, not P2):** the agent and Chrome run as the same uid, so a compromised browser process could use vsock as the agent can. The host already treats everything from the guest as guest-attested, so this doesn't change trust, but a separate uid for Chrome would make a browser exploit one step further from the host channel. Revisit with P5's hardening.

**Not recorded yet:** runs refused before a slot is taken (busy, policy) leave no run directory. The report schema has a `refused` status; decide in M5 whether refusals get a record.
