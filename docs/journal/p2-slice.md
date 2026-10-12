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
| M3 | Debian 13 rootfs with Chrome stable + guest agent, built rootless | |
| M4 | gRPC over vsock; guest agent drives Chrome, streams events, screenshot | |
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

**Not recorded yet:** runs refused before a slot is taken (busy, policy) leave no run directory. The report schema has a `refused` status; decide in M5 whether refusals get a record.
