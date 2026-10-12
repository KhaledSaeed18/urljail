# Architecture

Status: **design draft**. Only the P1 boot scripts exist so far ([journal](./journal/p1-boot.md)). Details marked _(verify)_ must be confirmed against Firecracker v1.17.0 and the guest kernel in use.

## System overview

```
                         ┌──────────────────────────── host (Fedora, KVM) ───────────────────────────┐
                         │                                                                           │
  urljail CLI ──gRPC──►  │  urljaild (host agent, Go)                                                │
  (later: NestJS)        │   ├─ pool manager ───── restores VMs from snapshot                        │
                         │   ├─ run orchestrator ─ one run = one VM = one URL                        │
                         │   ├─ netns manager ──── per-VM namespace, TAP, veth, nftables             │
                         │   ├─ capture ───────── eBPF (TCX) flow + SNI logger, pcap writer          │
                         │   ├─ resolver log ──── unbound in egress netns                            │
                         │   └─ report builder ── merges guest + host evidence → report.json         │
                         │            │                                                              │
                         │            │ vsock (via Firecracker UDS)                                  │
                         │   ┌────────▼──────────── jailer: chroot + cgroup v2 + netns + seccomp ──┐  │
                         │   │  firecracker VMM ──── KVM ──── guest (microVM)                      │  │
                         │   │                                 ├─ guest agent (Go, static)         │  │
                         │   │                                 └─ Chromium (CDP on localhost)      │  │
                         │   └──────────────────────────────────────────────────────────────────────┘  │
                         │            │ tap0                                                         │
                         │      [vm netns] ──veth──► [egress netns: nftables, unbound, wg0] ──► VPN    │
                         └───────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. `urljail` CLI
The operator's entry point until the control plane exists. Talks to `urljaild` over gRPC on a Unix socket.

```
urljail detonate <url> [--profile stealth|baseline] [--timeout 30s] [--out ./runs]
urljail runs list | urljail runs show <id>
urljail pool status
urljail doctor        # checks KVM, nftables loaded, egress mode, VPN up, SELinux contexts
```

### 2. `urljaild`: host agent (Go, runs as root or with the needed caps)
Owns every privileged operation. Long-running daemon.

| Module | Responsibility |
| ------ | -------------- |
| **pool** | Keeps N pre-restored or ready-to-restore clones per snapshot; replenishes after each run |
| **run** | State machine per detonation (below); enforces wall-clock timeout; always tears down |
| **netns** | Creates/destroys per-VM network namespaces, TAP, veth, NAT, attaches eBPF |
| **firewall** | Loads and verifies the nftables ruleset; refuses runs if it isn't loaded |
| **capture** | Loads eBPF programs (cilium/ebpf + bpf2go), reads ring buffer, writes pcap |
| **vsock** | Host side of the guest control channel |
| **report** | Merges evidence, writes `report.json`, stores artifacts |
| **api** | gRPC server (CLI now, NestJS later) |

### 3. Guest agent (Go, statically linked, PID 2-ish under a minimal init)
- Listens on AF_VSOCK.
- On `Detonate{url, profile, deadline}`: drives Chromium over CDP (chromedp), collects events, takes screenshot + DOM snapshot, streams results back.
- On restore: receives `SyncClock{now}` and sets the guest wall clock before anything else (a restored VM wakes up with its snapshot-time clock, which breaks TLS validation).
- Never decides anything security-relevant; the host treats everything it sends as untrusted evidence.

### 4. Chromium (in guest)
Pre-launched and warmed *before* the snapshot is taken, so a restore lands on a ready browser. Configured via enterprise policy + flags (see [guest-image.md](./guest-image.md)): QUIC off, ECH off, DoH off, `SSLKEYLOGFILE` set.

### 5. Control plane (Phase 7, later)
NestJS + Postgres + BullMQ + Next.js dashboard. NestJS is the orchestrator: it enqueues jobs, calls `urljaild` over gRPC, stores reports. `urljaild` stays the only privileged component.

## Detonation lifecycle

```
 REQUESTED → PREFLIGHT → RESTORING → NET_READY → CLOCK_SYNCED → NAVIGATING → OBSERVING → COLLECTING → TEARDOWN → DONE
                │                                                                                       ▲
                └── fail (egress unsafe, pool empty, firewall missing) ────────────── any error/timeout ─┘
```

1. **PREFLIGHT**: egress mode allows this URL source? nftables ruleset hash matches? VPN up (in live mode)? Disk space for artifacts?
2. **RESTORING**: take a clone from the pool; Firecracker loads snapshot (memory file mapped `MAP_PRIVATE` with copy-on-write, so clones share unchanged pages through the host page cache; confirmed in Firecracker's `snapshotting/snapshot-support.md`).
3. **NET_READY**: the clone's netns already exists (clones need identical TAP name/IP/MAC; per-VM netns + NAT gives each a unique outside identity); start eBPF capture + pcap.
4. **CLOCK_SYNCED**: host → guest `SyncClock` (alternative to evaluate in P4: `clock_realtime: true` in Firecracker's `LoadSnapshot`, which advances the guest clock at restore with kvm-clock). VMGenID reseeds the guest kernel's RNG on restore; `Reseed` over vsock stays as belt and braces. Userspace RNG state is still cloned (see [research/snapshot-entropy.md](./research/snapshot-entropy.md)).
5. **NAVIGATING / OBSERVING**: guest navigates, then observes until the network goes idle, bounded by a minimum dwell (catches delayed redirects) and a maximum (caps cost), with random jitter so a fixed dwell isn't a scanner fingerprint. No interaction simulation in v1; it becomes a research variable in P6.
6. **COLLECTING**: guest sends screenshot, DOM, CDP event log, key log; host stops capture, flushes pcap, collects resolver log slice.
7. **TEARDOWN**: kill VMM, delete netns, delete jail chroot, release cgroup. **Always runs**, including on error and timeout; a leaked VM is a bug.
8. **DONE**: report builder runs (can also be re-run later from stored artifacts).

## Host ↔ guest channel (vsock)

Firecracker implements virtio-vsock with a **host-side Unix domain socket**, not host AF_VSOCK: the host connects to the UDS and writes `CONNECT <port>\n`; Firecracker answers `OK <host_port>\n`; the guest side is a normal AF_VSOCK socket _(confirm with a test in P2)_. Once connected it's just a byte stream (`net.Conn`), so any framing works.

Decision: **gRPC over the vsock stream**, host-initiated, with artifacts sent in chunks ([ADR 0007](./decisions/0007-grpc-over-vsock.md)).

Messages (draft):

| Direction | Message | Purpose |
| --------- | ------- | ------- |
| host → guest | `SyncClock{unix_nanos}` | fix wall clock after restore |
| host → guest | `Reseed{entropy}` | inject fresh entropy (belt and braces with VMGenID) |
| host → guest | `Detonate{url, profile, deadline}` | start a run |
| guest → host | `Event{...}` (stream) | CDP-derived events: navigation, request, response, console, dialog, download |
| guest → host | `Artifact{kind, bytes}` | screenshot, DOM snapshot, key log |
| guest → host | `Done{status, error}` | run finished |

## Storage layout (per run)

```
runs/<run-id>/
  report.json          # derived; regenerable (urljail report <run-dir>)
  meta.json            # inputs and outcome: url, profile, egress mode, status, versions
  guest/events.jsonl   # raw CDP events, one JSON object per line
  guest/done.json      # the guest agent's result (final URL, title, dwell)
  guest/screenshot.png
  guest/dom.html
  guest/sslkeys.log    # TLS key log (decrypts host pcap offline)
  guest/chrome.log     # Chrome's stderr
  host/serial.log      # guest serial console
  host/firecracker.log
  host/capture.pcap    # full packet capture on the VM's TAP (tcpdump writes pcap, not pcapng)
  host/dns.jsonl       # resolver replies to this VM
  host/blocked.jsonl   # packets of this VM the egress ruleset dropped (NFLOG)
  host/flows.jsonl     # eBPF flow records with SNI/ALPN or HTTP Host
  downloads/<sha256>   # (later) never executed
```

`<run-id>` is a UUIDv7 ([ADR 0008](./decisions/0008-protobuf-report-schema.md)).

**Retention:** pcaps are deleted after N days (configurable) and under a total disk cap, oldest first. Reports, metadata and the other small artifacts are kept. The policy is implemented in P7.

## Repo layout

```
cmd/urljail/          # CLI: detonate, report, version
cmd/urljaild/         # host agent
cmd/urljail-agent/    # guest agent: vsock gRPC, drives Chrome (GOOS=linux, CGO_ENABLED=0)
cmd/urljail-init/     # guest PID 1
internal/daemon/      # gRPC service, run lifecycle, teardown, orphan reaping
internal/policy/      # egress-mode URL interlock
internal/vm/          # Firecracker API client (hand-written, ADR 0011), VMM process, vsock dialer
internal/hostnet/     # dev-mode host networking (P2 only; replaced by netns in P3)
internal/cdp/         # CDP client over --remote-debugging-pipe (ADR 0013)
internal/report/      # report.json builder
internal/image/       # guest image manifests
internal/guestinfo/   # guest-side facts for Hello
api/proto/            # gRPC: CLI↔daemon, host↔guest; report schema
api/schema/           # generated JSON Schema for report.json
gen/                  # generated Go code (committed)
images/debian-chrome/ # rootless guest image build (Containerfile, Chrome policy)
scripts/p1/           # P1 boot scripts
docs/
```

Planned: `internal/netns/` and `internal/firewall/` (P3, replacing `hostnet`), `internal/capture/` (P3, eBPF), `internal/pool/` (P4).

## Resource budget (this laptop)

7.1 GiB RAM, 4c/8t i7-8550U. See [environment.md](./environment.md).

| Item | Budget |
| ---- | ------ |
| Guest memory | 1 GiB per VM (Chromium is the cost) |
| Concurrent VMs | 2 in dev, 3 max |
| Snapshot memory file | ~1 GiB on disk per snapshot profile, shared via page cache across clones |
| Artifacts | ~5–20 MB per run (pcap dominates) |
