# Roadmap

Status: **P0–P5 done; live gate passed; P6 next**. Each phase ends with a written note in [`docs/journal/`](./journal/): what worked, what broke, what changed in the design.

The order is deliberate: **safety before live URLs, a working end-to-end slice before optimization, the familiar web stack last.**

```
 P0 ──► P1 ──► P2 ──► P3 ──► P4 ──► P5 ──► [LIVE GATE] ──► P6 ──► P7
 docs   boot   slice  net    pool   jail                   evasion  control plane
```

---

## P0: Planning (done 2026-10-12)
- [x] Idea, feedback, constraints
- [x] Name chosen ([naming/](./naming/))
- [x] Vision, architecture, network, threat model, guest image, report schema drafts
- [x] Resolve or park every item in [open-questions.md](./open-questions.md) (2026-10-12; Q17 and three verification tasks remain, each with a phase)
- [x] Review all docs: carried into P1, where it's checked against what was learned ([journal](./journal/p1-boot.md))
- [x] Tooling installed and versions pinned: Go 1.27.2, Firecracker v1.17.0, CI kernel 6.18.51 + Ubuntu 24.04 rootfs

**Exit:** docs reviewed; Phase 1 checklist agreed ([journal/p1-boot.md](./journal/p1-boot.md)).

## P1: Boot a microVM by hand (done 2026-10-12)
Learn the raw primitives before writing any Go. **No isolation exists yet**: the guest can reach the LAN through host NAT, so CI rootfs and benign URLs only.
- [done in P0] Install Go; download Firecracker + jailer release binaries; fetch a guest kernel + rootfs from Firecracker's CI artifacts
- ~~Stop Docker for the phase~~: not needed; `DOCKER-USER` accept rules handle its FORWARD drop whether Docker runs or not
- Create a TAP device by hand, boot a VM through the API socket with `curl --unix-socket`
- SSH/serial into the guest; give it internet via host NAT (dev only, benign URLs)
- Check VMGenID: Firecracker CHANGELOG for the chosen release + `dmesg | grep -i vmgenid` in the guest (Q7)
- Measure cold boot time; note SELinux denials (`ausearch -m avc`) and Docker firewall interactions

**Exit:** reproducible shell script that boots a VM with networking; journal entry with timings and every gotcha. **Met:** [scripts/p1/](../scripts/p1/), [journal](./journal/p1-boot.md).

## P2: Vertical slice: `urljail detonate` (done 2026-10-12)
The whole pipeline, as simple as possible, **cold boot** (no snapshots yet).
- Go module, `urljaild` + `urljail` skeletons, gRPC over a Unix socket
- Hand-written Firecracker API client over the Unix socket ([ADR 0011](./decisions/0011-hand-written-firecracker-client.md)); per-run TAP + simple NAT (dev egress), reusing P1's Docker/firewalld handling
- Custom Debian 13 slim rootfs with Google Chrome stable ([ADR 0012](./decisions/0012-google-chrome-stable-in-guest.md)) + guest agent, built rootless from a podman `debian:trixie-slim` container
- vsock channel: gRPC over host UDS `CONNECT` ([ADR 0007](./decisions/0007-grpc-over-vsock.md)), with an integration test for the handshake (Q8)
- Guest agent: navigate, collect CDP events, screenshot, DOM → stream back
- First `report.json` (navigation + requests + screenshot only)

**Exit:** `urljail detonate https://example.com` → report + screenshot; VM always torn down (including on Ctrl-C and timeout). **Met:** [P2 journal](./journal/p2-slice.md).

## P3: Network layer (done 2026-10-12)
- Per-VM netns + egress netns topology from [network.md](./network.md)
- nftables ruleset (load + verify hash at preflight)
- unbound in egress netns with logging + rebind protection; DNAT 53
- eBPF (C + bpf2go, TCX attach): flow records + ClientHello SNI/ALPN parser
- pcap writer; Chromium key log shipped back; reconciliation section in report
- `urljail doctor`

**Exit:** isolation test plan passes in `dev` mode; reports contain DNS, flows, SNI, blocked attempts, reconciliation. **Met:** [P3 journal](./journal/p3-network.md).

## P4: Snapshot pool (done 2026-10-12)
- Snapshot procedure from [guest-image.md](./guest-image.md) (warm Chromium, no network before snapshot)
- Restore into pre-created netns (identical inner config, unique SNAT)
- `SyncClock` (or `LoadSnapshot` `clock_realtime`) + `Reseed` on restore; check VMGenID actually reseeds (device + driver confirmed in P1)
- Own guest kernel on Linux ≥ 7.0 for VMClock restore notifications (see [guest-image.md](./guest-image.md))
- Pool manager: pre-warm N, replenish, reap orphans at startup
- Benchmarks: restore latency p50/p95, memory per clone, page-cache sharing

**Exit:** p50 restore-to-navigation < 1 s; 2–3 concurrent clones within RAM budget. **Met:** p50 202 ms, 3 clones in +370 MiB ([journal](./journal/p4-snapshots.md)). Pool, SyncClock, Reseed and the ≥ 7.0 kernel were resolved differently: [ADR 0015](./decisions/0015-restore-on-demand.md).

## P5: Jailer & hardening (done 2026-10-12)
- Run every VMM under the jailer: chroot, unprivileged uid/gid, cgroup v2 limits, own netns, seccomp
- SELinux: custom policy module / contexts for jailer paths (Fedora, enforcing; never `setenforce 0` as the fix)
- Firecracker rate limiters on net/block; artifact size caps; wall-clock kill
- Re-run isolation tests under the jailer

**Exit:** no VMM runs outside the jailer; SELinux enforcing with no unexplained denials. **Met:** [P5 journal](./journal/p5-hardening.md); jail design [ADR 0016](./decisions/0016-every-vmm-jailed.md).

## LIVE GATE (before P6) (passed 2026-10-12)
- [x] WireGuard-in-netns egress working; `live` mode interlock in the daemon ([journal](./journal/live-gate.md))
- [x] Full isolation test plan passes in `live` mode, including "VPN down ⇒ no egress" and the exit IP (Proton `149.88.25.131` ≠ home)
- [x] Threat model reviewed against what was actually built ([review](./threat-model.md#review-against-the-built-system-2026-10-12))
- [x] Dev sudo rule removed (`/etc/sudoers.d/urljail-dev`); urljaild runs as a systemd service from root-owned binaries
- [x] Feed terms of use checked for each source (Q13): free feeds first ([research/feeds.md](./research/feeds.md))
- [x] Proton VPN Free WireGuard config installed ([ADR 0017](./decisions/0017-proton-vpn-free.md)); live self-test passes with it
- [x] Feed ingestion design treating URLs strictly as data ([feed-ingestion.md](./feed-ingestion.md))

## P6: Anti-cloaking research (in progress)
See [research/anti-cloaking.md](./research/anti-cloaking.md).
- [x] Snapshot profiles as experimental conditions: six profiles, one snapshot each ([ADR 0018](./decisions/0018-profiles-as-snapshots.md)), verified live
- [x] Fresh-feed ingestion; detonate within minutes of publication (phishing URLs die in hours): `urljail feeds` with OpenPhish Community, plus own discovery from CT logs (`urljail feeds watch`) ([feed-ingestion.md](./feed-ingestion.md))
- [x] Cloaking measurement: same URL, multiple profiles at once, outcome labels, control runs, single-factor attribution (`urljail feeds compare`); one exit only
- [x] Write-up with results: [research/r1-results.md](./research/r1-results.md) (2026-10-13)

**Exit:** cloaking rate per countermeasure on a real feed, with methodology documented.

## P7: Control plane
- NestJS orchestrator + Postgres + BullMQ queue; gRPC client to `urljaild`
- Next.js dashboard: submit URL, run list, report view (redirect chain, network graph, screenshot)
- Artifact storage, retention policy (pcaps rotated after N days + disk cap; reports kept)

**Exit:** submit from the dashboard → report rendered; daemon remains the only privileged component.

---

## Side quests (can slot in anywhere after P4)
- **Snapshot entropy study**: [research/snapshot-entropy.md](./research/snapshot-entropy.md); a good standalone write-up.
- **HAR export**, pHash of screenshots, brand-impersonation heuristics.
- **Rust rewrite of one component** (e.g. the eBPF loader with aya) as a comparison exercise.
