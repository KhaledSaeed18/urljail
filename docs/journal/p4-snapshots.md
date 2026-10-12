# P4: Snapshot pool

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P4](../roadmap.md#p4-snapshot-pool-next)
- Exit: p50 restore-to-navigation < 1 s; 2–3 concurrent clones within RAM budget.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Snapshot built at daemon start (Chrome prepared, no network), every run restored from it | done |
| M2 | Clone safety: clock, VMGenID reseed, distinct kernel randomness across clones | |
| M3 | Pool of pre-restored clones, benchmarks (p50/p95, memory per clone, page-cache sharing), concurrency; exit criterion | |

## M1 notes

- **Agent `Prepare`:** launches Chrome and does all CDP setup (startup tab, domains, download behavior); the next `Detonate` uses that browser and drops the events queued before it (about:blank). `Hello` now returns the guest's wall clock, 16 bytes from `getrandom`, and whether a browser is prepared.
- **Build** (10–11 s): see [guest-image.md](../guest-image.md#snapshot-procedure-phase-4). Chrome's prepare takes 4.2 s; the guest tried to send 34 packets during the build, into a namespace with no route out.
- **Restore per run:** reflinked disk in the run's work directory + Firecracker started there (the snapshot's relative paths resolve per clone), `vsock_override`, `clock_realtime`, resume. `PUT /snapshot/load` takes **~20 ms**.
- **First result:** REQUESTED → NAVIGATING in **0.72–1.04 s** (cold boot: ~4.9 s); agent answering 167–471 ms after Firecracker starts; whole example.com run 5.5–6.1 s (cold: ~9.4 s). Reports stay consistent.
- **VMGenID reseeds on every restore:** the guest kernel logs `random: crng reseeded due to virtual machine fork` (answers Q7's open half: the device is there *and* the reseed happens).

### Bugs and findings

- **Guest clock resumed from snapshot time (11.7 s behind):** `clock_realtime` advances kvmclock, but Linux had switched the guest from `kvm-clock` to `tsc` 0.4 s into boot. Fixed with `clocksource=kvm-clock` on the kernel command line; restoring a snapshot >20 s old, the guest clock was within 0.25 s (including the RPC round trip). TLS survived 12 s of skew, but an hours-old snapshot wouldn't.
- **ARP after restore:** each VM namespace's `tap0` now has a fixed MAC, the same everywhere like the rest of the inside of a namespace, so the guest's ARP entry for its gateway, captured in the snapshot, stays right.
- **Stale-snapshot detection must cover boot args:** the clocksource fix didn't invalidate the first snapshot until boot args joined the manifest's freshness check.
- Firecracker writes snapshot files `0644`; they're now `0600`.
