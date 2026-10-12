# 0015: Restore on demand; kvmclock and VMGenID for clone safety

- Status: Accepted
- Date: 2026-10-12

## Context
The P4 plan had a pool manager keeping N clones pre-restored, a `SyncClock` and a `Reseed` message to each clone after restore, and a custom Linux ≥ 7.0 guest kernel for VMClock. Measured in P4 (20 sequential runs, then 3 concurrent):

| | p50 | p95 |
| - | --- | --- |
| Request → navigate (restore on demand) | 202 ms | 250 ms |
| of which: namespace setup | 63 ms | 88 ms |
| eBPF attach + tcpdump start | 44 ms | 70 ms |
| `PUT /snapshot/load` + agent answering | 65 ms | 82 ms |
| 3 concurrent: request → navigate | 216 ms | 234 ms |

Three clones running at once took 370 MiB of host memory in total (per clone: RSS ~395 MiB, PSS ~205 MiB, ~288 MiB shared clean from the snapshot through the page cache).

## Decision
- **Restore on demand, no pre-restored pool.** The exit target (p50 < 1 s) is met five times over; a pool could save at most ~110 ms (namespace, eBPF, capture) and would hold memory and processes idle. It would also break the clock: Firecracker advances the guest clock only at `LoadSnapshot` (`clock_realtime`), so a clone that waits paused in a pool resumes with its clock behind by the time it waited. Orphan reaping at daemon start (the pool's other job) already exists.
- **Clock: `clock_realtime` plus `clocksource=kvm-clock`**, no `SyncClock` message. The unprivileged agent couldn't set the clock anyway; skew after restore is a constant ~214 ms (the time to write the snapshot), checked per run and by the self-test.
- **Kernel RNG: VMGenID**, no `Reseed` message. The guest kernel logs the reseed on every restore; the run records it, the report flags a clone without it, and the self-test fails without it.
- **The custom ≥ 7.0 guest kernel for VMClock moves to research R2** (userspace RNG state), where it's needed; it isn't needed for any P4 goal.

## Consequences
- One snapshot per image (rebuilt at daemon start when the image, Firecracker, VM size or boot args change), ~10 s to build.
- If request latency ever matters below ~200 ms, pre-creating per-slot namespaces is the next step, not pre-restored VMs.
- Userspace RNG state in Chrome remains cloned; first data (25/25 distinct ClientHello randoms across 3 clones) is in [research/snapshot-entropy.md](../research/snapshot-entropy.md).
