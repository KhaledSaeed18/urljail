# P4: Snapshot pool

- Status: **closed**
- Started: 2026-10-12
- Closed: 2026-10-12
- Roadmap: [P4](../roadmap.md#p4-snapshot-pool-next)
- Exit: p50 restore-to-navigation < 1 s; 2–3 concurrent clones within RAM budget.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Snapshot built at daemon start (Chrome prepared, no network), every run restored from it | done |
| M2 | Clone safety: clock, VMGenID reseed, distinct kernel randomness across clones | done |
| M3 | Benchmarks (p50/p95 per step, memory per clone, page-cache sharing), concurrency; pool decided against ([ADR 0015](../decisions/0015-restore-on-demand.md)); exit criterion | done |

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

## M2 notes

- **Per run, `meta.json` → `clone`:** snapshot name, guest clock skew right after restore, 16 bytes of guest `getrandom`, and whether the guest kernel logged `crng reseeded due to virtual machine fork` (read from the serial log after teardown). The report's `run.clone` carries the snapshot, skew and reseed, and every restored run states the remaining gap: Chrome's userspace RNG state is copied from the snapshot.
- **Self-test gains two clone checks:** guest clock within 2 s of the host after restore, and the VMGenID reseed in the guest log. Both pass.

### Measured: three clones of one snapshot (example.com)

| | Clone 1 | Clone 2 | Clone 3 |
| - | ------- | ------- | ------- |
| REQUESTED → NAVIGATING | 255 ms | 169 ms | 199 ms |
| Guest `getrandom` | `2fb62077…` | `0c95a78a…` | `50f39d23…` |
| VMGenID reseed | yes | yes | yes |
| Clock skew after restore | 214 ms | 214 ms | 214 ms |
| TLS ClientHellos (from the pcap) | 8 | 9 | 8 |

- **ClientHello randoms and session IDs: 25 of 25 distinct across the clones.** BoringSSL in the cloned Chrome isn't replaying the snapshot's state for the values servers see. That's three clones, not a proof of independence (key shares, V8's `Math.random`, other userspace generators weren't checked): it stays research R2's question.
- **The constant 214 ms skew** is the time between the clock being captured at pause and the snapshot being written (the 1 GiB memory file); every clone lags by it. Well inside the 2 s check, and irrelevant for TLS.
- With the snapshot's memory in the page cache, restore-to-navigation is **~170–260 ms**; right after a build (pages just written) it was 0.7–1.0 s.

## M3 notes

- **Per-step timings** are now in every run's `meta.json` (`timings_ms`, cumulative from the request: preflight, disk, netns, ebpf, capture, vmm, agent, navigate, done).
- **20 sequential example.com runs, restored on demand:**

| Step | p50 | p95 |
| ---- | --- | --- |
| preflight (hash checks) | 6 ms | 13 ms |
| disk (reflink) | 1 ms | 2 ms |
| netns (namespace, TAP, veth, rules) | 63 ms | 88 ms |
| eBPF attach | 22 ms | 26 ms |
| tcpdump listening | 22 ms | 44 ms |
| VMM (start + `PUT /snapshot/load`) | 20 ms | 23 ms |
| agent answering | 45 ms | 59 ms |
| first navigate | 14 ms | 22 ms |
| **request → navigate** | **202 ms** | **250 ms** |
| whole run (incl. ~3.5 s dwell, teardown) | 4.66 s | 5.18 s |

- **3 concurrent clones** (`-max-vms 3`): request → navigate p50 216 ms; runs 7.4–7.6 s each (CPU contention on 4 cores / 8 threads, not memory); all three reports consistent, all reseeded.
- **Memory:** host MemAvailable 3712 → 3342 MiB with 3 clones running Chrome on a page: **~123 MiB per clone**. Per Firecracker: RSS ~395 MiB, PSS ~205 MiB, shared clean ~288 MiB (the snapshot's memory file through the page cache), private dirty ~106 MiB. A cold-booted VM needed ~1 GiB; the default concurrency is now 3.
- **No pre-restored pool:** [ADR 0015](../decisions/0015-restore-on-demand.md) (the target is met 5×; a paused clone's clock would lag by its waiting time; SyncClock/Reseed replaced by kvmclock + VMGenID; the ≥ 7.0 kernel moves to research R2).
- Test-script slip, again: a bare `wait` also waited for the daemon started in the same shell (as in P2). Wait on PIDs.

## Exit criterion

*p50 restore-to-navigation < 1 s; 2–3 concurrent clones within RAM budget.* **Met:** p50 202 ms (p95 250 ms); 3 concurrent clones in +370 MiB.
