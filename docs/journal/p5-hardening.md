# P5: Jailer and hardening

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P5](../roadmap.md#p5-jailer--hardening-next)
- Exit: no VMM runs outside the jailer; SELinux enforcing with no unexplained denials.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Every VMM (runs and snapshot builder) under the jailer: chroot, per-slot uid, own PID namespace, cgroup v2 limits, seccomp | done |
| M2 | Firecracker rate limiters (net, block), verified on every run; pcap byte cap; resource caps review | done |
| M3 | SELinux: denials checked by the daemon; confinement decision | |
| M4 | `doctor` proves no VMM outside a jail; isolation re-run; exit criterion | |

## M1 notes

- Design: [ADR 0016](../decisions/0016-every-vmm-jailed.md).
- **Verified on a running VMM** (found through its `urljail/*` cgroup): uid/gid 64000, no groups, `CapEff 0`, `NoNewPrivs 1`, `Seccomp: 2` (1 filter), `NSpid: … 1` (PID 1 of its own namespace), cgroup `urljail/s0-…` with `memory.max` 1280 MiB, `pids.max` 64, `cpu.max` `200000 100000` (161 MiB and 5 tasks in use), open files 1024. Its root holds only `dev/`, its own binary, `fc.sock`, `v.sock`, `firecracker.log`, `vmstate`, `mem`, `rootfs.ext4`.
- **Timing:** restore-to-navigation p50 242 ms, p95 306 ms (8 runs; 202/250 ms before). The jailer adds ~20 ms to the VMM step and ~20 ms before the agent answers.
- **Concurrency:** three clones at once ran as uids 64000, 64001, 64002. Self-test passes under the jailer.
- **Cleanup:** jails and cgroups gone after every run; at start the daemon kills anything in leftover `urljail/*` cgroups (every jailed VMM is in one) before removing them, after the namespace cleanup.

### Findings

- **The jailer's `--new-pid-ns` forks**, so the daemon would hold the jailer, not Firecracker. Starting the jailer with `CLONE_NEWPID` instead keeps the pidfd on Firecracker (the jailer execs in place).
- **Snapshots need a layout version:** the pre-jail snapshot passed the freshness check but its files (`0600`, operator-owned) were unreadable to jail uids. The manifest now has `layout: jail-v1`.
- **Socket paths:** jail ids are short (`s<slot>-<12 hex>`) because the API socket lives at `<data>/jail/<exec>/<id>/root/fc.sock`, and Unix socket paths stop at 108 bytes.
- **`pgrep -f` matched my own shell, a third time** (P1, P2 M4, here): an inspection reported uid 1000 and no seccomp because it was looking at the inspecting shell. Find VMMs through their cgroup (`/sys/fs/cgroup/urljail/*/cgroup.procs`), never by command-line pattern.

## M2 notes

- **Rate limiters** (token buckets refilled every 100 ms), set when the snapshot is built and inherited by every clone: network guest → out 20 MiB/s and 20k packets/s, → guest 40 MiB/s and 40k packets/s; disk 100 MiB/s and 10k IOPS. Snapshot layout `jail-v2`, so older snapshots rebuild.
- **Fail closed:** after every restore the daemon reads `GET /vm/config` back and refuses the run if any device lacks its limits (unit-tested against a fake VMM: missing tx limit, different disk limit, no devices). Restore-to-navigation stays ~200–410 ms.
- **pcap byte cap:** 500 000 packets didn't bound the size (with GSO one packet can be 64 KiB). The daemon now stops tcpdump at 256 MiB and records a host gap that reaches the report (`meta.json` → `host_gaps`).

### Every cap per run, as of P5

| What | Cap | Where |
| ---- | --- | ----- |
| Wall clock | default 30 s, client may ask up to 5 min; teardown always runs | daemon |
| Observation | min 3 s + ≤1 s jitter, max 15 s | daemon → agent |
| VMM memory / tasks / CPU | guest + 256 MiB / 64 / its vCPUs | cgroup v2 |
| VMM open files | 1024 | jailer rlimit |
| Network, disk | 20/40 MiB/s, 100 MiB/s (+ ops) | Firecracker rate limiters |
| Guest artifacts | 4 names only; 32/32/4/4 MiB each, 96 MiB total | daemon |
| CDP events | 200 000 (overflow counted) | daemon; agent queue 16 384 |
| DNS replies, blocked packets | 20 000 records each (overflow counted) | daemon |
| Packet capture | 500 000 packets or 256 MiB | tcpdump + daemon |
| eBPF flows / ClientHello data | 16 384 flows (LRU), 4 segments × 4 KiB per flow, 4 MiB ring | BPF maps |
| Concurrency | 3 VMs | daemon slots |

Not capped yet: the number and total size of run directories (retention is P7), and snapshots (one per image).
