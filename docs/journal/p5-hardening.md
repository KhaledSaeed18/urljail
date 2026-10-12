# P5: Jailer and hardening

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P5](../roadmap.md#p5-jailer--hardening-next)
- Exit: no VMM runs outside the jailer; SELinux enforcing with no unexplained denials.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Every VMM (runs and snapshot builder) under the jailer: chroot, per-slot uid, own PID namespace, cgroup v2 limits, seccomp | done |
| M2 | Firecracker rate limiters (net, block); resource caps review | |
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
