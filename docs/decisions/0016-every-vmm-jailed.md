# 0016: Every VMM runs under the jailer, as a per-slot uid

- Status: Accepted
- Date: 2026-10-12

## Context
Until P5 each Firecracker ran as the operator inside its VM's network namespace, with no chroot, no PID or mount namespace and no resource limits ([ADR 0014](./0014-root-daemon-unprivileged-vmm.md)). A VMM escape (adversary A4) would have landed in the operator's account, with access to the operator's files and processes.

## Decision
Every VMM, including the snapshot builder, runs under Firecracker's jailer (`internal/vm/jail.go`):

- **Identity:** uid `64000 + slot` (builder `64099`), gid `64000`, no supplementary groups; not the operator. Snapshot files are `operator:64000 0640`, so jails can read but not change them.
- **Filesystem:** chroot `<data>/jail/<firecracker exec name>/<id>/root` (base root-owned `0700`, on the same btrfs as images and snapshots). The kernel and snapshot are **hard-linked** in (so clones still share the snapshot's page cache); the run's disk is reflinked in. The jailer creates `/dev/kvm` and `/dev/net/tun` there. The snapshot's relative paths (`rootfs.ext4`, `v.sock`) resolve at each jail's root, so restores need no overrides.
- **PID namespace:** the daemon starts the jailer with `CLONE_NEWPID`; the jailer execs Firecracker in place, which becomes PID 1 of its namespace while the daemon's pidfd still tracks it. (The jailer's own `--new-pid-ns` forks, which would lose the pidfd.)
- **Network:** `--netns /run/netns/uj-vm-<n>` (the TAP is owned by the jail uid).
- **Limits:** cgroup v2 child of `/sys/fs/cgroup/urljail`: `memory.max` = guest + 256 MiB, `pids.max` 64, `cpu.max` = its vCPUs; `RLIMIT_NOFILE` 1024. Firecracker's built-in seccomp filters stay on.
- **Cleanup:** the jail and cgroup are removed after the VMM exits; at start the daemon kills anything left in `urljail/*` cgroups and removes leftover jails.

## Alternatives considered
- **Operator uid inside the jail:** simpler file permissions, but an escape would reach the operator's account again.
- **One shared jail uid:** the PID namespace and chroot already separate VMs, but distinct uids make cross-VM signalling and file access impossible even if those layers fail.
- **The jailer's `--new-pid-ns`:** loses the daemon's direct handle on the VMM process.

## Consequences
- Measured: restore-to-navigation p50 242 ms (was 202 ms without the jailer), 3 concurrent jailed clones as uids 64000–64002, self-test passing.
- The operator can no longer read jail directories; artifacts are copied out to the run directory.
- uids/gids 64000–64099 must stay unused on the host.
