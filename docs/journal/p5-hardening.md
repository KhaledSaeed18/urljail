# P5: Jailer and hardening

- Status: **closed**
- Started: 2026-10-12
- Closed: 2026-10-12
- Roadmap: [P5](../roadmap.md#p5-jailer--hardening-next)
- Exit: no VMM runs outside the jailer; SELinux enforcing with no unexplained denials.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Every VMM (runs and snapshot builder) under the jailer: chroot, per-slot uid, own PID namespace, cgroup v2 limits, seccomp | done |
| M2 | Firecracker rate limiters (net, block), verified on every run; pcap byte cap; resource caps review | done |
| M3 | SELinux: custom policy module confines every VMM in `urljail_vmm_t` (enforcing), installed by the daemon; denials reported by `doctor` | done |
| M4 | Every run verifies its VMM's confinement (fail closed); `doctor` checks every Firecracker on the host; exit criterion | done |

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

## M3 notes

Before: the daemon, every VMM and unbound ran as `unconfined_t`, and jail files were `data_home_t`; "SELinux enforcing" protected nothing around the VMMs. Decision (asked): a custom domain, installed by the daemon.

- **Policy module** `selinux/urljail.{te,fc,if}` (built with `make selinux`, needs `selinux-policy-devel`; the `.pp` is committed like the eBPF object). The jailer (unconfined, started by the daemon) execs the Firecracker copy in the jail (`urljail_jail_t`), which transitions to **`urljail_vmm_t`**. The jailer sets no_new_privs, so the transition needs `nnp_transition` (policy capability `nnp_nosuid_transition` is on).
- **Types:** `urljail_jail_t` (jail trees: the VMM's disk, sockets, log, and the `/dev/kvm` and `/dev/net/tun` nodes the jailer mknods there), `urljail_image_t` (`ci/`, `images/`, `snapshots/`: read-only to VMMs; hard links into jails keep it), `urljail_run_t` (`runs/`, `logs/`: the VMM may only write/append to the serial console fd it inherits), `urljail_vmm_tmpfs_t` (the VMM's own memfds, via a tmpfs type transition instead of access to generic `tmpfs_t`).
- **The VMM may:** manage its jail's files and sockets, use its jail's device nodes, read and map images and snapshots, create unix sockets, create/attach its tun socket (relabelling it from the daemon-created TAP's context), use its memfds, use fds and send SIGCHLD to its unconfined parent. Nothing else: no home files, no network sockets of its own, no other domains.
- **The daemon installs it** at start when its SHA-256 changes (`semodule -i`, ~8 s), then `restorecon -R -F` on the data directories, and relabels each new snapshot. If SELinux is on and the module can't be loaded, the daemon refuses to start. `doctor` reports whether the domain is enforcing and every AVC involving urljail types since the daemon started, with the path.
- **Result: enforcing, zero denials** across a snapshot build (cold boot), restored detonations and the self-test.

### How it was developed, and what that taught

1. Permissive first: the first runs logged `tmpfs_t` read/write/map (memfds), `data_home_t` write (the inherited serial log), and tun-socket relabels. Each became a narrow rule or its own type, not a broad allow.
2. **Permissive mode logs each distinct denial once**, then caches it as allowed until the policy reloads. Runs without a module reinstall showed "no denials" that proved nothing. Enforcing logs every denial and makes missing permissions fail visibly; that's where the last one surfaced.
3. **The last denial was a layout bug, not a missing rule:** the snapshot builder's serial console lived inside `snapshots/` (read-only to VMMs), so enforcing mode blocked it. Build logs moved to `logs/snapshot-build/` (`urljail_run_t`).
4. The AVC summary needed the file path (`name=` or `path=`) to tell which file a denial was about.

## M4 notes

- **Per run, fail closed:** right after the VMM starts, the daemon reads `/proc/<pid>` and refuses the run unless the process has the jail's uid, `NoNewPrivs`, seccomp filter mode, its own `/urljail/<jail id>` cgroup, a root that isn't the host's (`stat` of `/proc/<pid>/root` against `/`), and the `urljail_vmm_t` context. The self-test reports what it verified, e.g. `pid 108406: uid 64000, no_new_privs, seccomp filter, cgroup /urljail/s0-fdaceed3d6a9, chrooted, urljail_vmm_t`.
- **`doctor` checks every Firecracker process on the host**, found by executable name, not only urljail's. Negative test: an unjailed Firecracker started by the operator during a jailed run was flagged on every property (`uid 1000 is not a jail uid, no_new_privs off, seccomp mode 0, cgroup /user.slice/…, not chrooted, SELinux domain unconfined_t`) while the jailed one passed; `doctor` exited 1, then healthy again once it was gone.
- Test slip: the first rogue VMM exited at once because its socket path (in the scratchpad) was over the 108-byte limit, which would have made the negative test pass vacuously. Check the negative case is really running before trusting it.

## Exit criterion

*No VMM runs outside the jailer; SELinux enforcing with no unexplained denials.* **Met.**

- Every VMM (detonations, self-test, snapshot builder) is jailed; each run verifies it and refuses otherwise; `doctor` checks the whole host.
- SELinux enforcing, the VMM domain `urljail_vmm_t` enforcing, zero AVCs for urljail types across builds, restores and the self-test.
- Isolation self-test passes under the jailer.

## Follow-ups (not P5)

- Inside the guest, the agent and Chrome still share uid 1000 (P2 note): a separate uid for Chrome.
- The daemon runs as full root ([ADR 0014](../decisions/0014-root-daemon-unprivileged-vmm.md)); a capability-bounded daemon is possible but `CAP_SYS_ADMIN` (namespaces, mounts for the jailer) keeps it close to root.
- Per-VM SELinux MCS categories (as libvirt does) would add a second separation between VMs on top of the per-slot uids.
- The dev sudoers rule must go before the live gate.

## Follow-ups from the threat model (2026-10-13)

The three "should/later" items from the live-gate review:

- **VMs die with the daemon.** `Delegate=cpu memory pids` in the unit; at start the daemon moves itself into `<service>/daemon` (cgroup v2 allows no processes in a node with controllers enabled), enables the controllers and gives the jailer `<service>/vms` as the parent. A stop or a crash of the main process now takes every VMM with it, instead of leaving them browsing until a restart. Leftovers in the old `/sys/fs/cgroup/urljail` are reaped and the directory removed. Dev runs (no delegated cgroup) keep the old location. The per-run and `doctor` confinement checks take the parent from the config.
- **unbound in `named_t`.** The daemon starts it as `nsenter --net=/run/netns/<ns> -- runcon -t named_t unbound …` (both exec in place, so the pid is unbound's) when it runs as `unconfined_service_t`; policy 1.3.0 allows exactly that transition plus the pipe and signal unbound needs back to the daemon, and labels `/run/urljail/unbound` as `urljail_dns_conf_t`, readable by `named_t`. After start the daemon reads unbound's context and refuses to serve if it isn't `named_t`; `doctor` shows it, and AVC reporting includes `named_t`. `-confine-resolver=false` turns it off. The module is now installed before the egress namespace comes up, since it carries the transition.
- **Reports built unprivileged.** After the run directory is handed to the operator, the daemon runs itself as `__build-report <dir>` with the operator's uid and gid, no supplementary groups, no_new_privs, a Go memory limit plus `RLIMIT_AS` 4 GiB, 64 open files, 256 MiB output, no core files, 60 s. Checked on a real run: the helper's report is identical to the daemon's. First version also set `RLIMIT_NPROC` 0, which kills the Go runtime (`pthread_create failed`) and would count the operator's whole session: removed.
- **First confined start failed closed:** `runcon: runcon may be used only on a SELinux kernel`. `ip netns exec` remounts `/sys` for the namespace, which hides selinuxfs, so runcon concluded SELinux was off; unbound didn't start and the daemon refused to serve (restarting every 5 s, 23 times, until fixed). Fixed by entering only the network namespace with `nsenter --net=/run/netns/<ns>`, which leaves the mounts alone.

