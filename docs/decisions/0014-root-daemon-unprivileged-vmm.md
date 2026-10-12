# 0014: urljaild runs as root; VMMs run as the operator

- Status: Accepted
- Date: 2026-10-12

## Context
P3 needs root for nearly everything the daemon does: creating network namespaces, starting Firecracker *inside* a VM's namespace, loading nftables rulesets, running the resolver, and (M3) loading eBPF and capturing packets. In P2 the daemon ran as the operator and shelled out to `sudo ip`/`nft`. Starting Firecracker through `sudo ip netns exec` would have run it as root, and with sudo between the daemon and the VMM, the daemon would no longer hold the VMM's PID (an orphan risk if the daemon is killed). Running the VMM as root until the jailer arrives (P5) would be a regression.

## Decision
From P3, `urljaild` runs as root and refuses to start otherwise. It's the only privileged component, as [ADR 0005](./0005-cli-first-control-plane-last.md) planned.

- **The operator** (from `SUDO_UID`, or `-operator`) owns everything handed back: the gRPC socket (`/run/urljail/urljaild.sock`, `0600`), run directories, the VM socket directory. The CLI stays unprivileged.
- **The VMM stays unprivileged:** the daemon starts `ip netns exec <vm-ns> setpriv --reuid=<op> --regid=<op> --clear-groups --no-new-privs -- firecracker ...`. Both tools exec in place, so the process the daemon started *is* Firecracker: same PID and pidfd, uid of the operator, no groups, no capabilities, `NoNewPrivs`, in its VM's namespace (verified in P3 M1).
- **Dev convenience:** the operator's sudoers drop-in allows `bin/urljaild` without a password. The binary is user-writable, so this is root-equivalent, like the existing `ip` entry; both are removed before the live gate ([threat model](../threat-model.md)).

## Alternatives considered
- **Unprivileged daemon + sudo calls:** VMM PID tracking goes through sudo, and every new tool (eBPF loader, tcpdump, unbound) needs another sudoers entry.
- **Root VMM until P5:** simplest, but a step back for the component facing hostile guests.
- **Daemon with capabilities instead of root** (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_BPF`, ...): `CAP_SYS_ADMIN` for namespaces is close to root anyway; revisit with P5 hardening.

## Consequences
- `Pdeathsig` is cleared when setpriv changes the uid, so orphan reaping at daemon start is the backstop for a killed daemon.
- The daemon process (root) must never parse guest data in ways that could be exploited: it already treats every guest byte as hostile input (name allowlists, size caps, JSON validation).
- A root daemon started with `sudo` can't be `SIGKILL`ed through sudo (sudo can't relay `SIGKILL`); use `SIGTERM`.
