# Development environment

Snapshot of the host as of **2026-10-12**. Update when hardware or OS changes.

## Host

| Item | Value | Implication |
| ---- | ----- | ----------- |
| OS | Fedora 44, kernel 7.2.9 | Recent kernel: TCX eBPF attach, BTF/CO-RE, VMGenID-aware guests all available |
| CPU | Intel i7-8550U, 4 cores / 8 threads, VT-x | Laptop part: thermal throttling under sustained load |
| Virtualization | bare metal (`systemd-detect-virt` = none), `/dev/kvm` present, mode `0666` | No nested virt; no need to join the `kvm` group |
| RAM | 7.1 GiB total, ~4.4 GiB in use at idle desktop | Snapshot clones share memory: ~125 MiB each (P4), default 3 concurrent; CPU (4c/8t) is the limit now |
| Disk | `/home`: 236 GB, ~210 GB free | Plenty for snapshots + artifacts |
| cgroups | v2 (`cgroup2fs`) | Required by jailer config |
| SELinux | **Enforcing** | Jailer chroot paths need correct contexts; plan a policy module |
| BTF | `/sys/kernel/btf/vmlinux` present | CO-RE eBPF works without kernel headers |
| Network | Wi-Fi on a home LAN (`wlp2s0`) | Must never be reachable from guests; live egress via VPN only |
| firewalld | running, default zone `FedoraWorkstation` | Filters host forwarding too; P1 puts `tap0` in `trusted` (runtime only) |
| auditd | active | SELinux denials go to `/var/log/audit/audit.log` (root only), not the journal |
| sudo | password; plus a dev-only NOPASSWD rule for `ip`, `firewall-cmd`, `nft`, `sysctl` | See [threat model](./threat-model.md); remove before the live gate |
| subuid/subgid | `524288:65536` | Rootless rootfs builds with `podman unshare` |

## Tooling

| Tool | Status | Needed for |
| ---- | ------ | ---------- |
| Go | 1.27.2, user-local in `~/.local/go` | host agent, guest agent, CLI |
| Rust (`rustc`) | installed (`~/.cargo`) | optional side quests |
| clang | installed | compiling eBPF C programs |
| bpftool | installed | inspecting loaded programs/maps |
| nft | installed | firewall |
| Docker, Podman | installed | rootfs builds (podman, rootless); **Docker modifies host firewall**, see network.md |
| Node (nvm, v24) | installed | P7 control plane |
| Firecracker + jailer | v1.17.0 in `~/.local/share/urljail/firecracker/`, symlinked in `~/.local/bin` | VMM |
| unbound, WireGuard tools | missing; install in P3 | resolver, egress |
| squashfs-tools | **missing**; `sudo dnf install squashfs-tools` at P1 start | unpacking the CI rootfs |
| tcpdump | installed | pcap (P3) |

## Known friction to expect

- **SELinux + jailer**: denials when the jailer chroots/mknods; fix with labels/policy, never by disabling SELinux.
- **Docker's nftables/iptables rules**: FORWARD policy DROP in the host netns, and the rules **stay loaded after `systemctl stop docker`**. P1 needed accept rules in `DOCKER-USER`. The netns design avoids this for VM↔egress traffic, but `dev` mode egress through the host still meets it ([network.md](./network.md#nftables-policy-egress-netns)).
- **sudo needs a TTY**: Claude Code's `!` commands can't prompt for a password, and Fedora caches sudo credentials per TTY.
- **RAM pressure**: close heavy desktop apps when running several VMs; consider zram tuning.
- **Laptop sleep/suspend**: kills long runs and VPN handshakes; disable during experiments.
