# Development environment

Snapshot of the host as of **2026-10-10**. Update when hardware or OS changes.

## Host

| Item | Value | Implication |
| ---- | ----- | ----------- |
| OS | Fedora 44, kernel 7.2.9 | Recent kernel: TCX eBPF attach, BTF/CO-RE, VMGenID-aware guests all available |
| CPU | Intel i7-8550U, 4 cores / 8 threads, VT-x | Laptop part: thermal throttling under sustained load |
| Virtualization | bare metal (`systemd-detect-virt` = none), `/dev/kvm` present, mode `0666` | No nested virt; no need to join the `kvm` group |
| RAM | 7.1 GiB total, ~4.4 GiB in use at idle desktop | **Primary constraint**: 2 concurrent VMs in dev, 3 max |
| Disk | `/home`: 236 GB, ~210 GB free | Plenty for snapshots + artifacts |
| cgroups | v2 (`cgroup2fs`) | Required by jailer config |
| SELinux | **Enforcing** | Jailer chroot paths need correct contexts; plan a policy module |
| BTF | `/sys/kernel/btf/vmlinux` present | CO-RE eBPF works without kernel headers |
| Network | Wi-Fi on a home LAN | Must never be reachable from guests; live egress via VPN only |

## Tooling

| Tool | Status | Needed for |
| ---- | ------ | ---------- |
| Go | **missing**, install in P1 | host agent, guest agent, CLI |
| Rust (`rustc`) | installed (`~/.cargo`) | optional side quests |
| clang | installed | compiling eBPF C programs |
| bpftool | installed | inspecting loaded programs/maps |
| nft | installed | firewall |
| Docker, Podman | installed | rootfs builds (podman, rootless); **Docker modifies host firewall**, see network.md |
| Node (nvm, v24) | installed | P7 control plane |
| Firecracker + jailer | **missing**, download release binaries in P1 | VMM |
| unbound, WireGuard tools | check in P3 | resolver, egress |

## Known friction to expect

- **SELinux + jailer**: denials when the jailer chroots/mknods; fix with labels/policy, never by disabling SELinux.
- **Docker's nftables/iptables rules**: FORWARD policy DROP in host netns; our design sidesteps by living in dedicated namespaces.
- **RAM pressure**: close heavy desktop apps when running several VMs; consider zram tuning.
- **Laptop sleep/suspend**: kills long runs and VPN handshakes; disable during experiments.
