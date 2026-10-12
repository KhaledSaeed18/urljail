# P1 scripts

Boot a Firecracker microVM by hand, then capture the working steps as scripts. See the [P1 journal](../../docs/journal/p1-boot.md).

| File | Purpose |
| ---- | ------- |
| `env.sh` | Pinned versions, artifact paths and SHA-256s; `urljail_p1_verify` checks them |
| `boot.sh` | Build the rootfs if missing (rootless), create user-owned `tap0`, NAT via firewalld + `DOCKER-USER`, boot via the API socket, wait for SSH, add route + DNS in the guest. `--no-net` boots with the serial console only |
| `teardown.sh` | Ctrl-Alt-Del the guest (force-kill after 5 s), then remove `tap0`, the firewalld changes and the tagged nft rules. `--keep-net` stops the VM only. Safe to rerun |

## Usage

```bash
scripts/p1/boot.sh        # ~2 s to SSH
ssh -i ~/.local/share/urljail/p1/id_ed25519 root@172.16.0.2
scripts/p1/teardown.sh
```

Needs: KVM access (`/dev/kvm`), podman, squashfs-tools, and passwordless sudo for `ip`, `firewall-cmd`, `nft` and `sysctl` (see the [P1 journal](../../docs/journal/p1-boot.md)). The rootfs is reused across boots, so guest changes persist until you delete `~/.local/share/urljail/p1/ubuntu-24.04.ext4`.

Dev only: no isolation exists yet, so benign URLs only.
