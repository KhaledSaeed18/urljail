# P1 scripts

Boot a Firecracker microVM by hand, then capture the working steps as scripts. See the [P1 journal](../../docs/journal/p1-boot.md).

| File | Purpose |
| ---- | ------- |
| `env.sh` | Pinned versions, artifact paths and SHA-256s; `urljail_p1_verify` checks them |
| `boot.sh` | _(written during P1)_ build rootfs, create TAP, boot via API socket, set up NAT |
| `teardown.sh` | _(written during P1)_ kill the VMM, remove TAP and NAT rules, delete the socket |

Dev only: no isolation exists yet, so benign URLs only.
