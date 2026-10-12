# Architecture Decision Records

One file per significant decision. Never edit an accepted ADR's decision. Supersede it with a new one and link both ways.

| # | Decision | Status | Date |
| - | -------- | ------ | ---- |
| [0001](./0001-firecracker-microvms.md) | Firecracker microVMs (not containers, not QEMU) | Accepted | 2026-10-10 |
| [0002](./0002-go-for-host-and-guest.md) | Go for host agent, guest agent and CLI | Accepted | 2026-10-10 |
| [0003](./0003-wireguard-netns-egress.md) | Live egress through WireGuard moved into a dedicated netns | Accepted | 2026-10-10 |
| [0004](./0004-sslkeylog-instead-of-mitm.md) | TLS visibility via SSLKEYLOGFILE, not a MITM proxy | Accepted | 2026-10-10 |
| [0005](./0005-cli-first-control-plane-last.md) | CLI first; NestJS/Next.js control plane last | Accepted | 2026-10-10 |
| [0006](./0006-name-urljail.md) | Project name: urljail | Accepted | 2026-10-10 |
| [0007](./0007-grpc-over-vsock.md) | gRPC over the Firecracker vsock stream | Accepted | 2026-10-12 |
| [0008](./0008-protobuf-report-schema.md) | Protobuf as the report schema source of truth; UUIDv7 run IDs | Accepted | 2026-10-12 |
| [0009](./0009-debian-guest-ci-kernel.md) | Debian 13 slim guest, CI kernel until P4, new headless as baseline | Accepted | 2026-10-12 |
| [0010](./0010-mullvad-live-egress.md) | Mullvad as the live-mode WireGuard provider | Accepted | 2026-10-12 |
| [0011](./0011-hand-written-firecracker-client.md) | Hand-written Firecracker API client (amends 0002) | Accepted | 2026-10-12 |
| [0012](./0012-google-chrome-stable-in-guest.md) | Google Chrome stable in the guest, pinned and archived | Accepted | 2026-10-12 |
| [0013](./0013-own-cdp-client-over-pipe.md) | Own CDP client over --remote-debugging-pipe (cdproto types, no chromedp) | Accepted | 2026-10-12 |
| [0014](./0014-root-daemon-unprivileged-vmm.md) | urljaild runs as root; VMMs run as the operator | Accepted | 2026-10-12 |
| [0015](./0015-restore-on-demand.md) | Restore on demand; kvmclock and VMGenID for clone safety (no pool, SyncClock or Reseed) | Accepted | 2026-10-12 |

## Template

```markdown
# NNNN: Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context
What forces are at play; what problem needs deciding.

## Decision
What we chose.

## Alternatives considered
What else, and why not.

## Consequences
What becomes easier, harder, or newly required.
```
