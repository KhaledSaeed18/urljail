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
