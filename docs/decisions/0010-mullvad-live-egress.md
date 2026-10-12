# 0010: Mullvad as the live-mode WireGuard provider

- Status: Superseded by [0017](./0017-proton-vpn-free.md) (free plan wanted)
- Date: 2026-10-12

## Context
[0003](./0003-wireguard-netns-egress.md) puts live egress through a WireGuard interface in `uj-egress` and needs a provider that supplies plain WireGuard configs (open question Q9).

## Decision
Use **Mullvad**: standard WireGuard configs, accountless sign-up (account number, no email), flat pricing, and many exit locations. The report records the exit used (server name, exit IP, ASN) for every live run.

## Alternatives considered
- **Proton VPN free tier:** few servers and restrictions on the free plan; fine for a quick test but not as the standard exit.
- **WireGuard exit on your own VPS:** cheap and fully controlled, but the exit IP is tied to you, and abuse reports land on your account.
- **Residential proxies:** rejected in [0003](./0003-wireguard-netns-egress.md) on ethical grounds.

## Consequences
- Phishing kits often block VPN and datacenter ASNs, so exit type is a **measured variable** in P6, not something to hide.
- A paid subscription is needed before the live gate.
- `urljail doctor` checks the WireGuard handshake age before allowing live runs.
