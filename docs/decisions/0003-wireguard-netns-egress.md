# 0003: Live egress through WireGuard in a dedicated netns

- Status: Accepted
- Date: 2026-10-10

## Context
Live phishing URLs must never be fetched from the operator's home IP, and guests must never reach the home LAN. The host is a laptop on a home network; no spare hardware or VLAN-capable switch is assumed.

## Decision
A shared `uj-egress` network namespace holds the nftables policy, the resolver, and `wg0`. `wg0` is created in the host namespace and moved into `uj-egress`, so its encrypted UDP leaves via the host's Wi-Fi while the plaintext interface and the only default route exist inside `uj-egress`. Three egress modes: `off` (default), `dev` (host NAT, allowlisted benign URLs only), `live` (wg0 only). The daemon refuses non-allowlisted URLs unless in `live` mode with a healthy tunnel.

## Alternatives considered
- **Separate VLAN / physical network:** strongest, but needs hardware; may be added later.
- **System-wide VPN on the host:** affects all operator traffic, and fails *open* when it drops.
- **Residential proxies:** better for anti-cloaking but many networks are built from unwitting users' devices; ethically hard to defend.
- **Tor:** heavily flagged by phishing kits; skews cloaking measurements.

## Consequences
- **Fails closed:** tunnel down ⇒ no route.
- VPN exit IPs are themselves a cloaking signal; becomes an experimental variable.
- Needs a VPN provider with WireGuard configs (e.g. Mullvad; verify Proton free tier).
- DNS upstream also goes via `wg0` in live mode.
