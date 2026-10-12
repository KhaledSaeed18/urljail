# Live gate

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [live gate](../roadmap.md#live-gate-before-p6-next)
- Exit: every item on the roadmap's live-gate checklist done; live mode then starts only through its interlock.

## WireGuard egress (done with a local test peer; real VPN pending)

- **As designed in [ADR 0003](../decisions/0003-wireguard-netns-egress.md):** `wg0` is created in the host namespace (its encrypted UDP leaves through the host's network) and moved into `uj-egress`, where it holds the **only** default route. In live mode there is no link from the egress namespace to the host at all: with the tunnel down there is no route out. Configured over netlink (`wgctrl`), so `wireguard-tools` isn't needed. Input is a standard wg-quick file (`-wg-config`, must be `0600`).
- **Resolver in live mode** forwards to the VPN's DNS (from the config). A VPN's DNS is often private (Mullvad: `10.64.0.1`), so the egress output rules allow exactly those upstream addresses on the exit before the private-address drop.
- **Live interlock** (in the daemon, not convention): `-egress live` is refused while `/etc/sudoers.d/urljail-dev` exists, without a WireGuard config, or until the tunnel has a handshake; the daemon then runs its own isolation self-test and refuses to serve unless it passes. Every run's preflight requires a handshake under 3 minutes old (keepalive 25 s), exactly one default route via the exit, and the usual ruleset hashes.
- **Live self-test checks:** *VPN down ⇒ no egress* (the tunnel is really taken down; the guest must not reach a public IP; the tunnel is restored and must handshake again) and *public IP seen by the guest is the VPN exit* (the guest fetches `https://api.ipify.org`; the host asks the same from its own namespace; they must differ).
- **`-egress live-test`:** the same WireGuard path to a local peer in namespace `uj-testvpn`, which terminates the tunnel and NATs out through the host. Its exit IP is the home IP, so the URL policy stays the dev allowlist and the exit-IP check is skipped (it correctly saw guest and host both at `185.160.227.25`).

### Result in live-test mode

Startup self-test passed through the tunnel, including **VPN down ⇒ no egress: `connect: network is unreachable`** with the tunnel down; the egress namespace held only `lo` and `wg0`, with `default dev wg0`. Detonations ran through the tunnel (navigate 220 ms, reports consistent); a non-allowlisted URL was refused. Shutdown left no namespace, `wg0`, test-peer link or `DOCKER-USER` rule. Dev mode passed a regression run afterwards.

### Bugs found by the tunnel

- **MTU:** `wg0` has MTU 1420, the guest 1500, so the egress namespace sent ICMP "need to frag" for most connections. Path-MTU discovery coped here, but VPN paths often drop that ICMP. Clamping only outgoing SYNs (`rt mtu`) wasn't enough: the guest takes its segment size from the server's SYN-ACK. Now SYNs both ways across the exit are clamped to the exit MTU − 40 (1380 on WireGuard, 1460 on the dev exit): zero "need to frag" afterwards.
- **IP fragments counted as flows:** a run showed 365 flows, 345 of them to random ports. Non-first IP fragments carry no TCP/UDP header, and the BPF program read their payload as ports. It now skips L4 parsing for fragments: back to 23–25 flows.

## Checklist

| Item | State |
| ---- | ----- |
| WireGuard-in-netns egress working; `live` mode interlock in the daemon | done with the test peer; needs a run with the real VPN config |
| Full isolation test plan in `live` mode, incl. "VPN down ⇒ no egress" | passes in live-test; the exit-IP check needs the real VPN |
| Dev sudo rule removed | pending (operator); the daemon needs another way to start first (systemd unit) |
| Threat model reviewed against what was built | pending |
| Feed terms of use checked (Q13) | pending (operator decision) |
| Feed ingestion design, URLs strictly as data | pending |
| Mullvad subscription; exit recorded per run | pending (operator) |
