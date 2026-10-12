# 0017: Proton VPN Free as the live-mode WireGuard exit

- Status: Accepted
- Date: 2026-10-12
- Supersedes: [0010](./0010-mullvad-live-egress.md)

## Context
[ADR 0010](./0010-mullvad-live-egress.md) picked Mullvad (paid). The operator wants a free option. urljail's live exit takes any standard wg-quick config (`-wg-config`), so the provider is a configuration choice, not code.

## Decision
Use **Proton VPN's free plan**: no payment, open-source clients, a no-logs policy, and manual WireGuard configs for its free servers. In the config generator: **NetShield off** (it filters malware and ad domains at DNS, which would change what detonations see), no extra features. Proton's resolver (`10.2.0.1`) is private, which the egress rules already allow by exact address.

## Alternatives considered
- **Mullvad** (ADR 0010): better server choice and accountless, but paid.
- **Self-hosted WireGuard on a free cloud VM:** fully open source, but the exit IP is tied to the operator's cloud account and abuse reports land there.
- **Tor:** free and open source, but heavily blocked by phishing kits (skews the cloaking research, as ADR 0003 noted) and needs different plumbing.

## Consequences
- Few free servers and countries, modest speed, one device: fine for single detonations; exit diversity for P6 (exit type as a variable) is limited.
- As with any VPN, the provider sees exit traffic (accepted in the threat model).
- The live interlock is unchanged: the daemon's self-test must see the guest's public IP differ from the home IP before it serves.
