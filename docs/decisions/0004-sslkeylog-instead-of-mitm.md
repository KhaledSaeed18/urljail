# 0004: TLS visibility via SSLKEYLOGFILE, not a MITM proxy

- Status: Accepted
- Date: 2026-10-10

## Context
Reports need HTTPS content and metadata. The original pitch proposed a transparent mitmproxy with a CA baked into the guest.

## Decision
No MITM. Chromium writes TLS session keys to `SSLKEYLOGFILE` inside the guest; the guest agent ships the key log back; host pcap is decrypted offline. Request/response content also comes from CDP.

## Alternatives considered
- **mitmproxy with injected CA:** servers would see mitmproxy's TLS (JA4) and HTTP/2 fingerprint instead of Chrome's, which is exactly what CDNs and phishing kits use to detect bots. It would undermine the anti-cloaking research and add a component to secure.

## Consequences
- The server sees authentic Chrome TLS/HTTP2 fingerprints.
- Decryption depends on guest-supplied keys (guest-attested); traffic *metadata* (SNI, IPs, sizes, timing) remains host-attested via eBPF/pcap.
- QUIC disabled and ECH disabled by policy so SNI and TLS stay observable on the wire.
