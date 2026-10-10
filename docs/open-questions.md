# Open questions

Each question gets resolved into an ADR, a doc update, or explicitly parked. Leaning = current best guess, not a decision.

| # | Question | Leaning | Decide by |
| - | -------- | ------- | --------- |
| Q1 | Host↔guest framing over vsock: gRPC vs length-prefixed protobuf vs JSON lines | gRPC over the vsock stream (typed, streaming, same toolchain) | P2 |
| Q2 | Rootfs base: Debian slim vs Alpine vs Ubuntu minimal | Debian slim (Chromium deps, glibc) | P2 |
| Q3 | Guest kernel: build our own vs Firecracker CI kernel | CI kernel in P1–P2, own config from P4 (need `CONFIG_VMGENID`) | P4 |
| Q4 | nftables from Go: google/nftables library vs generated `nft -f` file | `nft -f` file (readable, diffable, hashable); library later if needed | P3 |
| Q5 | pcap: in-process AF_PACKET (gopacket/pcapgo) vs `tcpdump` subprocess | `tcpdump` in P3 for speed; in-process later | P3 |
| Q6 | Report schema source of truth: protobuf vs JSON Schema vs Go structs | Protobuf (shared with gRPC), JSON via protojson | P2 |
| Q7 | Does the Firecracker release we pick expose VMGenID on x86_64? | Verify in P1 | P1 |
| Q8 | Firecracker vsock host side: confirm UDS + `CONNECT <port>` handshake semantics for host-initiated and guest-initiated connections | Verify in P2 | P2 |
| Q9 | VPN provider for live mode | Mullvad (WireGuard, no account); check Proton free tier | Live gate |
| Q10 | Interaction simulation: none, scripted, or replayed human traces | None in v1; a research variable in P6 | P6 |
| Q11 | Dwell time per run: fixed vs adaptive (network idle) | Network-idle + min/max bounds + jitter | P2 |
| Q12 | Artifact retention: keep pcaps forever or rotate | Rotate pcaps after N days; keep reports | P7 |
| Q13 | Feed terms of use (OpenPhish, URLhaus, PhishTank) permit research detonation? | Check each before ingestion | Live gate |
| Q14 | Run IDs: ULID vs UUIDv7 | Either; pick one in P2 | P2 |
| Q15 | Headful Chromium needs a display server in the guest (Xvfb vs cage/Wayland headless): cost in RAM and boot time? | Measure in P6 | P6 |
| Q16 | Should `linkopsy` become the name of the report/subcommand (`urljail linkopsy <url>`)? | Maybe; cosmetic | anytime |
