# Open questions

Each question gets resolved into an ADR, a doc update, or explicitly parked. Leaning = current best guess, not a decision.

## Open

| # | Question | Leaning | Decide by |
| - | -------- | ------- | --------- |
| — | _(none)_ | | |

## Verification tasks

Decided in principle; each needs a fact confirmed on the real stack.

| # | Question | Plan | When |
| - | -------- | ---- | ---- |

## Resolved

| # | Question | Resolution | Recorded in |
| - | -------- | ---------- | ----------- |
| Q1 | Host↔guest framing over vsock | gRPC over the vsock stream; large artifacts chunked | [ADR 0007](./decisions/0007-grpc-over-vsock.md) |
| Q2 | Rootfs base | Debian 13 slim | [ADR 0009](./decisions/0009-debian-guest-ci-kernel.md) |
| Q3 | Guest kernel | Firecracker CI kernel P1–P3; own config with `CONFIG_VMGENID` from P4 | [ADR 0009](./decisions/0009-debian-guest-ci-kernel.md) |
| Q4 | nftables from Go | Generated `nft -f` file: validate with `nft -c`, apply atomically, hash at preflight | [network.md](./network.md#nftables-policy-egress-netns) |
| Q5 | pcap capture | `tcpdump` subprocess in the VM netns for P3; in-process later only if needed | [network.md](./network.md#host-side-capture) |
| Q6 | Report schema source of truth | Protobuf; `report.json` via protojson; JSON Schema generated from the proto | [ADR 0008](./decisions/0008-protobuf-report-schema.md) |
| Q7 | VMGenID on x86_64 with Firecracker v1.17.0 | Exposed (`VMGENCTR:00`, driver bound, P1) and the kernel reseeds on every restore (`crng reseeded due to virtual machine fork`, P4). Userspace RNG state is still cloned (research R2) | [P4 journal](./journal/p4-snapshots.md) |
| Q8 | Firecracker vsock `CONNECT` handshake semantics | Verified in P2: `CONNECT 1024` / `OK <port>` as documented; unit test against a fake Firecracker plus every real run ([P2 journal](./journal/p2-slice.md)) | [ADR 0007](./decisions/0007-grpc-over-vsock.md) |
| Q9 | VPN provider for live mode | Mullvad | [ADR 0010](./decisions/0010-mullvad-live-egress.md) |
| Q10 | Interaction simulation | None in v1; a research variable in P6 | [research/anti-cloaking.md](./research/anti-cloaking.md) |
| Q11 | Dwell time per run | Network idle, bounded by min/max, plus jitter | [architecture.md](./architecture.md#detonation-lifecycle) |
| Q12 | Artifact retention | Rotate pcaps after N days (configurable) with a total disk cap; keep reports | [architecture.md](./architecture.md#storage-layout-per-run) |
| Q13 | Feed terms of use and source | Free feeds first (OpenPhish Community + URLhaus), within their terms; a fresher phishing source later for cloaking statistics (2026-10-12) | [research/feeds.md](./research/feeds.md), [feed-ingestion.md](./feed-ingestion.md) |
| Q14 | Run IDs | UUIDv7 | [ADR 0008](./decisions/0008-protobuf-report-schema.md) |
| Q15 | Display server for headful Chromium | `--headless=new` baseline; headful (Xvfb / cage) as a P6 profile, cost measured then | [ADR 0009](./decisions/0009-debian-guest-ci-kernel.md) |
| Q16 | Use `linkopsy` as the name of the report or subcommand? | Parked: keep `urljail detonate` | — |
| Q17 | Guest browser build | Google Chrome stable `.deb`, pinned and archived (Debian 13's `chromium` is 5 majors behind) | [ADR 0012](./decisions/0012-google-chrome-stable-in-guest.md) |
| Q18 | Firecracker API client | Hand-written thin client over the API socket; generate from the v1.17.0 OpenAPI spec if it grows | [ADR 0011](./decisions/0011-hand-written-firecracker-client.md) |
