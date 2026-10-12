# 0007: gRPC over the Firecracker vsock stream

- Status: Accepted
- Date: 2026-10-12

## Context
The host agent and the guest agent need a control and evidence channel: `SyncClock`, `Reseed` and `Detonate` from host to guest, and a stream of CDP-derived events plus artifacts from guest to host. Firecracker exposes guest vsock to the host as a Unix domain socket, not host AF_VSOCK. Once a connection is set up it's a plain byte stream, so any framing works (open questions Q1, Q8).

## Decision
**gRPC over the vsock stream**, with the service defined in `api/proto/` alongside the CLI↔daemon API.

Connection setup follows Firecracker's vsock protocol _(confirm with an integration test in P2)_:

| Direction | Mechanism | Used for |
| --------- | --------- | -------- |
| Host → guest | Host connects to the VM's UDS, writes `CONNECT <port>\n`, reads `OK <host_port>\n`, then speaks gRPC on the stream | Control: `SyncClock`, `Reseed`, `Detonate` and the event stream |
| Guest → host | Guest connects to AF_VSOCK CID 2; Firecracker forwards it to a host listener on `<uds_path>_<port>` | Not used in v1; reserved |

The host side wraps the handshake in a custom gRPC dialer. The guest side listens with `mdlayher/vsock`.

## Alternatives considered
- **Length-prefixed protobuf:** fewer moving parts, but you hand-roll request/response correlation, streaming and cancellation, which gRPC already provides.
- **JSON lines:** untyped, and binary artifacts would need base64.
- **HTTP/1.1 + JSON:** same typing problem, and no natural server-streaming.

## Consequences
- One protobuf/gRPC toolchain for both the CLI↔daemon and host↔guest links.
- Deadlines and cancellation carry over to the guest, so a host timeout ends guest work cleanly.
- Large artifacts (screenshot, DOM, key log) must be **chunked**, because gRPC's default maximum message size is 4 MB.
- A single host-initiated connection keeps the guest from opening sockets towards the host, so there's one less listener on the host side.
