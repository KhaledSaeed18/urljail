# 0002: Go for host agent, guest agent and CLI

- Status: Accepted; library list amended by [0011](./0011-hand-written-firecracker-client.md) (no firecracker-go-sdk)
- Date: 2026-10-10

## Context
The operator is comfortable in both Go and Rust. The host agent needs Firecracker control, eBPF loading, netlink/netns, nftables, and gRPC. The guest agent needs CDP and vsock and should be a single static binary.

## Decision
Go everywhere in the core: `urljaild`, `urljail` CLI, guest agent. eBPF programs in C, loaded via cilium/ebpf + bpf2go.

## Alternatives considered
- **Rust (aya, chromiumoxide, hand-rolled Firecracker API client):** viable and educational, but no official Firecracker SDK and a slower path to the first working slice.
- **Mixed (Rust host, Go guest):** two toolchains, two gRPC stacks, little benefit early.

## Consequences
- Libraries: firecracker-go-sdk, cilium/ebpf, vishvananda/netlink + netns, google/nftables (or `nft -f`), chromedp, grpc-go, mdlayher/vsock (guest side).
- Static guest binary (`CGO_ENABLED=0`) drops straight into the rootfs.
- Rust remains available for side quests (e.g. an aya port of the capture module for comparison).
