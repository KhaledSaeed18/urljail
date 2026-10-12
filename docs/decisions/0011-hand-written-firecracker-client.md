# 0011: Hand-written Firecracker API client

- Status: Accepted
- Date: 2026-10-12
- Amends: [0002](./0002-go-for-host-and-guest.md) (drops firecracker-go-sdk from its library list)

## Context
[ADR 0002](./0002-go-for-host-and-guest.md) listed firecracker-go-sdk for VMM control. As of 2026-10-12 its API definition targets Firecracker API **1.4.1** and its last release is v1.0.0 (2022). urljail pins Firecracker **v1.17.0**, which adds the PCI transport (`--enable-pci`, 1.13), VMClock (1.15) and other changes the SDK doesn't model. P1 booted a VM with six `PUT` calls over the API socket (open question Q18).

## Decision
`internal/vm/` contains a small hand-written client: `net/http` over the Firecracker API Unix socket, with typed request structs only for the endpoints urljail uses (logger, boot-source, drives, network-interfaces, vsock, machine-config, actions, snapshot create/load). The VMM process (and later the jailer) is launched with `os/exec`, and tracked by pidfd/cgroup rather than a PID file (lesson from P1).

`firecracker_spec-v1.17.0.yaml`, shipped in the release tarball, is the reference for field names and semantics. If the endpoint list grows past what's comfortable by hand, generate the client from that spec instead.

## Alternatives considered
- **firecracker-go-sdk:** lags the API by many versions, and its machine/jailer abstractions hide the steps urljail wants to control and learn (goal G6).
- **Client generated from the OpenAPI spec now:** exact, but a large generated surface for ~10 calls; kept as the fallback.
- **SDK for process/jailer helpers only:** still pulls in the outdated models, and the jailer invocation is a handful of flags.

## Consequences
- Firecracker upgrades mean diffing the spec YAML between releases and updating the structs that changed.
- Jailer invocation (chroot layout, uid/gid, cgroups, netns) is written by hand in P5.
- One fewer dependency in the privileged daemon.
