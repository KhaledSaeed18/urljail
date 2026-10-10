# 0001: Firecracker microVMs

- Status: Accepted
- Date: 2026-10-10

## Context
Each detonation runs hostile web content. We need strong isolation per URL, fast startup, and disposability, on one Linux laptop.

## Decision
Run every detonation in a Firecracker microVM on KVM, restored from a snapshot, under the jailer.

## Alternatives considered
- **Containers (namespaces + seccomp):** share the host kernel, so a kernel exploit from a compromised browser reaches the host. Too thin for deliberately hostile content.
- **QEMU/KVM full VMs:** stronger device realism (virtio-gpu, SMBIOS), but much larger attack surface and slower boot/restore. Kept as a possible *comparison baseline* for anti-cloaking research.
- **gVisor:** good syscall isolation but no real kernel boundary; less learning value for the KVM/VMM layer.
- **Remote browser services:** no control over instrumentation; defeats the purpose.

## Consequences
- Minimal device model: no GPU (WebGL via SwiftShader, a cloaking signal), no SMBIOS, no audio.
- Snapshot/restore gives sub-second clones but introduces clone-uniqueness problems (clock, RNG, network identity).
- Requires bare-metal KVM (available on this host).
- Firecracker vsock is exposed to the host as a Unix socket (`CONNECT <port>` handshake), not host AF_VSOCK.
