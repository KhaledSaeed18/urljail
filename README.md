# urljail

**Detonate suspicious URLs in disposable Firecracker microVMs and report what they actually do.**

> **Status: Phase 5 next.** `urljail detonate` restores a Firecracker snapshot (Chrome already running; ~0.2 s to navigation) in its own network namespace, drives sandboxed Chrome over a CDP pipe, captures DNS, flows (with SNI), blocked attempts and a pcap on the host, and writes a report that reconciles the host's view with the guest's. `urljail selftest` runs the isolation test plan; `urljail doctor` checks the host. Dev mode only: benign allowlisted URLs, egress via the home IP until the live gate. See the [roadmap](docs/roadmap.md).

## What it does

Give urljail a link you don't trust. It:

1. Restores a fresh Firecracker microVM from a snapshot (well under a second).
2. Opens the URL in an instrumented Chromium inside the VM.
3. Observes everything from two independent vantage points: **inside** the browser (Chrome DevTools Protocol) and **outside** the VM on the host (eBPF, DNS resolver, firewall).
4. Writes a behavioral report: redirect chain, requests, DNS lookups, TLS SNI, credential forms, screenshot, DOM snapshot.
5. Destroys the VM. Nothing survives except the evidence.

```
urljail detonate https://suspicious.example
```

## How it works

```
 urljail CLI ──gRPC──► urljaild (host agent, Go)
                          │
                          ├─ restores microVM clone ── jailer (chroot · cgroups v2 · seccomp · netns)
                          │                              └─ Firecracker on KVM
                          │                                   └─ guest agent + Chromium (CDP)
                          │  vsock
                          ├─ per-VM network namespace ── TAP ── eBPF flow/SNI capture + pcap
                          ├─ egress namespace ── nftables (no LAN, no metadata) ── resolver ── WireGuard
                          └─ report builder ── merges host + guest evidence → report.json
```

Built on Linux kernel primitives end to end: **KVM, Firecracker + jailer, network namespaces, TAP, nftables, eBPF (TCX), cgroups v2, seccomp, vsock**.

## Design highlights

- **Safe by construction:** guests can't reach the host, the LAN, or link-local/metadata addresses. Live egress goes only through a WireGuard tunnel living in its own namespace, so if the tunnel drops there is *no route*: it fails closed.
- **Two witnesses:** every network fact is seen by the browser *and* by the host. Disagreement is itself a finding.
- **Authentic fingerprints:** no MITM proxy. TLS is decrypted offline from Chromium's key log, so servers see a real Chrome TLS fingerprint.
- **Measurable evasion:** anti-cloaking countermeasures are switchable snapshot profiles, so their effect on phishing-kit cloaking can be measured rather than assumed.

## Documentation

Start at [docs/README.md](docs/README.md).

| Doc | Topic |
| --- | ----- |
| [Vision](docs/vision.md) | Problem, goals, non-goals |
| [Architecture](docs/architecture.md) | Components, lifecycle, storage |
| [Network](docs/network.md) | Isolation, egress, DNS, capture |
| [Threat model](docs/threat-model.md) | Assets, adversaries, mitigations |
| [Roadmap](docs/roadmap.md) | Phases and exit criteria |
| [Decisions](docs/decisions/) | Architecture Decision Records |
| [Research](docs/research/) | Anti-cloaking, snapshot entropy, related work |

## Stack

Go (host agent, guest agent, CLI) · C (eBPF programs) · Firecracker · Chromium · nftables · unbound · WireGuard. A NestJS + Next.js control plane comes last.

## Safety notice

urljail is designed to load hostile web content. Do not run it against live phishing or malware URLs until the isolation tests and the live gate in the [roadmap](docs/roadmap.md#live-gate-before-p6) pass on your machine.
