# Vision

> **urljail**: detonate suspicious URLs in disposable microVMs and report what they actually do.

## The problem

You get a link you don't trust. Static checks (the URL string, domain age, a blocklist lookup) are what attackers optimize against, and they say nothing about what the page *does*. Opening it on your own machine is the one thing you must not do.

Existing services (urlscan.io, commercial sandboxes) answer part of this, but they are black boxes: you can't see how the browser is configured, how the network is captured, or how often the page lied to the scanner. Phishing kits actively **cloak**: they show a harmless page to anything that looks like a scanner and the real phishing page to humans.

## What urljail is

A Linux-native system that, for each URL:

1. Restores a fresh Firecracker microVM from a snapshot (well under a second).
2. Opens the URL in an instrumented Chromium inside the VM.
3. Watches everything from two independent vantage points: **inside** the browser (CDP) and **outside** the VM on the host (eBPF + DNS resolver + firewall).
4. Produces a structured behavioral report: redirect chain, requests, DNS lookups, TLS SNI, credential forms, screenshot, DOM snapshot.
5. Destroys the VM. Nothing survives except the evidence.

## Goals

- **G1: Safe by construction.** A malicious page must not reach the host, the LAN, or the operator's home IP. Isolation is layered, and egress fails closed.
- **G2: Two witnesses.** Every network fact in the report is observed by the guest (CDP) *and* by the host (eBPF/resolver). Disagreement between them is itself a finding.
- **G3: Fast and disposable.** Snapshot restore, not cold boot. One URL = one VM = one lifetime.
- **G4: Honest output.** The report states what was observed, what wasn't, and how confident it is. It never silently fills gaps.
- **G5: Measurable evasion.** Anti-cloaking countermeasures are switchable, so their effect can be measured, not just claimed.
- **G6: Learn the real primitives.** KVM, Firecracker, namespaces, cgroups v2, seccomp, TAP, nftables, eBPF/TCX, vsock: built by hand, not hidden behind a framework.

## Non-goals (for now)

- **Not a malware sandbox for executables.** URLs and the pages behind them only. Downloads are recorded (hash, size, type) but never executed.
- **Not a verdict engine.** urljail reports behavior; deciding "phishing or not" is a downstream consumer (a classifier, an analyst). Simple heuristic flags are fine; an ML model is not part of the core.
- **Not multi-host / cloud scale.** One Linux machine. Horizontal scaling is a later concern, if ever.
- **Not Windows guests.** Linux guest + Chromium only.
- **Not a public service.** Single operator. No auth, no multi-tenancy until the control plane phase.

## Success criteria

| Milestone | Criterion |
| --------- | --------- |
| Works | `urljail detonate https://example.com` returns a JSON report + screenshot, VM destroyed afterwards |
| Fast | p50 restore-to-navigation < 1 s on this laptop |
| Safe | Documented isolation tests pass: LAN unreachable, metadata IPs unreachable, DNS rebinding refused, no egress when VPN is down |
| Trustworthy | Host-side and guest-side network views reconciled in every report |
| Research | Cloaking rate measured with and without each countermeasure on a real feed |

## Design principles

1. **Fail closed.** If a safety layer is missing (VPN down, nftables not loaded), detonation refuses to start: it never degrades to "open".
2. **The guest is hostile.** Anything the guest reports is evidence, not truth. The host never trusts guest input for control decisions.
3. **Evidence over interpretation.** Store raw artifacts (pcap, key log, DOM, HAR-like log); derive the report from them. Reports can be regenerated.
4. **Small, sharp components.** Host agent, guest agent, capture, report builder: each replaceable.
5. **Write it down.** Every non-obvious decision gets an ADR in [`decisions/`](./decisions/).
