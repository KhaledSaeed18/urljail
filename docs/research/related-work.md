# Related work & prior art

To read and compare against. Notes get filled in as each one is studied.

## URL / web detonation services and tools

| Project | What it is | Relevance |
| ------- | ---------- | --------- |
| urlscan.io | Public URL scanning service: screenshots, requests, DOM | Closest product; black box on browser config and cloaking |
| Lookyloo (CIRCL) | Open-source web capture + redirect-chain visualization | Open-source comparison point for reports |
| Elastic "Detonate" | Elastic Security Labs' internal detonation system | Architecture write-up worth reading |
| CAPE / Cuckoo | Malware sandboxes (files, some URL support) | Mature sandbox design, mostly Windows/executables |

## Firecracker-based sandboxes (same technology, different purpose)

| Project | Purpose | What to learn |
| ------- | ------- | ------------- |
| Firecracker docs (`snapshotting/`, `network-for-clones`, `random-for-clones`, jailer) | Primary reference | Clone networking, entropy, jailer setup |
| firecracker-containerd | Containers in microVMs | Lifecycle management patterns |
| weaveworks ignite (archived) | VM manager with container UX | How they handled images and networking |
| liquidmetal flintlock | MicroVM management service | gRPC API design for VM lifecycle |
| E2B, BunkerVM, Zeroboot | Disposable microVM sandboxes for AI-agent code | Snapshot pools, fast restore at scale |

## Cloaking and phishing-crawler research

| Paper | Venue | Takeaway to check |
| ----- | ----- | ----------------- |
| CrawlPhish: client-side cloaking in phishing | IEEE S&P 2021 | Taxonomy of JS cloaking techniques |
| PhishPrint: evading phishing detection crawlers by prior profiling | USENIX Security 2021 | How crawlers get fingerprinted; evaluation framework |
| SPARTACUS | (see PhishPrint authors / follow-ups) | Triggering cloaking on purpose as a defense |
| PhishDecloaker | USENIX Security 2024 | CAPTCHA-based cloaking; vision models to pass gates |

## eBPF / networking references

| Resource | For |
| -------- | --- |
| cilium/ebpf docs + examples (TCX, ring buffer, bpf2go) | capture module |
| "Learning eBPF" (Liz Rice) | fundamentals |
| WireGuard "routing & network namespace integration" page | egress design |
| nftables wiki | ruleset |
