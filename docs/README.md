# urljail docs

> Detonate suspicious URLs in disposable Firecracker microVMs and report what they actually do.

**Status:** live gate passed (2026-10-12): urljaild runs as a service in live mode, WireGuard (Proton VPN Free) the only exit, verified by its own startup self-test. P6 (anti-cloaking research) next. No code yet. Last updated 2026-10-12.

## Reading order

| # | Doc | What's in it |
| - | --- | ------------ |
| 1 | [vision.md](./vision.md) | Problem, goals, non-goals, success criteria, principles |
| 2 | [architecture.md](./architecture.md) | Components, detonation lifecycle, vsock channel, storage layout, repo layout |
| 3 | [network.md](./network.md) | Netns topology, WireGuard egress, nftables policy, DNS, capture, isolation tests |
| 4 | [threat-model.md](./threat-model.md) | Assets, adversaries, layered mitigations, operating rules |
| 5 | [guest-image.md](./guest-image.md) | Kernel, rootfs, Chromium config, snapshot procedure, clone-safety checklist |
| 6 | [report-schema.md](./report-schema.md) | Draft `report.json` with per-observation sources |
| 7 | [roadmap.md](./roadmap.md) | Phases P0–P7, exit criteria, the live gate |
| 8 | [environment.md](./environment.md) | This host's hardware/OS facts and expected friction |
| 9 | [feed-ingestion.md](./feed-ingestion.md) | Design: feeds as untrusted data, unprivileged ingestion, provenance |
| 10 | [open-questions.md](./open-questions.md) | Remaining open question, verification tasks, and resolved questions with links to where each was recorded |

## Folders

| Folder | Contents |
| ------ | -------- |
| [decisions/](./decisions/) | Architecture Decision Records (ADRs) |
| [research/](./research/) | Research tracks: [anti-cloaking](./research/anti-cloaking.md), [snapshot entropy](./research/snapshot-entropy.md), [related work](./research/related-work.md) |
| [naming/](./naming/) | Name-check reports that led to "urljail" |
| [journal/](./journal/) | One entry per phase: what worked, what broke, what changed |

## Conventions

- Items marked _(verify)_ are believed true but must be confirmed against the actual Firecracker/kernel versions in Phase 1–2.
- Decisions go in `decisions/` as ADRs; questions go in `open-questions.md` until decided.
- [`journal/`](./journal/) has one entry per phase with what worked, what broke, and what changed.

## Glossary

| Term | Meaning |
| ---- | ------- |
| Detonation / run | One URL opened in one fresh microVM; produces one report |
| Clone | A VM restored from a snapshot |
| Profile | A snapshot variant with a specific browser configuration (experimental condition) |
| Egress mode | `off` / `dev` / `live`: what network exit detonations may use |
| Live gate | The checklist that must pass before untrusted URLs are detonated |
| Host-attested / guest-attested | Observed outside the VM (trusted) vs reported by the guest (evidence only) |
| Cloaking | A page showing different content to scanners than to humans |
