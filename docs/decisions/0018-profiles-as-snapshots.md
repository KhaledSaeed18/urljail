# 0018: Experimental conditions are browser profiles, one snapshot each

- Status: Accepted
- Date: 2026-10-12

## Context
P6 compares how phishing pages treat the scanner under different conditions ([research/anti-cloaking.md](../research/anti-cloaking.md)). Chrome is launched inside the snapshot (P4), so anything set at launch (flags, environment) is fixed per snapshot. Settings applied at run time over CDP (user-agent overrides, injected scripts) are themselves detectable and only reach the tab they're set on.

## Decision
A **browser profile** is a named set of launch settings (`BrowserProfile` in the guest API). The daemon builds **one snapshot per profile** at startup (about 11 s each, only when missing or stale) and each run restores from its profile's snapshot. Profiles: `baseline` (Chrome as installed), `stealth` (every countermeasure) and `stealth-no-<x>` (stealth minus one countermeasure, for ablation). Countermeasures are launch flags or environment only, nothing injected into pages.

## Consequences
- No per-run cost: a profile's run is as fast as a baseline run.
- About 2 GB of disk per profile (memory file plus the disk, reflinked).
- Countermeasures that need run-time behavior (simulated interaction) aren't profiles; they'll be a separate run option.
- WebGL reports SwiftShader in every profile (Firecracker has no GPU): a constant, not a condition.
