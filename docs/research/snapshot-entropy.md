# Research track R2: entropy uniqueness across snapshot clones

Status: **idea / design**. Side quest after Phase 4.

## Problem

Every clone restored from the same snapshot starts with **identical memory**, which includes every random-number generator's internal state at snapshot time. Two clones may then produce the *same* "random" values: TCP initial sequence numbers, TLS client randoms, session IDs, key shares, UUIDs, Chromium's internal tokens.

Consequences:
- **Security:** reused nonces/key shares can break cryptographic assumptions.
- **Fingerprinting:** a phishing kit (or CDN) seeing identical values from different IPs could link and flag our scanners.
- **Research validity:** clones that aren't independent bias measurements.

Firecracker documents this concern (`random-for-clones`) _(verify current doc name)_.

## Layers of state

| Layer | State | Fix available |
| ----- | ----- | ------------- |
| Guest kernel CRNG | cloned | **VMGenID**: the VMM changes a generation ID on restore; Linux (≥ 5.18 with `CONFIG_VMGENID`) reseeds on change. Firecracker exposes a VMGenID device on x86_64 since 1.8.0; confirmed bound in the guest on v1.17.0 ([P1 journal](../journal/p1-boot.md)). Also: host-injected entropy over vsock |
| Kernel-derived values (TCP ISN, etc.) | depend on CRNG + secrets | fixed if CRNG reseeded before first use |
| **Userspace PRNGs** (BoringSSL in Chromium, V8 `Math.random`, Go runtime in guest agent) | **cloned, and the kernel reseed does not touch them** | open question: this is the interesting part |

## Experiments

1. **Baseline:** restore N clones *without* VMGenID/reseed; have each make a TLS connection to a test server we control; collect ClientHello random, session ID, key shares (from pcap) and `Math.random()` outputs (from a test page). Count duplicates.
2. **Kernel fix only:** enable VMGenID + vsock reseed. Repeat. Expect kernel-level values to diverge; measure whether Chromium's values still collide.
3. **Userspace:** investigate how BoringSSL seeds and reseeds (fork-safety, RDRAND mixing, reseed intervals) and whether V8's PRNG state is reseeded at all. Test mitigations: restart renderer processes after restore; snapshot *before* launching Chromium (trades restore speed for safety); `MADV_WIPEONFORK`-style tricks don't apply to VM clones.
4. **Cost:** restore latency for each mitigation.

## Deliverable

A write-up: which values collide under which configuration, root causes, mitigation trade-offs, and a recommended clone-safety procedure for urljail's [guest-image.md checklist](../guest-image.md#clone-safety-checklist-each-restore).
