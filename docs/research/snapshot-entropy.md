# Research track R2: entropy uniqueness across snapshot clones

Status: **in progress**: kernel and TLS randomness verified independent across clones; V8 `Math.random()` found cloned (2026-10-19), fix pending. Side quest after Phase 4.

## Problem

Every clone restored from the same snapshot starts with **identical memory**, which includes every random-number generator's internal state at snapshot time. Two clones may then produce the *same* "random" values: TCP initial sequence numbers, TLS client randoms, session IDs, key shares, UUIDs, Chromium's internal tokens.

Consequences:
- **Security:** reused nonces/key shares can break cryptographic assumptions.
- **Fingerprinting:** a phishing kit (or CDN) seeing identical values from different IPs could link and flag our scanners.
- **Research validity:** clones that aren't independent bias measurements.

Firecracker documents this concern in `docs/snapshotting/random-for-clones.md` ("Entropy for Clones") and, for v1.17.0, states it plainly in `snapshot-support.md`: after a VMGenID reseed, "state other than the guest kernel entropy pool, such as unique identifiers, cached random numbers, cryptographic tokens, etc **will** still be replicated".

## Layers of state

| Layer | State | Fix available |
| ----- | ----- | ------------- |
| Guest kernel CRNG | cloned | **VMGenID**: the VMM changes a generation ID on restore; Linux (≥ 5.18 with `CONFIG_VMGENID`) reseeds on change. Firecracker exposes a VMGenID device on x86_64 since 1.8.0; confirmed bound in the guest on v1.17.0 ([P1 journal](../journal/p1-boot.md)). Also: host-injected entropy over vsock |
| Kernel-derived values (TCP ISN, etc.) | depend on CRNG + secrets | fixed if CRNG reseeded before first use |
| **Userspace PRNGs** (BoringSSL in Chromium, V8 `Math.random`, Go runtime in guest agent) | **cloned, and the kernel reseed does not touch them** | open question: this is the interesting part |

## First data point (P4 M2, 2026-10-12)

Three clones of one snapshot, Chrome 155 prepared before the snapshot, guest kernel 6.18 with VMGenID: the kernel reseeded on every restore (`crng reseeded due to virtual machine fork`), guest `getrandom` output differed, and **all 25 TLS ClientHello randoms and session IDs** captured on the host were distinct. Not yet checked: key shares, V8 `Math.random`, other userspace state. See [the P4 journal](../journal/p4-snapshots.md#m2-notes).

## Second data point (P7, 2026-10-14): every capture so far

[`scripts/research/tls-hellos.py`](../../scripts/research/tls-hellos.py) reads every run's host capture and pulls each guest ClientHello's random, legacy session ID and X25519 key share (run with `python3 -I`; the pcaps are untrusted input and every length is bounds-checked). Over all retained captures, from 2,614 runs on six snapshots (812 restores of `baseline`, 631 of `stealth`, 556 of `stealth-headful`, about 185 of each other profile):

| Value | Seen | Distinct | Seen in more than one run |
| ----- | ---- | -------- | ------------------------- |
| Client random | 34,955 | 34,750 | **0** |
| Session ID | 34,955 | 34,736 | **0** |
| X25519 key share | 34,758 | 34,725 | **0** |

Every repeat is a TCP retransmission inside one run (same random, same session ID, the key share agreeing or past the captured segment in one copy: 186 of 186). So Chromium's TLS randomness is not cloned across restores of one snapshot: BoringSSL draws from the kernel, and the kernel reseeds on VMGenID. This closes the TLS part of experiment 1 for the configuration urljail runs (VMGenID on). Still open: V8 `Math.random()` and `crypto.getRandomValues()` in pages, which need a test page served to the guest, and anything cached in the browser process before the snapshot.

## Third data point (2026-10-19): `Math.random()` is cloned

No test page was needed: Google Analytics 4 is one. gtag.js makes the client ID (`cid=<random>.<seconds>` on every `g/collect` request) the first time a site is visited, the random part from `Math.random()` in the page. Each restore starts with no cookies, so every run makes a new one. [`scripts/research/ga-client-ids.py`](../../scripts/research/ga-client-ids.py) pulls them from every run's guest request log (`python3 -I`):

| | |
| --- | --- |
| Runs with a GA4 client ID | 164 (on all six snapshots) |
| Distinct random parts | 132 |
| Random parts seen in more than one run | **22, covering 46 runs (28 %)** |
| ... on different sites | 5 |
| ... across different snapshots | 0 |

Two independent draws of a 31-bit value colliding 22 times in 156 is impossible by chance (expected ≈ 6 × 10⁻⁶). The seconds part differs in nearly every pair (the ID was made fresh, minutes to hours apart), and the repeats cross sites: `754490377` on `tracking.autosoftdms.com` at 01:51 and on `kdgaccounting.co.nz` at 03:33 (`baseline`); `881706934` on `pedenaccountingservices.com` at 07:00 and on `ideanote.korange.work` at 09:20 (`stealth`); `1831006613` on `fine-ants-ing.net` and four hours later on `strangerthings-store.com` (`stealth-headful`). So **every clone of a snapshot replays the same `Math.random()` sequence**: two pages that call it the same number of times before making the ID get the same ID, whatever site they're on.

Why, most likely (to be confirmed by the fix): the guest agent drives the tab Chrome opened before the snapshot ([browser.go](../../cmd/urljail-agent/browser.go)), and the first navigation from that tab's initial `about:blank` stays in its renderer process, created before the snapshot. V8 seeds each isolate's xorshift128+ once, at creation, from the OS; the kernel reseed on restore (VMGenID) doesn't reach state already in a process. TLS randomness is different (second data point): BoringSSL in the network process reads the kernel for each handshake's randomness.

What it costs urljail:

- **Linkability.** Google Analytics, and any tracker that draws an ID from `Math.random()`, receives the same IDs from runs that are supposed to be unrelated visitors. A kit operator's analytics can tie urljail's visits together across sites and exits.
- **A cloaking signal.** A page can compare the first few `Math.random()` outputs with values seen before: a visitor whose "random" numbers repeat a previous visitor's is a cloned scanner. One evaluation in a kit's script is enough, and no browser countermeasure profile changes it.
- **Research validity.** Profile comparisons (R1) assume independent visits; on this axis clones aren't.

Fix (written, not yet in the image): before navigating, the agent kills Chrome's renderer processes (those in its process group whose command line says `--type=renderer`) and waits for `Inspector.targetCrashed` on the tab; `Page.navigate` then starts the page in a renderer forked from the zygote after the restore, whose V8 isolate is seeded after the VMGenID reseed ([renderer.go](../../cmd/urljail-agent/renderer.go)). Against Chrome 155 on the host (`URLJAIL_TEST_CHROME`), 8 of 8 runs: 5 renderers replaced in 35–56 ms, the page loads and its script runs in new ones. To be verified in the VMs the same way as found: GA client IDs of runs after the fix should never repeat.

## Experiments

1. **Baseline:** restore N clones *without* VMGenID/reseed; have each make a TLS connection to a test server we control; collect ClientHello random, session ID, key shares (from pcap) and `Math.random()` outputs (from a test page). Count duplicates.
2. **Kernel fix only:** enable VMGenID + vsock reseed. Repeat. Expect kernel-level values to diverge; measure whether Chromium's values still collide.
3. **Userspace:** investigate how BoringSSL seeds and reseeds (fork-safety, RDRAND mixing, reseed intervals) and whether V8's PRNG state is reseeded at all. Test mitigations: restart renderer processes after restore; snapshot *before* launching Chromium (trades restore speed for safety); `MADV_WIPEONFORK`-style tricks don't apply to VM clones.
4. **VMClock:** Firecracker ≥ 1.15 exposes a VMClock device whose `vm_generation_counter` changes on every restore. With a Linux ≥ 7.0 guest, userspace can `mmap()` it or `poll()` the device. Test whether the guest agent can use it to trigger re-randomization (restart renderers, reseed its own state) faster than a vsock message arrives.
5. **Cost:** restore latency for each mitigation.

## Deliverable

A write-up: which values collide under which configuration, root causes, mitigation trade-offs, and a recommended clone-safety procedure for urljail's [guest-image.md checklist](../guest-image.md#clone-safety-checklist-each-restore).
