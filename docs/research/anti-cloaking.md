# Research track R1: measuring phishing cloaking

Status: **first results 2026-10-13**: [r1-results.md](./r1-results.md). Runs in Phase 6, after the live gate.

## Question

How often do phishing pages show the scanner something different from what a human would see, and **which scanner signals trigger it**? How much does each countermeasure actually buy?

## Important correction to the original pitch

The original idea listed CPUID hypervisor bits and DMI strings as evasion signals. Those matter for **native malware**. A phishing page is **JavaScript in a browser sandbox**: it cannot read CPUID or DMI. What phishing kits can actually see:

| Layer | Signals | Observable by |
| ----- | ------- | ------------- |
| Browser API | `navigator.webdriver`, headless traces, UA/UA-CH consistency, plugins, languages, screen/window sizes, timezone vs IP geo | page JS |
| Rendering | WebGL vendor/renderer (Firecracker has **no GPU** → SwiftShader), canvas/audio fingerprints, fonts | page JS |
| Behavior | no mouse movement, instant interaction, time on page, focus/visibility events, referrer | page JS |
| Network | IP reputation / ASN (datacenter, VPN, Tor), geo | server |
| TLS/HTTP | JA4 TLS fingerprint, HTTP/2 SETTINGS & frame order | server (or CDN like Cloudflare) |
| Timing | visit seconds after the link was created/sent | server |
| Interactive gates | CAPTCHA / Turnstile / "click to continue" | page |

Guest-level hypervisor masking is therefore **low priority**; browser and network signals are where cloaking lives.

## Method (draft)

**Conditions** = snapshot profiles × egress exits. Factors (each switchable):

| Factor | Levels |
| ------ | ------ |
| Headless | `--headless=new` vs headful (virtual display) |
| WebGL | SwiftShader as-is vs renderer string spoofed vs disabled |
| Automation traces | default vs `webdriver` hidden vs CDP-detectable artifacts minimized |
| Interaction | none vs scripted human-like mouse/scroll/dwell |
| Locale coherence | default vs timezone/language matched to exit geo |
| Exit | VPN exit A vs VPN exit B (vs mobile hotspot, if available) |

**Design:** for each fresh URL, detonate under several conditions nearly simultaneously (URLs die fast, and kits rotate). Compare outcomes.

**Outcome labels per (URL, condition):** phishing content shown / benign decoy / error-blank / redirect-away (e.g. to google.com) / gate (CAPTCHA).

**Detecting "different content":** DOM structural diff + screenshot perceptual hash + presence of credential forms + final URL/eTLD+1. Validate the automatic labeling on a hand-labeled sample.

**Metric:** cloaking rate = share of URLs where at least one condition got phishing content and another didn't; per-factor effect via ablation (turn one countermeasure off at a time).

## As built: profiles (P6 M2, [ADR 0018](../decisions/0018-profiles-as-snapshots.md))

What a page saw from the baseline browser, measured live on a public bot-detection page (bot.sannysoft.com, 2026-10-12):

| Signal | Baseline | Countermeasure |
| ------ | -------- | -------------- |
| User-Agent | `HeadlessChrome/155.0.0.0` | `--user-agent` with the desktop string (`Chrome/155.0.0.0`) |
| `navigator.webdriver` | `true` | `--disable-blink-features=AutomationControlled` |
| Time zone | UTC, while the exit IP is in Chicago | `TZ` set to the exit's zone (`-exit-timezone`) |
| WebGL renderer | SwiftShader | none (no GPU in Firecracker): constant across profiles |
| Exit network | datacenter ASN (Datacamp, Proton free) | none with one free exit |
| Plugins, languages, `window.chrome`, permissions, window size | passed | — |

Profiles: `baseline`, `stealth` (UA + webdriver + time zone), `stealth-headful` (stealth with a virtual display, Xvfb, instead of headless mode; added after M4 showed Cloudflare challenges independent of the first three countermeasures), and ablations `stealth-no-ua`, `stealth-no-webdriver`, `stealth-no-tz`. `urljail feeds run` opens each URL under every profile at once.

## Data sources

- Terms and freshness of each feed: [feeds.md](./feeds.md). In short: OpenPhish Community is 12 h stale, URLhaus is malware, PhishTank registration is closed; fresh phishing needs OpenPhish Academic or paid, or own discovery from CT logs.
- Exit type (VPN/datacenter ASN) is itself a cloaking signal; record exit server, IP and ASN per run ([ADR 0010](../decisions/0010-mullvad-live-egress.md)).
- Freshness is the dominant variable: record time-since-first-seen for every detonation.

## Ethics & safety

- Never submit real credentials. If form submission is ever tested, generated canary values only, and only after deciding it's acceptable.
- Rate-limit per domain; don't hammer infrastructure that may be compromised legitimate sites.
- Live gate in [roadmap.md](../roadmap.md) must be passed first.

## Related work to read before starting

- **CrawlPhish**: large-scale analysis of client-side cloaking in phishing (IEEE S&P 2021).
- **PhishPrint**: evaluating security crawlers against cloaking by prior profiling (USENIX Security 2021).
- **SPARTACUS**: disguising user traffic as security crawlers to *trigger* cloaking defensively.
- **PhishDecloaker**: CAPTCHA-cloaked phishing detection with vision models (USENIX Security 2024).
- urlscan.io, Lookyloo (CIRCL): existing URL capture services/tools to compare against.

The novelty urljail can offer: **controlled, reproducible ablation on a microVM platform**, with independent host-side network evidence, plus the Firecracker-specific "no GPU" signal measured against a real-hardware baseline.
