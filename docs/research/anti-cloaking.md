# Research track R1: measuring phishing cloaking

Status: **idea / design**. Runs in Phase 6, after the live gate.

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

## Data sources

- OpenPhish (community feed), URLhaus (abuse.ch), PhishTank: check terms of use for each.
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
