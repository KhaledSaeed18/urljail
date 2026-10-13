# R1 results: do phishing pages cloak against a browser scanner?

Status: **results, 2026-10-13** (P6). Method and design: [anti-cloaking.md](./anti-cloaking.md); day-by-day record, including every correction: [P6 journal](../journal/p6-anti-cloaking.md).

## Answer

On 172 fresh URLs, each opened under five or six browser profiles at the same moment:

1. **The only signal that ever changed what a site showed was the User-Agent** (`HeadlessChrome/…` vs the desktop string): 5 URLs. Every one was infrastructure reacting to headless Chrome: Cloudflare's bot challenge (3), Google's sign-in (1), an Amazon-internal tool (1).
2. **`navigator.webdriver`, the time zone and headless mode itself had no measurable effect.**
3. **No phishing kit was seen cloaking on any of the four signals.** The phishing that was reached was already behind Cloudflare's phishing interstitial within minutes of its certificate, already taken down, or behind a kit's own click gate, which no browser profile passes.
4. Profile differences that one countermeasure didn't explain (16 URLs) were at the noise level measured by repeat runs (3%): single runs without an answer, rotating redirects, late-rendering login fields.

For a scanner: don't announce `HeadlessChrome`, mainly to get past CDNs and identity providers. Beyond that, the barriers seen were interaction gates and takedown speed, not browser fingerprinting.

## Method

1. **Discovery.** Let's Encrypt's Certificate Transparency logs, read live (about 31 new names per second). Names are scored for phishing (brand in the registered name, lookalike spelling, account words, cheap TLD); brands' own domains and hosting platforms are excluded. The free OpenPhish feed was tried first and dropped: its URLs were about 7 h old and 6 of 9 were dead.
2. **Wait** 5 minutes after the certificate's log timestamp (the site needs time to go up); sites not up in any profile get one retry 30 minutes later.
3. **Detonate under every profile at once**, each in a fresh Firecracker microVM restored from that profile's snapshot, through one VPN exit (Proton VPN free, Chicago, a datacenter network).
4. **Controls.** The same URL again under `baseline` (and `stealth-headful` in the last run): how often two identical runs disagree is the noise.
5. **Label** each run from its report and captured page: dead, no response, origin down, blocked, gate, login, error page, redirect away, content.
6. **Compare and attribute.** A countermeasure explains a difference only if the outcomes split exactly along it, with at least two agreeing runs on each side (controls count on their twin's side).

| Profile | User-Agent | `navigator.webdriver` | Time zone | Mode |
| ------- | ---------- | --------------------- | --------- | ---- |
| `baseline` | `HeadlessChrome` | `true` | UTC | headless |
| `stealth` | desktop | hidden | exit's (America/Chicago) | headless |
| `stealth-no-ua` | `HeadlessChrome` | hidden | exit's | headless |
| `stealth-no-webdriver` | desktop | `true` | exit's | headless |
| `stealth-no-tz` | desktop | hidden | UTC | headless |
| `stealth-headful` | desktop | hidden | exit's | headful (Xvfb) |

Constant in every profile: Chrome 155, software WebGL (SwiftShader; no GPU in a microVM), `en-US,en`, 1920×1080, the same exit IP.

## Numbers

| Run (2026-10-13) | Profiles | Controls | URLs | Reached a page |
| ---------------- | -------- | -------- | ---- | -------------- |
| OpenPhish batches | 5 | — | 9 | 3 |
| CT watch A, 02:55–03:54 | 5 | — | 35 | — |
| CT watch B, 04:09–06:37 | 5 | baseline | 59 | 55 |
| CT watch C, 10:13–13:04 | 6 | baseline, stealth-headful | 65 | 60 |

Across all runs: 172 URLs compared, 115 reached with a control, control disagreement 3 of 115 (3%), 21 URLs with any profile difference, **5 explained by one countermeasure, all the User-Agent**.

Watch C, per profile, over the 60 URLs that reached a page:

| Profile | content | login | gate | blocked | error page | redirect away | no response |
| ------- | ------- | ----- | ---- | ------- | ---------- | ------------- | ----------- |
| baseline | 28 | 7 | 4 | 3 | 13 | 4 | 1 |
| stealth | 29 | 7 | 3 | 3 | 12 | 5 | 1 |
| stealth-no-ua | 28 | 7 | 4 | 3 | 13 | 4 | 1 |
| stealth-no-webdriver | 31 | 6 | 2 | 3 | 13 | 5 | 0 |
| stealth-no-tz | 29 | 7 | 2 | 3 | 13 | 5 | 1 |
| stealth-headful | 29 | 7 | 3 | 3 | 12 | 5 | 1 |

### The five User-Agent splits

| Site | `HeadlessChrome` got | Desktop UA got | Who reacted |
| ---- | -------------------- | -------------- | ----------- |
| `mirror.tools.amazon.dev` | 403 Forbidden | redirect to Amazon's login | Amazon-internal tool |
| `www.tdaccounting.net` | "Just a moment..." challenge | the site | Cloudflare |
| `simone-zeller-mentalstark.de` | challenge | the site | Cloudflare |
| `blockchain-smart-contract.com` → `blockchain.com` | challenge | the site | Cloudflare |
| BBVA sign-in (`…backend-services.net`) | Google's own sign-in page | handed on to BBVA's identity provider | Google sign-in |

### Phishing reached

- `facebookabc.cc`, `f-p-w-whatsapp.com.cn`: Cloudflare's "Suspected Phishing" interstitial, in every profile, minutes after the certificate.
- `auspost.adqwi.com` (Australia Post lure, OpenPhish): a kit-made "Verify you are human" page imitating Cloudflare's, with no CAPTCHA provider; its inline code reads only `navigator.languages` and waits for a click, then POSTs a code to its own path. Same in every profile, including headful.

## Corrections made on the way

- The first gate label counted ordinary pages as gates (contact forms loading reCAPTCHA; Cloudflare's script injected into normal pages). Fixed; an earlier claim that most gates blocked every profile was withdrawn.
- Headful Chrome without a GPU first had no WebGL at all; fixed so headful and `stealth` differ only in headless mode.
- The stealth profiles first reported a single language (`en-US`), which made them stand out; fixed.
- CT scoring produced many false positives (brands' own infrastructure in other TLDs, brands inside ordinary words, "account**ing**" as ING); fixed and pinned by 29 test cases.

## Limits

- **One exit**, a datacenter network: exit type (residential, mobile) is untested and may matter more than any browser signal.
- **Few real phishing sites**: CT scoring finds fresh names but mostly ordinary businesses; the phishing reached was a handful of sites.
- One run per profile per URL, plus one or two controls; one Chrome version; one day.
- No interaction: click gates were seen and not passed.

## Reproduce

```bash
urljail feeds watch -for 3h          # CT discovery, all profiles, controls (live mode)
urljail feeds compare                # labels, differences, attribution, noise
urljail feeds compare -differs -json # the comparisons as data
```
