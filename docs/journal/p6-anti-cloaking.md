# P6: anti-cloaking research

Status: **in progress** (started 2026-10-12)

## M1: feed ingestion

`urljail feeds` ([feed-ingestion.md](../feed-ingestion.md)), unprivileged, OpenPhish Community only (URLhaus needs an Auth-Key).

- First fetch: 300 URLs, 0 skipped by the strict parser; a second fetch inside the hour was not sent (minimum interval).
- `feeds run` refuses unless the daemon reports `live`, takes at most one URL per registrable domain per batch, and records `run.feed` (name, first seen) in the report.

### First live batch (3 URLs, 2026-10-12)

All three ran in disposable VMs through Proton (`US-FREE#61`); none reached a phishing page:

| URL host (path omitted) | Outcome |
| ----------------------- | ------- |
| `*.sabahi.tech` | `NXDOMAIN` from upstream: taken down |
| `*.pages.dev` | `NXDOMAIN`: Cloudflare Pages project removed |
| `*.pages.dev` | 403, Cloudflare "Suspected Phishing" interstitial |

Expected for this feed: OpenPhish Community lists URLs hours after detection, and urljail's "first seen" is its own fetch time, not publication. Cloaking measurements will need fresher URLs (design doc: OpenPhish Academic, or own discovery).

**Reconciliation findings** (all three reports were "NOT consistent" at first; nothing escaped):

1. **Chrome's DNS probe.** When navigation fails with `ERR_NAME_NOT_RESOLVED`, the error page checks whether DNS works: `google.com` through the system resolver and once straight to `8.8.8.8:53`. The VM namespace redirects any port-53 packet to urljail's resolver, so the query was answered by it and logged. Now labeled `browser-background`, **only** when the navigation failed on DNS; a query to `8.8.8.8` on any other run stays unexplained.
2. **Network Error Logging.** Cloudflare's `Report-To`/`NEL` headers make Chrome post reports to `a.nel.cloudflare.com` without a request the Network domain shows. The report builder now reads `Report-To` and `Reporting-Endpoints` from response headers (https endpoints only, capped, fuzzed) and labels that traffic `page-report`.

After the fix, all three reports are consistent.

## M2: browser profiles as conditions

- Baseline measured live on bot.sannysoft.com: `HeadlessChrome` in the User-Agent, `navigator.webdriver` true, SwiftShader WebGL; everything else passed. The exit (Proton `US-FREE#61`, `149.88.25.131`) is in Chicago on a datacenter ASN, while the guest's clock zone is UTC.
- Built: `BrowserProfile` in the guest API (launch flags and `TZ` only, values validated in the agent so nothing can smuggle a flag), one snapshot per profile ([ADR 0018](../decisions/0018-profiles-as-snapshots.md)), `Detonate` refuses unknown profiles, `Version` lists them, `urljail feeds run` runs every profile at once and prints one line per profile (final host, title or error, password field, host≠guest).
- **Verified live** (bot.sannysoft.com and browserleaks.com, all five profiles): User-Agent `HeadlessChrome` only in `baseline` and `stealth-no-ua`; `navigator.webdriver` only in `baseline` and `stealth-no-webdriver`; `timeZone` `America/Chicago` in the profiles with the countermeasure, `UTC` in the others; Client Hints brands are `Google Chrome` in every profile, headless included; WebGL SwiftShader everywhere, as expected.
- **Found:** the stealth profiles set `en-US` as the only language, so `navigator.languages` was `["en-US"]` instead of Chrome's usual `["en-US","en"]`: the countermeasure made stealth stand out. Fixed: no language override (the default fits a US exit), and a set language now produces `xx-YY,xx`.
- Launching five detonations at once against three VM slots: the daemon refused the extra two (`all 3 VM slots are busy`), as designed; `feeds run` limits itself to the daemon's slot count.

### First batch under all five profiles (2026-10-13, 3 URLs × 5 profiles, each URL's profiles at once)

| URL host (path omitted) | All five profiles |
| ----------------------- | ----------------- |
| `*.cupricclumbers.com` | run timed out in collection: no screenshot, no DOM |
| `*.pages.dev` | `NXDOMAIN`: taken down |
| `*.adqwi.com` (Australia Post lure) | "Verify you are human" gate, same for every profile |

No profile changed what a page showed. The gate is itself a cloaking technique (content behind interaction); getting past it needs interaction, which no profile simulates.

**Found: collection without its own limit.** On `*.cupricclumbers.com`, observation ran its full 12 s, then `Page.captureScreenshot` never answered (the page kept its renderer busy; 26 image requests blocked by ORB, no dialog), the run hit its 30 s deadline and every guest artifact was lost. Fixed in the agent: final URL and title first (answered by the browser process), then DOM and screenshot with 5 s each, and the guest's error is now a stated gap in the report (guest-attested, bounded).

Rerun of `*.cupricclumbers.com` under all five profiles with the fix: final URL, title and DOM kept, the screenshot timed out in every profile and the report says so. Every profile got the same page: a Chinese gambling-site title and no body, only a script from another host on port 6987, typical of hijacked-domain spam kits that pick content by referrer (search-engine visitors) or mobile User-Agent, neither of which any profile varies yet. Chrome looked up that host's HTTPS record as `_6987._https.<host>` (RFC 9460 port prefix), which reconciliation now maps to the host. Known limit: a run whose screenshot times out ends with status `error` although everything else was collected.

After a fourth batch (3 more URLs, all `NXDOMAIN` in every profile): 9 OpenPhish URLs, 6 dead, 1 Cloudflare takedown, 1 human-verification gate, 1 bodyless spam page, **none showed phishing content in any profile**. The feed's age (about 7 h here) is the limit, not the profiles.

## M3: own discovery from CT logs

Decision (2026-10-13): find candidates in Certificate Transparency instead of waiting for feeds ([feed-ingestion.md#ct-discovery-own-source-p6](../feed-ingestion.md#ct-discovery-own-source-p6)).

- Parser checked against a real Let's Encrypt tile (256 entries, 6 s of the log, 78 precertificates).
- First scoring pass, 3 min live: 8 candidates, all false positives (Microsoft's internal `microsoft-int.com`, machine-generated hostnames). Tuned: brand position, hyphens counted in the registered name only, generated labels penalized, those domains excluded. 10 min live afterwards: 0 candidates in 41,539 names.
- Dumped 7,540 names (4 min) to check: genuine brand impersonation is rare. The one plausible candidate, `accounts.tdaccounts.online`, needed a general rule (short brand glued to an action word: `td`+`accounts`), not a memorized name.

### First hour of `feeds watch` (2026-10-13, 02:55–03:55)

114 candidates queued, 35 detonated under all five profiles, about 5 min after each certificate.

- **Differential treatment caught, on a non-phishing site.** `mirror.tools.amazon.dev` (an Amazon-internal tool): `baseline` and `stealth-no-ua`, the two profiles still sending `HeadlessChrome`, got `403 Forbidden`; the three with the desktop User-Agent were redirected to Amazon's login (`midway-auth.amazon.com`). The ablation pinned it on the User-Agent alone: the comparison P6 is built for works.
- **Fresh phishing reached.** `facebookabc.cc` was already behind Cloudflare's "Suspected Phishing" interstitial 5 min after its certificate. Two Cloudflare-fronted names answered 521/525 (origin not up yet) at 5 min.
- **AWS GovCloud sign-in** showed a password field in some profiles and not others across two runs (`baseline` never did). With only two runs this is as likely page timing as treatment; noted, not concluded.
- **Most candidates were false positives:** Amazon's own infrastructure in other TLDs (`amazon.dev`, `amazonwebservices.cn`/`.eu`, `amazonaws-us-gov.com`), `americanexpress.com` itself, Stripe's card-reader domain, and brands inside ordinary words (`icloud` in "forticloud", `sagawa` in "bitsagawallet", `lineme` in "onlinemedical"). Fixed: brands match on word boundaries (whole word, or glued to an action word or at most three characters, and short brands only to action words); a registered name that is exactly a brand, in any TLD, is the company; known infrastructure names are excluded in every TLD. Re-scored offline, the hour's 114 candidates drop to 7, all plausible.
- **Navigation without an answer.** One server accepted the connection and never answered: `Page.navigate` held the run until its deadline and every artifact was lost. Fixed in the agent: navigation waits at most 12 s, then the run records "navigation timed out (no response)", stops loading and still collects.
- **Retry:** when every profile found a site not up (DNS failure, no answer, refused, Cloudflare 52x), the URL is queued once more for 30 min later; the first round's runs are kept as `<profile>#1`.

## M4: comparison with a noise control (2026-10-13)

`urljail feeds compare` labels each run (dead, no-response, origin-down, blocked, gate, login, error-page, redirect-away, content), compares a URL's profiles, and names the countermeasure when exactly one splits the outcomes. Every URL also runs a second time under `baseline` (`baseline~control`): two identical runs disagreeing is the noise a profile difference has to beat.

### 2.5 h of `feeds watch` with the control (04:2x–06:5x)

62 candidates queued, 59 detonated with a control, **55 reached a page in at least one profile (93%**, against about a third for OpenPhish).

| Outcome (baseline) | URLs |
| ------------------ | ---- |
| content | 20 |
| error page | 15 |
| gate (Cloudflare challenge and similar) | 9 |
| login | 7 |
| redirect away | 2 |
| dead, no response, origin down | 5 |
| blocked (Cloudflare "Suspected Phishing") | 1 |

- **Noise:** the control disagreed with its twin on 2 of 55 (4%): a rotating redirect (`5kraken.cc` to `sion6.at` or `sion10.to` on each visit) and a site flipping between page and error.
- **Profiles differed on 7 of 55.** Two were noise (the control disagreed too), four were a single profile out of line with no pattern (a run without an answer, a login field rendering late), consistent with the noise rate.
- **One clean single-factor split:** `www.tdaccounting.net`. Cloudflare's "Just a moment..." Turnstile challenge for both `HeadlessChrome` profiles and the control (the same 28,864-byte page each time); the page itself for the three desktop-UA profiles. Attributed to the User-Agent, with the control agreeing. The site is most likely an ordinary business (a false positive of the `td`+"account" rule), so this measures Cloudflare's bot management, not a phishing kit; but many kits sit behind Cloudflare.
- **Profiles barely matter overall.** Per profile, label counts are nearly identical: 9 gates for the `HeadlessChrome` profiles against 8 for the desktop-UA ones, the difference being that one site. So 8 of 9 gates challenged every profile: what triggers them is something no profile varies, most likely the datacenter exit IP (Proton free) or browser signals beyond the three countermeasures (WebGL SwiftShader, headless rendering).
- **Precision of CT scoring for phishing is low.** The seven logins were self-hosted auth portals (authentik, Authelia), affiliate trackers and a company portal. The one clear phishing site, `f-p-w-whatsapp.com.cn`, was already behind Cloudflare's phishing interstitial.

**Where this leaves R1:** across 103 fresh URLs with five profiles each (both watch runs), two differences were explained by one countermeasure, both the User-Agent, neither on a phishing site. No phishing kit was seen cloaking on User-Agent, `navigator.webdriver` or time zone. The barriers seen are infrastructure-level: Cloudflare challenges (independent of the three countermeasures) and Cloudflare's own phishing takedowns within minutes.

## M5: headful profile

Decision (2026-10-13): test headless mode itself, the largest browser-side signal left, to find out whether the Cloudflare challenges that hit every profile come from headless Chrome or from the exit.

- `BrowserProfile.headful`: the agent starts Xvfb (`:99`, 1920×1080×24, no TCP) and launches Chrome without `--headless`, on X11; both are in the snapshot. Software rendering as before (no GPU). Guest init creates `/tmp/.X11-unix` (root, sticky).
- Profile `stealth-headful`: stealth's webdriver and time-zone countermeasures, headful, no User-Agent override (a headful browser's UA is already the desktop one).
- **Attribution tightened:** a countermeasure explains a split only with at least two runs on each side, all agreeing; control runs count on their twin's side. `stealth-headful` is alone on its side, so `watch` now runs controls for `baseline` and `stealth-headful` by default (8 runs per URL). The two User-Agent attributions from M4 still hold under the stricter rule.

