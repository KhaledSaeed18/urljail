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

