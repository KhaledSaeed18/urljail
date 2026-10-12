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
