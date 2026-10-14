# P7: control plane

Status: **closed** 2026-10-14 (started 2026-10-13)

## M1: retention

Before: 1,410 run directories, 3.9 GB, of which packet captures 3.1 GB (1,379 files); snapshots 13 GB (six profiles, all in use).

- `urljail gc [-pcap-days 7] [-pcap-cap 10G] [-dry-run] [-v]` (`internal/retention`), unprivileged: deletes `host/capture.pcap` and `guest/sslkeys.log` (the keys only decrypt that capture, and are the sensitive part) of runs older than N days, then oldest first while the total is above the cap. Runs younger than 15 min are left alone (they may be running). Each pruned run gets `host/retention.json` and its report is rebuilt: `artifacts.pcap` is empty and a gap says "Packet capture and TLS key log deleted by retention on <date> (<reason>)". Reports, metadata and the other artifacts are kept.
- First pass on the real data: nothing to delete under the default policy (everything is under a week old, 3.0 GiB < 10 GiB); with a 1 GiB cap it would delete the 905 oldest.
- Automatic: `deploy/urljail-gc.{service,timer}`, a systemd **user** timer (daily, as the operator, `NoNewPrivileges`, idle I/O), installed without root by `scripts/install-user.sh` (also puts the CLI in `~/.local/bin`). Lingering is on, so it runs while logged out.
- **Found:** two run directories were still root's: the run interrupted by the crash test and an older one. The daemon hands a run directory over only at the end of the run, so a crash leaves it root-owned, with no status and no report, and retention can't touch it. The daemon now recovers such runs at startup: status `interrupted`, handed to the operator, report built by the unprivileged helper.

## M2: orchestrator and dashboard ([ADR 0019](../decisions/0019-control-plane-deployment.md))

- **Infrastructure, no root:** Postgres 17 and Redis 7.4 in rootless podman as Quadlet user units, images pinned by digest at setup; the NestJS API (12.1) and the Next.js dashboard (16.4, React 19) as systemd user services. `control-plane/scripts/setup.sh` creates the podman secrets and `~/.config/urljail/control-plane.env` (0600). Listeners: 127.0.0.1 only (55432, 56379, 7801, 7800).
- **API:** gRPC to `urljaild` over its Unix socket, with the `.proto` loaded from `api/proto` at runtime (one source for the contract); one Postgres row per submission (state from the daemon's stream, then the report as JSONB and a summary); BullMQ queue `detonations`, never retried, worker concurrency taken from the daemon's VM slots (3). Routes: status, submit, list, get, screenshot.
- **Checked:** no or wrong token → 401; a `Host` other than localhost → 421 on both API and dashboard; `javascript:` URLs rejected (400). End to end: a URL submitted through the API ran under `stealth`, its report (`urljail.report/v0`) stored, the screenshot served as a verified PNG. **The P7 exit:** a URL submitted through the dashboard's form (as a browser posts it) → `303` to its run page → detonated → report rendered with redirect chain, network graph and screenshot (www.bbc.com: `bbc.com`, `bbci.co.uk` ×71, `optimizely.com`, `tinypass.com`). The same post from a foreign `Origin` was refused by Next ("Invalid Server Actions request") and created no run.
- **Found while building:**
  - BullMQ 6 no longer brings its Redis client: `ioredis` had to be installed explicitly.
  - TypeScript 7 dropped `moduleResolution: node10`; the API compiles with `nodenext` to CommonJS.
  - The run page first showed no final URL, observation time or redirect chain: `report.json` uses the proto field names (`final_url`, `redirect_chain`, written with `UseProtoNames`), the page read camelCase. Fixed to read the proto names; requests per domain are counted from the request list (a `Domain` carries hosts, not counts). Seen in a headless screenshot of the page, not in tests.
  - The repo's `runs/` ignore rule also matched the dashboard's `app/runs/` pages; excepted.
- **Every run in the dashboard:** the API indexes run directories it doesn't know at start and every minute (`source = cli`: CLI and `urljail feeds` runs; self-tests and unfinished runs skipped; files size-capped, only UUIDv7 names read). First pass: 1,355 runs. The list shows where each run came from.
- **Open item (guest coverage):** www.bbc.com's report was "not consistent" over one DNS lookup, `logx.optimizely.com`, that appears nowhere in the guest's CDP events or DOM. The guest agent enables the Network domain on the page's own session only, so requests from web workers (and, likely, out-of-process iframes) are invisible to it while the host still sees them. Built: the page session auto-attaches (paused, flattened) to workers and out-of-process iframes; each gets the Network domain and auto-attach for its own children, then is released (always, even if setup failed, so a page can't be left frozen). Only Network, never `Runtime.enable`. **Verified** after the daemon restart (2026-10-14): www.bbc.com is now consistent; `logx.optimizely.com/v1/events` is posted from the out-of-process iframe `a4621041136.cdn.optimizely.com/client_storage/`, which the agent now sees. The same restart recovered the two crash-left runs (`recovered interrupted runs count=2`: status `interrupted`, operator-owned, reports built).

## M3: reconciliation coverage

The fix above raised the question of how often the guest's account of a run misses traffic the host saw. Across all 1,327 reports with host records: **94 not consistent (7 %)**. Rebuilding them with the current report code cleared 5 (older reports). The rest, by cause:

| Cause | Runs | Fix |
| ----- | ---- | --- |
| Requests from out-of-process iframes and workers (Google Maps embeds, Stripe, Plaid, Google Analytics, Decibel, Olark, Optimizely) | most of the 42 left | The auto-attach above. Re-running 10 of these URLs with their original profiles: 5 became consistent at once (the rest are the causes below). |
| WebSockets (`ws-us2.pusher.com`, 16 runs) | 16 | The guest already logged them (`Network.webSocketCreated`); the report builder only read `requestWillBeSent`. Now a request of type `WebSocket` with its handshake status. |
| Preconnects named in a **response header** (`fonts.gstatic.com`, 26 runs, mostly headful) | 26 | Google Fonts stylesheets send `Link: <https://fonts.gstatic.com>; rel=preconnect`. The report read hints from the DOM only; `Link` headers now count too (capped at 64 hosts per run, header values capped at 16 KiB). |
| WebRTC: STUN lookups and connections, mDNS and IGMP multicast | 10 | **Left flagged.** CDP has no record of WebRTC; the host sees it and the guest can't explain it. That is the reconciliation doing its job (a page probing for the real IP is worth seeing), not a gap to label away. |
| `accounts.meta.com` on instagram.co look-alikes: a real TLS connection the page never requested and no child target opened | 8 | **Left flagged.** Likely browser-initiated (FedCM or similar); proving it needs the capture decrypted, and tshark isn't installed. |
| A HubSpot DNS lookup with no connection | 2 | Left flagged. |

After the report fixes, without re-running anything: **42 of 1,344 not consistent (3 %)**, of which most are iframe runs from before auto-attach.

- **Found in the control plane:** a rebuilt `report.json` (`urljail report`, retention) never reached the dashboard: the importer skipped runs it already had. It now records the mtime of the `report.json` each stored report was read from and refreshes finished runs whose file is newer (never a run the worker is still handling). First pass after the change: 1,347 refreshed.


## Exit

Met: a URL submitted through the dashboard's form is detonated and its report rendered (redirect chain, network graph, screenshot); the control plane, its database and queue run as the operator, so `urljaild` stays the only privileged component. The installed daemon builds reports with the code from before M3's two report fixes (WebSockets, `Link` headers) until its next reinstall; the CLI and `urljail report` already use them.

## Side quest: look-alike pages and brand signals (2026-10-14)

### S1: screenshot hash

`page.screenshot_phash` (`internal/visual`): a 64-bit DCT perceptual hash (32×32 grey, 8×8 low frequencies, bit = above the median of the AC terms). Decoding refuses PNGs over 4096×4096 before reading pixels; 2.1 M fuzz executions without a crash. ~50 ms per 1920×1080 screenshot, most of it PNG decoding. Screenshots with almost no contrast (luminance σ < 2) are `screenshot_blank` with no hash: 118 of 1,321 (9 %).

**How close is "the same page"? Measured, not guessed.** Pairs that should match: same final URL and title (2,374 pairs). Pairs that shouldn't: different registrable domain and different, non-generic titles (215k pairs). First pass on every screenshot gave 1.2 % false matches even at distance 3, all from Chrome's own error page, which looks the same everywhere and takes the domain as its title. Restricted to pages that loaded (no navigation error, last status < 400; 761 pages):

| Distance ≤ | Same-page pairs found | Different-page pairs matched |
| ---------- | --------------------- | ---------------------------- |
| 3 | 44 % | 0 |
| 6 | 61 % | 0 |
| 8 | 75 % | 30 (0.014 %) |
| 12 | 86 % | 276 |

The 30 at distance 8 all go through one nginx welcome page (a few lines of text on white), 8 bits from both a "coming soon" page and BBVA's real login. **6 is the default** (`visual.DefaultMaxDistance`). A 256-bit variant (64×64, 16×16) separated no better per unit of recall and was dropped. Same-page recall is limited by what changes between visits: cookie banners, rotating hero images, headful vs headless rendering.

### S2: `urljail similar`

`urljail similar <run>` lists runs whose screenshots are within the distance; `urljail similar -groups` groups all loaded pages and lists groups that span several domains. Groups are formed against each group's first member, not by chaining (single linkage first put BBVA's login, an nginx page and "A-C-S" into one cluster through the nginx page). On the corpus, 9 groups span more than one domain:

- **A family of look-alike domains found by look alone:** `{clear,prime,sure}facilityservicesteam.com` share one template ("Corporate Cleaning Group"), `{pro,try,top}facilityservicesteam.com` another ("Moore's General Services"). The CT discovery found them separately.
- Shared software, not kits: Meta's Signals Gateway on `tracking.clawdispatch.com` and `tracking.mayhemfights.com`, Authelia on two self-hosted domains, `example.{com,org,net}`. A look-alike group is a lead, not a verdict.
- Roblox "script" pages on two `pages.dev` projects.

### S3: forms, brands and indicators

- **`page.forms` and `page.password_fields`** from the final DOM (top document only; at most 32 forms of 64 fields; actions resolved against `<base>` and the final URL; `cross_origin_action` when a form posts to another registrable domain). On the corpus: 127 runs with a password field, on 19 hosts, nearly all real sign-in pages (Google, Instagram, AWS, BBVA, self-hosted Authelia and authentik); none posted to another domain.
- **`internal/brands`**: 31 brands with the words that name them (ordinary words like "wise", "kraken", "orange" left out: "Snappy Kraken" and "J-WiSe" would match), the domains that are theirs, and their sign-in URL.
- **`indicators`** in the report, each a fact with its reason, none a verdict:
  - `password-form-cross-origin` (medium).
  - `brand-name-off-domain`: a brand named in the title or h1/h2, on a domain belonging to none of the brands named. **High** with a password field; **medium** with only sign-in wording. "None of the brands named" matters: "Amazon Web Services Sign-In" names Amazon and AWS, and the real AWS sign-in on `amazonaws-us-gov.com` is neither's impersonation.
  - `brand-look-off-domain`: the screenshot within 6 bits of a brand's reference screenshot, off its domains.
- **Reference screenshots** (`urljail brands refs`, `internal/brands/refs.json`): each brand's sign-in page under `stealth` and `baseline`. The first take produced 53, and two false visual matches showed what was wrong with them: **14 were not sign-in pages.** Cloudflare's "Performing security verification" (Coinbase, Revolut), PayPal's DataDome captcha wall, eBay's error page, Discord's "Network Error", Microsoft's "Trying to sign you in" transition, Roblox before it rendered, an Amex marketing page. A Cloudflare challenge looks the same on every site, so the Coinbase "reference" matched `tdaccounting.net`'s challenge at 2 bits. A reference now needs a sign-in field (a password, or a text/email/tel field in a form): 39 references of 23 brands remain, the closest two brands 14 bits apart. The same brand under the two profiles is often far apart (Google 32, Chase 32): the sites serve different pages to `HeadlessChrome` (Chase sends it to a privacy page), so both are kept.
- **On 40 fresh OpenPhish URLs** (`feeds run -n 40 -profiles stealth`): 5 flagged, all brand imitations.
  - `brand-name-off-domain`, high: a Facebook clone, an Instagram and a Netflix look-alike, a "Microsoft | Login" page, all on `vercel.app`. (`netflixgpt-react` may be a tutorial clone rather than a working kit; the indicator says what the page claims to be, not who made it.)
  - **Device-code phishing**, medium: "Log in to Docusign. Use the code below to sign in", with a sign-in code and a Microsoft-logo button, on `loginservice.cloud`. No password field at all: the victim types the code into the real Microsoft device login and hands over a session. The password-only rule missed it; sign-in wording without a password is now a medium indicator.
  - **Visual matching found none of them.** The Facebook clone copies Facebook's mobile layout and is 28–30 bits from the desktop references. A whole-page hash recognises a copy of the page it was taken from, not a brand. Useful against kits that clone the current page pixel for pixel; not seen here.
  - False positives on the 1,400 earlier runs: none for any indicator after the reference fix.
- **Found, guest agent:** 4 of the 40 runs lost their DOM (`DOM.getOuterHTML: Could not find node with given id`): the page replaced its document between `GetDocument` and `GetOuterHTML`. The read is retried once against the new document. Needs the new image.
- **Dashboard:** the run page shows indicators (severity, id, reason), forms (method, where they send, field names and types, "other domain" when cross-origin) and "Looks like" (runs within 6 bits, linking to their run pages); the list marks flagged runs with the brand. Summaries are versioned and recomputed from the stored reports when the summary format changes.
- **Verified on the reinstalled daemon** (`dev-c2d19782`): the daemon's own report for the Facebook clone, re-run, carries `brand-name-off-domain` (high) and the screenshot hash. The DocuSign device-code kit was taken down within the hour (now `404 page not found`, blank screenshot, no indicator). Two of the four pages that had lost their DOM were re-run on the new image and kept it (6.9 KB and 66 KB); the race doesn't reproduce on demand, so that shows the read works, not that the retry fired.
- **Mistake on the way:** the first reinstall installed a `bin/urljaild` built mid-way through S3 (version `ca371ac-dirty`), because later builds went to a scratch path; `scripts/install-daemon.sh` copies whatever `bin/` holds. Caught by checking the version the daemon logs at start; one more reinstall.
