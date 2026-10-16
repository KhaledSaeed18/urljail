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

### S4: detection run on live feeds (2026-10-14)

349 fresh OpenPhish URLs under `stealth`, eight rounds over 4 hours (`feeds run -n 40`, newest first); 103 loaded a page, 102 labelled by hand from screenshot and title ([labels and frozen-rule indicators](../research/data/p7-indicator-labels.tsv)). The first batch and rounds 1–4 were for tuning; the rules were frozen at `fa8a848` and rounds 5–8 labelled before any indicator was looked at, then scored once with that binary.

| Threshold | Tuning: flagged / FP | Held-out: flagged / FP |
| --- | --- | --- |
| High only | 8 of 36 / 0 of 20 | 10 of 34 / 0 of 12 |
| Medium and up | 17 / 1 | 11 / 1 |
| Any | 28 / 3 | 14 / 6 |

- **High severity is precise and narrow:** no false positive on either set, a third of the phishing. `brand-name-off-domain` carried it (11 held-out hits, 0 false positives).
- **Most of the tuning gain didn't transfer:** 78 % → 41 %. The tuning rounds added 21 brands after seeing them; the held-out rounds brought 5 more the list lacked (Banco Pichincha ×6 pages of one kit, Spectrum, KuCoin, OpenSea, La Banque Postale). 8 held-out misses name no brand at all: generic webmail kits, "verify you are human" gates, a scanned-document lure. Payment and details forms: 0 of 6.
- **The low indicator failed:** `brand-presented-off-domain` fired on 3 phishing pages and 6 harmless ones (tutorial clones on github.io, empty look-alike blogs, MetaMask's own docs on a consensys Vercel preview). Demoted to `info` after scoring (`097b668`), reported as a post-hoc change.
- **The screenshot match fired once** in the whole study (a Google clone, tuning set): kits copy mobile or older layouts.
- **Found on the way:** a kit that renders its page from a `blob:` URL (the final URL's domain came back empty and every brand rule was skipped; now read from the blob's origin, plus a `blob-document` indicator); kit headings built from `<div class=title>` (counted, but only next to a password, a details form or sign-in wording: alone they flagged Wikipedia's "Meta" link and a "Google Chrome" requirement on chase.com); Stripe's own `stripe-terminal-local-reader.net` pages, titled with their host, read as "presenting Stripe" (titles are now matched without the host).
- 15 phishing URLs led to the brand's real site (facebook.com, google.com); none was flagged.

### HAR export

Each report build also writes `har.json` (HAR 1.2) from the guest's CDP events, listed as `artifacts.har`; the run page has "Download HAR" (served as an attachment, never rendered). Requests are keyed by CDP session plus request ID (iframes and workers reuse IDs), redirects become one entry per hop, timings come from Chrome's ResourceTiming. Response bodies aren't captured, so content has sizes and types only (said in the HAR's comment). On the BBC run: 87 entries for 87 requests; 37 had no response event before collection (status 0, with a comment).

### S5: second held-out set (2026-10-14 afternoon)

The misses in S4 suggested one new rule, **`form-on-free-hosting`** (medium): a password field or a details form on a host anyone can publish to for free (replit.app, vercel.app, netlify.app, pages.dev, github.io, webflow.io, duckdns.org and ~40 others). On all S4 pages it would have flagged 27 phishing pages and nothing else, but it was written after seeing them, so it was frozen with the rest at `091ec7e` and tested on new pages. Two sets, labelled before any indicator was looked at (`set` column `heldout2-*` in [the labels](../research/data/p7-indicator-labels.tsv); `indicators_frozen` is `fa8a848` for the S4 rows, `091ec7e` for these):

- **OpenPhish, fresh** (64 pages: 30 phishing, 14 benign, 20 the brand's real site). OpenPhish's free list didn't change from 03:51 to 15:28, so this set is that one update (three passes of 40) plus one earlier page; `feeds run -max-age` was added so a loop only spends VMs on URLs first seen recently.
- **CT discovery** (`feeds watch -for 2h`, 13 pages that loaded, none phishing): a population of mostly ordinary new sites, which is where false positives show.

| | Phishing flagged (medium+) | Others flagged (medium+) | High: phishing / others |
| --- | --- | --- | --- |
| OpenPhish | 8 of 30 | 2 of 34 | 4 / 0 |
| CT discovery | – | 1 of 13 | – / 0 |

- `form-on-free-hosting` caught 7 of 30 phishing pages and two real apps ("Card Ledger" and "Clear Ledger", private apps with a login on pages.dev; OpenPhish listed both, probably for the word). Of the 22 phishing pages no medium-or-high indicator caught, 9 sat on hosting the list doesn't name (typedream.app ×2, Bluehost ×2, cleverapps.io ×2, b12sites.com, Azure Front Door, a cPanel host), 8 on listed hosts but asked for nothing yet (gates, wallet, Steam and "free Robux" lures), 5 on their own domains (two Indian "tax penalty" lures on cheap TLDs, a FinanzOnline look-alike, a Call of Duty login, a document lure). A list of hosting services has the same long tail as a list of brands.
- The CT false positive: `amazonex.app`, an ad tool's site, two letters from "amazon" (`brand-lookalike-domain`).
- Across every held-out page (123: 46 + 64 + 13), **high severity never fired on a page that wasn't phishing**; it caught 14 of 64 phishing pages. Medium and up: 19 of 64 phishing pages, 4 false positives (2 private apps on free hosting, a look-alike blog, an ad tool's look-alike domain).
- Six tutorial clones on github.io, netlify.app and vercel.app (Spotify, Netflix, Amazon, Instagram) got only the `info` indicator: the demotion in S4 holds.

### S6: favicons (2026-10-14 evening)

- **Capture:** the guest agent records each image Chrome loads on its own behalf (CDP type `Other`, status 200: the favicons) and, at collection, reads up to four bodies with `Network.getResponseBody`: from the browser's memory, so no extra request and nothing a page can see. They come back as `favicon-0..3` (256 KiB each, now on the daemon's artifact allow-list) with `favicons.json` naming each one's URL and type. The report lists them in `page.favicons` with their SHA-256. Checked on www.wikipedia.org: one icon, 2,734 bytes.
- **Indicator:** `brand-favicon-off-domain` (high): a page's favicon is byte for byte one a brand's own site served, off that brand's domains. Brand references now record the favicons of the brand's page; a page that isn't a sign-in page (a bot wall, a home page) is kept for its favicons alone, and brands without a sign-in URL use their home page.
- **Found on the way, daemon:** the reinstall rebuilt all six snapshots and the sixth (`stealth-headful`) timed out writing its 2 GiB memory file: the Firecracker client had one 10 s timeout for every call, and the disk was still busy with the five before it. The daemon exits on a failed build, so it looped (4 starts) until the disk was idle. Calls now get their own deadline (snapshot create 2 min, load 30 s, the rest 10 s); installed at the next reinstall.
- **Found on the way, egress:** the Proton VPN Free exit slowed through the day. Mean page throughput per run: **225 KB/s in the morning, 106 KB/s in the afternoon, 47 KB/s in the evening.** At 47 KB/s pages hit the 15 s dwell limit before their scripts arrive: the evening's reference pass got sign-in pages without their forms, no favicons and screenshot timeouts, and was discarded. References are taken at 04:00 instead. Anything measured in the evening (outcome labels, what loaded) is affected by this too.

### Labelling in the dashboard

The 179 labels of S4–S5 were a hand-written TSV; labelling is now part of the dashboard. A `labels` table (one row per run: verdict phish / benign / unsure / real-site, kind of phishing, brand, note), a label form on the run page ("Save and next unlabelled" walks the review queue), list views *All runs / Needs a label / Labelled* and a filter by indicator, and `/evaluate`: every labelled run scored at each severity and per indicator, by kind of phishing, with the false positives and the misses listed (URLs as text). `/labels.tsv` exports them with the indicators. The review queue opens runs blind (`?blind=1`): indicators and look-alike runs stay hidden until the run is labelled, as in the held-out sets. The 179 labels were imported through the API. The labels are a Server Action like submitting, so a post from another origin is refused (checked: 500, label unchanged). The evaluation page says what it is: all labelled runs, tuning pages included, so it overstates against the held-out numbers here.

### S7: kit families (2026-10-14 night)

The same kits came back all day on different hosts (one Banco Pichincha loan form on six replit/vercel hosts, one webmail login on four, a Naver clone on three, AR24, a Spotify clone, the Steam invitation). **`kit-match`** (medium) recognises them by structure: `internal/kits` fingerprints the final DOM as a 128-value MinHash of element paths (each element with its parent and grandparent; tag names, plus type and name of form fields; scripts, styles and text ignored), and a page matches a person-labelled phishing page when the estimated Jaccard similarity is at least **0.7**. A match only counts **across places**: another registrable domain and not the same hosting platform (two pages on github.io or gitbook.io share the platform's template: on the first calibration a GitBook tech-support scam and a GitBook Trezor page matched at 0.67 for that reason alone), and **never on a brand's own domain** (kits copy the real page: accounts.google.com matched a Google clone at 84 %).

Calibration on S4–S5's labelled pages, leave-one-out, across places (131 of 179 big enough to fingerprint, at least 20 distinct paths):

| Threshold | Phishing pages matching another | Other pages matching a phishing page |
| --- | --- | --- |
| 0.5 | 20 of 66 | 3 of 61 |
| 0.6 | 17 of 66 | 0 of 61 |
| 0.7 | 17 of 66 | 0 of 61 |
| 0.8 | 15 of 66 | 0 of 61 |

References (`internal/kits/refs.json`, `urljail kits refs -labels <tsv>`): the 66 labelled phishing pages with a fingerprint. Over every stored run (2,600+, rebuilt), `kit-match` fired only on those kits' hosts, their comparison-profile runs, and one unlabelled OpenPhish run on `h5.usakkkk.shop` titled "TikTok-Wholesale": the fake-merchant kit from round 2 on a new host. Most matched pages had no other indicator (the Pichincha forms, the webmail kits, the Steam lure). In-sample, so this says the rule finds today's families; whether kits come back the next day on new hosts is what the next held-out set measures. Frozen with the favicon rule.

### S8: third held-out set (2026-10-15 morning): favicons and kit-match

References retaken at 04:00, when the VPN exit was fast: 73 (57 sign-in screenshots, 49 with favicons, 40 brands; no favicon shared between brands, the closest two brands' screenshots 14 bits apart). On the full corpus the brand screenshot match at 6 bits put Cloudflare Access's real sign-in page and a Facebook clone on DocuSign's plain "enter email" card, while the real clone hits were 0 and 2 bits: the brand match now needs **4 bits or fewer**. Frozen at `21d0924` (04:34). OpenPhish refreshed at 04:34 (299 URLs); the loop ran each fresh batch, then 15 minutes of CT watch, until the queue was spent (07:40). Labelled blind: **117 pages: 88 phishing, 17 benign, 5 the brand's real site, 7 unsure**.

| | Phishing flagged (of 88) | Others flagged (of 22) |
| --- | --- | --- |
| High | 24 (27 %) | 0 |
| Medium and up | 34 (39 %) | 0 |

| Indicator | Fired on phishing | Only indicator on | Others |
| --- | --- | --- | --- |
| brand-name-off-domain | 27 | 18 | 0 |
| form-on-free-hosting | 15 | 1 | 0 |
| kit-match | 6 | 0 | 0 |
| brand-look-off-domain | 1 | 1 | 0 |
| **brand-favicon-off-domain** | **0** | 0 | 0 |
| brand-presented-off-domain (info) | 25 | – | 8 |

- **Favicons: nothing.** 40 of the 88 phishing pages loaded a favicon; none was byte-identical to a brand's. The kits serve their host's own icon (or the platform's), and the most repeated kits this morning (a DocuSign password page on dynamic-DNS hosts, nine copies; a fake Google "account hacked" alert, seven) loaded none. Eight brands, Google, Microsoft's own sign-in and DocuSign among them, got no reference favicon either: Chrome often doesn't request one when the page names an SVG or an inline icon. As built, the favicon rule doesn't earn its place.
- **kit-match: right every time, never alone.** Six hits, all phishing: yesterday's Banco Pichincha loan form on four new replit/vercel hosts (the case it was built for), and two Framer pages (a Gmail and an Eastlink clone) matching yesterday's Framer Microsoft clone, which may be Framer's template as much as a kit (framer.app and framer.website are the same builder). Every one was also caught by `form-on-free-hosting`. It missed the eight "Access Restricted" gates (too little HTML to fingerprint) and kits first seen today.
- **What carries detection is still the brand named off its domain** (18 of its 27 hits had nothing else). By kind, at medium and up: credential pages 27 of 31, payment and details 4 of 6, lures 3 of 34, gates 0 of 16, device-code 0 of 1 (a OneDrive "enter this code at microsoft.com/devicelogin" page).
- No false positives at medium or up, on 22 non-phishing pages (tutorial clones, two companies' phishing-awareness training pages, an education site, a slot-review site).

- **CT discovery, 04:34 to 12:30 (not labelled one by one):** 109 pages loaded (21 more never did). At `21d0924` one was flagged at medium or up: `brand-lookalike-domain` on an S3 "Access Denied" error at `cdn.client-invoice.appwrd-dev.aws.pmicloud.biz` ("pmicloud" two letters from "icloud"): a page that shows and asks for nothing, most likely a false alarm. At the gate rules' `1623cdd`, the Russian `captcha-wave.sion10.to` page is added (see S9).

### S9: gates (2026-10-15)

28 of the labelled phishing pages (all sets) were gates: a page that asks for nothing and stands in front of the kit. None was flagged at medium or up. Four kinds:

| Gate | Pages | What it is |
| --- | --- | --- |
| "Access Restricted" | 10 | One kit on netlify.app: "this site blocks anonymous proxies, VPNs, and automated clients". Our exit is a VPN: this is the kit's cloak, served instead of the phishing page |
| "Verify you are human" | 6 | A Cloudflare Turnstile box drawn in the page's own HTML (logo, "Privacy · Help"), no Cloudflare loaded; typo-squats and parcel/rewards domains |
| Outlook "confirming it's you" | 5 | Outlook-branded, a real Turnstile widget, on a law firm's and .top domains |
| "Vérification CAPTCHA" etc. | 7 | An Orange-branded digit CAPTCHA drawn on a canvas, a Spotify reCAPTCHA "redirecting" page, a "Security Check" in front of a password page, a bare "Verification Required" |

All 28 are short: 3 to 43 visible words. 21 load no CAPTCHA service at all. Three rules, each on pages of 60 words or fewer:

- `fake-human-check` (medium): human-check wording ("verify you are human", "captcha" as a word, so not "protected by reCAPTCHA", "security check", "confirming it's you", in French, Spanish, Portuguese, German, Italian and Russian), and no CAPTCHA service contacted or embedded (Cloudflare challenges, hCaptcha, reCAPTCHA, Arkose, GeeTest, Friendly Captcha, MTCaptcha). Never on a brand's own domain.
- `brand-name-off-domain` gains a medium case: the brand named in the title or headings of a human-check page, off the brand's domain (the Outlook Turnstile kit, the Spotify reCAPTCHA page).
- `block-page-on-free-hosting` (medium): a short page turning away VPN or proxy visitors ("vpn", "proxy" with "restricted", "blocked", "denied", "forbidden") on free hosting. Off free hosting it stays silent: Amazon's internal sign-in portal says the same thing to our exit.

On the 296 labelled pages: gates caught **27 of 28** (was 0); the three rules fired on 21 phishing pages and **none of the 81 others**. The one left is a brandless "Verification Required" page with a real Turnstile: the same as a legitimate site behind one. Across all 4,450 captured pages (rebuilt): the rules fired only on OpenPhish URLs and on ten CT-discovered `captcha-<word>.sion10.to` / `sion6.at` pages ("Введите капчу", a Russian "enter the captcha / log in" page on random subdomains, one of which Cloudflare already shows as "Suspected Phishing"); never on a control run (Tranco top sites, sign-in pages of 40 brands, the real Netflix and Spotify sign-ins that mention reCAPTCHA, Revolut behind a real Cloudflare challenge).

**These are tuned on every labelled gate.** The 27 of 28 is in-sample; they need a fourth held-out set before they count.

### S10: fourth held-out set (2026-10-15 afternoon): the gate rules

Frozen at `1623cdd` (11:23). OpenPhish refreshed at about 15:20 (300 URLs); the loop ran each fresh batch, then 15 minutes of CT watch, until 20:00. From 15:36 a fuzzer (not urljail) took six of the eight cores: most of that batch failed with guest-agent deadlines, so the loop was stopped until it ended (16:37) and restarted to pause whenever it runs. 85 fresh URLs passed the 3-hour age limit in that hour and were never run. Of 308 runs, 56 pages loaded (36 OpenPhish, 20 CT); 84 others were Cloudflare's own "Suspected Phishing" / "Suspected Malware" interstitial (mostly CT `pages.dev` hosts Cloudflare had already caught), the rest errors and timeouts. Labelled blind: **56 pages: 26 phishing, 18 benign, 7 the brand's real site, 5 unsure**.

| | Phishing flagged (of 26) | Others flagged (of 25) |
| --- | --- | --- |
| High | 4 (15 %) | 0 |
| Medium and up | 17 (65 %) | 4 |

| Indicator | Fired on phishing | Only indicator on | Others |
| --- | --- | --- | --- |
| form-on-free-hosting | 7 | 1 | **4** |
| brand-name-off-domain | 6 | 3 | 0 |
| block-page-on-free-hosting | 4 | 4 | 0 |
| kit-match | 3 | 1 | 0 |
| fake-human-check | 1 | 1 | 0 |
| brand-lookalike-domain | 1 | 1 | 0 |
| password-form-cross-origin | 1 | 0 | 0 |
| brand-presented-off-domain (info) | 7 | – | 5 |

- **Gates: 4 of 4, no false alarm.** All four were the "Access Restricted" netlify kit, caught by `block-page-on-free-hosting` and by nothing else (one titled "Flybuys – Sign In": the kit's page behind its cloak). `fake-human-check` fired once, rightly, on a gov.br clone asking for the CPF with a drawn "Não sou um robô" box. The fake Cloudflare box and the Outlook "confirming it's you" kit didn't come back this afternoon, so those cases are still in-sample only. Neither rule fired on a host's own "please wait while your request is being verified" bot page (a German company site) or on any other non-phishing page.
- **kit-match alone, for the first time:** the Steam friend-invite lure from yesterday on a new netlify host (79 % alike), with nothing else flagging it. Its other two hits: a Framer Spectrum clone matching yesterday's Framer page (the template again), and a brandless webmail login on 4everland.app identical to a vercel one.
- **By kind, at medium and up:** credential pages 10 of 10, gates 4 of 4, lures 3 of 12 (two "Meta Verified" pages, the Steam lure). Missed: three copies of a Shopee prize-draw scam on blogspot, three Ledger "setup guide" pages (typedream, gitbook), two WhatsApp-styled contact pages and a DANA PayLater menu: pages that ask for nothing and name the brand only in the body.
- **The four false alarms are one cause:** `form-on-free-hosting` on two wordpress.com blogs (a Brazilian wine blog and a sports blog, each captured twice). Their WordPress comment form (comment, name, email, website) counts as a form asking for details. (Earlier sets had four at medium: two look-alike domains, two private apps with a login on pages.dev.) Fixed below (S11).

### S11: comment forms (2026-10-15)

A form whose only typed-in fields are a message box (`comment`, `message`, `feedback`, `enquiry` and the like) and what a comment needs (name, email, website, subject), with no password, no longer counts as asking for details: WordPress's comment form, and contact forms like it. A textarea under any other name (a recovery phrase), or a phone number or second email beside the message (the Meta "appeal" kit in the labels), still counts. The hidden textareas CAPTCHA widgets fill (`g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`) no longer count as fields at all; on the labelled pages they always sat beside a password field, so that changes nothing yet. Over all 5,385 stored runs, rebuilt before and after: exactly four reports change, the four wordpress.com false alarms of S10. On the 352 labelled pages, medium-and-up false alarms go from 9 to 5 (at the current rules) and no phishing page loses an indicator (126 flagged before and after). After the test, so not held-out.

### S12: lures (2026-10-15 evening)

Lures were the largest gap: 9 of the 77 labelled lures (all sets) flagged at medium or up. They ask for nothing and name the brand in the title or body, as do the 32 non-phishing pages with `brand-presented-off-domain` (22 tutorial clones of Netflix, Amazon, Spotify and Instagram home pages, empty "facebook" blogs, MetaMask's docs on a Vercel preview, an agency's DHL tool, a slot review, a novel titled "Binance"). Read side by side, none of those 32 says any of the following, and most lures say at least one. Six rules, all medium, never on a brand's own domain:

- `brand-domain-in-title`: the title or headings write a brand's own domain ("Official Site® | Ledger.com/Start®" on typedream.app). Matched as a whole host name after folding accents.
- `brand-name-disguised`: the title or a heading spells the brand with accents or look-alike letters ("Trézór Suite", "KÚCÔIN LÔGIN", "Ku𝐂oin"), checked per title and heading (one kit spells it plainly in a heading).
- `brand-alert-off-domain`: a brand in the title or headings and alarm wording on the page ("has been hacked", "account suspended", "community standards", "security alert"; six languages). One Google "your Android has been hacked" kit is 12 of its 18 hits.
- `brand-offer-off-domain`: a brand in the title or headings and prize or offer wording ("pemenang", "free robux", "credit limit offer", "oferta exclusiva").
- `brand-official-claim`: the title names a brand and calls itself official or carries ® / ™.
- Brands added: KuCoin, Zoom, Exodus, OpenSea, imToken, DANA.

On the 352 labelled pages (in-sample: written after reading these lures):

| Rules | Phishing flagged | Lures | False alarms (of 118) |
| --- | --- | --- | --- |
| Before | 126 of 214 | 9 of 77 | 5 |
| Domain, disguised, alert, offer | 155 | 38 | 5 |
| + the six brands | 160 | 43 | 5 |
| + official claim | 165 | 47 | 5 |

All 5,385 stored runs were rebuilt with each binary and diffed: every change is on a host already labelled phishing (the labelled run or its other-profile runs), except a CT "Roblox script" page where "you won" matched "you won't" (fixed before the last pass) and the Wells Fargo mortgage sandbox (labelled unsure), flagged for "preapproved": ordinary mortgage wording, the likeliest false alarm of the offer rule. The added brands give medium hits only for KuCoin and OpenSea; Zoom, Exodus and imToken get the info indicator, DANA nothing. Still missed: 30 lures, mostly straight copies of the real page (Zoom ×4, WhatsApp ×4, imToken, a Ledger download site), video-only "Meta Center" pages, document and tax lures for brands not on the list, and alerts that name the brand only in the body. The Google kit and the crypto "setup guide" pages (likely one SEO operation) carry much of the gain; the fifth held-out set measures it.

### S13: kit references from every labelled set (2026-10-15 evening)

The kit references held only the pages labelled on 13–14 October (66). Rebuilt from every labelled phishing page (`urljail kits refs -labels docs/research/data/p7-indicator-labels.tsv`): **137 references** (71 new, from the third and fourth sets; 77 phishing pages too small to fingerprint, the gates among them). Leave-one-out across places on the 352 labelled pages, at the 0.7 threshold: 49 of 137 phishing pages match another labelled phishing page (26 with the old references), none of the 102 benign or real-site pages (the same at 0.6 and 0.8; three at 0.5). The closest non-phishing page is the Wells Fargo mortgage sandbox (unsure) at 0.53; the closest benign one, an empty "facebook" blog, at 0.50.

Over all 5,385 stored runs, rebuilt with the old and new references: 69 runs gain `kit-match` and none lose it, all on hosts already labelled phishing: 23 labelled runs and 46 runs of the same hosts under the other profiles. None on a CT page, a control run or an unlabelled host. Of the 23, 18 are one DocuSign kit on dynamic-DNS hosts and 1 a Framer pair, all already flagged by other rules; the 4 new catches are the Zoom "Join Meeting" kit on `us0N-web-zoom.us` (identical to each other, nothing else flagged them; Zoom is now a brand, so `zoom.us` itself can't match). In-sample: 169 of 214 phishing pages and 51 of 77 lures flagged, false alarms unchanged at 5 of 118. These are same-day repeats within the third set; no fourth-set page matched a third-set one, so whether the new references catch kits on later days is for the fifth set.

### S14: favicon rule removed (2026-10-15 evening)

`brand-favicon-off-domain` fired on none of the 5,385 stored runs, and on none of set 3, where it was tested held-out. 51 of the 214 labelled phishing pages loaded a favicon; none is byte for byte a brand's, and none is served from a brand's domain: kits use their host's or platform's icon. Favicons do repeat within a kit (one icon on all nine dynamic-DNS hosts of the DocuSign kit, another on the four Zoom hosts), but kit-match already finds both. The indicator and its matcher are removed; the guest still captures favicons, reports keep their hashes, and brand references still record theirs, in case a kit-favicon rule is worth trying later. Rebuilt before and after: no report changes.

### Known false alarms, left as they are (2026-10-15)

Looked at before freezing; no fix kept every catch, so the rules stay:

- **`brand-lookalike-domain` on short brand names.** It fires on 25 hosts in the corpus. Names under 8 letters at edit distance 2 give the false alarms: `pmicloud.biz` (an S3 error page; "icloud" with two letters before it), `amazonex.app` (an ad tool), `taroblox.store` (a Vietnamese Roblox item shop); `img.dicloud.vip`, an image host, is one letter off. Requiring distance 1 for short names would drop the first three, and also `ledger--io.pages.dev` (which Cloudflare already shows as "Suspected Phishing") and three typo-squats that never loaded. Not done.
- **`form-on-free-hosting` on private apps.** "Card Ledger" and "Clear Ledger", private apps with a login on pages.dev, look like `ledger-staging-9yb.pages.dev`, labelled phishing: an ordinary title, an email and a password on pages.dev. Nothing on the page tells them apart.
- Also still flagged: the empty Turkish blog on `faceebook.blogspot.com` (look-alike) and one tuning-set page.

### Freeze for the fifth held-out set

Frozen with this commit: the lure rules (S12), kit references from every labelled set (S13), no favicon rule (S14). Two gate cases have still only been seen in-sample: the fake Cloudflare "verify you are human" box drawn in HTML and the Outlook "confirming it's you" Turnstile kit.

### S15: fifth held-out set (2026-10-16 night): the lure rules

Frozen at `ef81165` (2026-10-15 19:20 UTC). OpenPhish didn't change its list until 00:32 UTC (261 new URLs); the loop ran each batch, then 15 minutes of CT watch, until the queue was spent at 03:59 (41 URLs passed the 3-hour limit first). No fuzzer run this time. 397 runs (276 OpenPhish, 121 CT), 154 pages loaded, 8 of them without a final URL or a screenshot. Labelled blind: **146 pages: 74 phishing (50 lures, 17 credential, 4 payment, 3 gates), 42 benign, 3 the brand's real site, 27 unsure**. All phishing but one (an App Store page copy on `apps--apple.com`, from CT) came from OpenPhish.

| | Phishing flagged (of 74) | Others flagged (of 45) |
| --- | --- | --- |
| High | 5 | 1 |
| Medium and up | 38 (51 %) | 6 |
| The same without the S12 lure rules | 24 | 2 |

| Indicator | Fired on phishing | Only indicator on | Others |
| --- | --- | --- | --- |
| brand-name-off-domain | 12 | 9 | 2 |
| brand-offer-off-domain | 8 | 7 | 1 |
| form-on-free-hosting | 8 | 2 | 0 |
| kit-match | 8 | 5 | 0 |
| brand-domain-in-title | 7 | 5 | 3 |
| fake-human-check | 2 | 1 | 0 |
| brand-name-disguised | 1 | 1 | 0 |
| brand-official-claim | 1 | 0 | 0 |
| brand-alert-off-domain | 0 | – | 0 |
| brand-presented-off-domain (info) | 16 | – | 17 |

- **Lures: 23 of 50** (3 of 34 in set 3, 3 of 12 in set 4). The lure rules alone caught 14: the Shopee prize draw (7 pages on blogspot, `brand-offer-off-domain`), the Ledger "Ledger.com/Start" pages (5 on typedream and netlify, `brand-domain-in-title`), a "Ⓚucoin Login" page and an Amazon page copy. So two kit families carry most of it, as expected from S12. `brand-alert-off-domain` caught nothing: the Google "hacked" kit didn't come back, and the two "Facebook has suspended your account" pages name the brand only in a dialog, not a title or heading.
- **The lure rules' price: 4 false alarms.** `brand-domain-in-title` on three captures of one Amazon India tutorial clone on github.io: its banner says "You are on amazon.com ... click here to go to amazon.in" inside an element with a "title" class, which the rules read as a heading. `brand-offer-off-domain` on AdsChase, a Shopify ad tool (CT), whose headings name Google and whose text says "winners". The other two false alarms are older rules: `brand-name-off-domain` (high) on "Work Café Banco Santander", a sign-in on an agency's `interacso.dev` domain that I labelled benign as the DHL agency tool was (a judgment call), and (medium) on iCloud Support Ltd, a UK IT consultancy whose name contains "iCloud", with a form asking for details.
- **Kit references:** 8 kit-match hits, all right. One came from the refreshed references (an imToken clone matching the third set's); the others matched pages labelled on 14 October (Banco Pichincha loan forms, a brandless "Account Verification" login, the Steam invite, the Turnstile "shared document" kit, a Framer Rogers page).
- **Gates: 2 of 3.** The drawn Cloudflare "Verify you are human" box came back (`giftboxesss881.ink`) and `fake-human-check` caught it, its first catch on a fresh page; also a drawn "I am not a robot" box on replit. Missed: a French "Vérification de votre navigateur en cours" page (the wording isn't in the list). The Outlook "confirming it's you" Turnstile kit didn't come back.
- **Unsure:** 18 of the 27 are the Russian "Введите капчу / Войти" captcha box on `sion10.to` subdomains (CT), never labelled before; `fake-human-check` flags 11 of them. Two more are Microsoft password pages with a prefilled address on Fortra phishing-simulation domains (`brand-name-off-domain`, high): sanctioned simulations, phishing in form.
- **Misses (36):** mostly brands not on the list (Xfinity, AR24, Crypto.com, Scotiabank, Swisscom, Metanet, Spectrum, U.S. Bank, Gemini, SwissBorg, UnionPay, the Indian civil-registration portal, Orange, which is an ordinary word); page copies and document lures that name nothing; two Orange lures on `sites.google.com`, which belongs to Google, so the brand rules stay silent there.
