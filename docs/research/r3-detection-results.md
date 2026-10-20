# R3 results: detecting phishing from a detonation report

Status: **results, 2026-10-20** (P7 side quest, S1–S22). Day-by-day record, including every correction: [P7 journal](../journal/p7-control-plane.md#side-quest-look-alike-pages-and-brand-signals-2026-10-14). Labels and the indicators each set's freeze produced: [p7-indicator-labels.tsv](./data/p7-indicator-labels.tsv).

## Answer

Over eight held-out sets of fresh phishing-feed and Certificate Transparency pages (14–20 October 2026), labelled blind and scored once with the rules frozen before each set was run:

1. **Medium and up flagged 190 of 407 phishing pages (47 %) and 27 of 304 others (8.9 %).** High severity alone: 62 of 407 phishing pages, 1 false alarm in 304.
2. **What carries detection is a brand named off its own domains** (`brand-name-off-domain`: 94 phishing pages, 59 of them caught by nothing else, 9 false alarms). Everything else adds a few pages per set.
3. **Rules written after a set catch that set's kits, rarely the next set's.** Every after-the-set round raised the in-sample rate (the last one from 46 % to 51 % on set 7); on the following held-out set each round added 0 to 7 pages, except the S12 lure rules (14 in set 5, from two kit families). In-sample on every labelled page, today's rules flag 76 %; held-out they flagged 47 %.
4. **The held-out rate follows the brand list.** Most misses in every set are pages that ask for nothing yet (135 of the 217 misses have no password and no field to type into) and sign-in clones of brands the list didn't have; a brand added after a set helps only if it comes back (4 of 13 did, every page then caught).
5. **Kit references work within about a day.** `kit-match` was never wrong (26 phishing pages, no false alarm) and caught 10 pages alone, but only when the same operation was still publishing: set 7, three days after the last labels, got none; set 8, a day after, four.

For a scanner: a report-only detector of this kind is a triage signal, not a verdict. High severity can be acted on (one false alarm in 304); medium and up needs a person. The gains left are in coverage (brands, gate kits, payment pages), and each has the same long tail.

## Method

1. **Pages.** The free OpenPhish feed (newest URLs, within three hours of first being listed) and Let's Encrypt's CT logs scored for phishing names (`urljail feeds run`, `feeds watch`), one detonation per URL in a fresh Firecracker microVM through one VPN exit, plus control runs under two other browser profiles. Sets 1–6 and 8 were labelled on the `stealth` profile; set 7 on `stealth-headful`, because the `stealth` snapshot had stopped restoring ([journal](../journal/p7-control-plane.md#snapshots-older-than-a-day-2026-10-19)).
2. **Freeze.** The rules (one Go binary: `internal/report`, the brand list, the kit references) are committed and frozen before a set's loop starts; nothing is changed while it runs.
3. **Blind labels.** Each page that loaded with a screenshot is labelled from its screenshot, URL, title, visible text and form fields, never its indicators: phishing (credential, lure, gate, payment, device-code), benign, the brand's real site (a redirect to facebook.com), or unsure. Tutorial clones of a homepage are benign; a sign-in clone asking for a password is phishing.
4. **Score once** with the frozen binary (`urljail indicators score`). A page counts as flagged when any indicator is medium or high; `info` doesn't count. Others are benign and real-site pages; unsure pages count in neither.
5. **After the set**, rules may change from its misses and false alarms; each change is measured over every stored run (`urljail indicators dump` / `diff`, about 8,000 runs) and kept only if it adds no false alarm on labelled pages and changes runs only on phishing hosts. Those numbers are in-sample and reported as such.

## Results by set

Medium and up, at the freeze each set was run with:

| Set | Date | Freeze | Phishing flagged | Others flagged | High: phishing / others |
| --- | --- | --- | --- | --- | --- |
| 1 | 14 Oct | `fa8a848` | 11 of 34 | 1 of 12 | 10 / 0 |
| 2 | 14 Oct | `091ec7e` | 8 of 30 | 3 of 44 | 4 / 0 |
| 3 | 15 Oct | `21d0924` | 34 of 88 | 0 of 22 | 24 / 0 |
| 4 | 15 Oct | `1623cdd` | 17 of 26 | 4 of 25 | 4 / 0 |
| 5 | 16 Oct | `ef81165` | 38 of 74 | 6 of 45 | 5 / 1 |
| 6 | 16 Oct | `7394876` | 23 of 37 | 7 of 91 | 2 / 0 |
| 7 | 19 Oct | `c97191a` | 19 of 41 | 3 of 33 | 2 / 0 |
| 8 | 20 Oct | `a863671` | 40 of 77 | 3 of 32 | 11 / 0 |
| **All** | | | **190 of 407 (47 %)** | **27 of 304 (8.9 %)** | **62 / 1** |

By kind, all held-out sets: credential pages 103 of 157 (66 %), gates 16 of 45, lures 63 of 181 (35 %), payment 8 of 22, device-code 0 of 2.

## What each rule caught held-out

Phishing pages a rule fired on at medium or high, how many it alone flagged, and non-phishing pages it fired on, over the eight held-out sets at their freezes:

| Indicator | Phishing | Alone | Others | Added |
| --- | --- | --- | --- | --- |
| brand-name-off-domain | 94 | 59 | 9 | S3 |
| form-on-free-hosting | 57 | 13 | 8 | S5 |
| kit-match | 26 | 10 | 0 | S7, references refreshed S13, S19, S21 |
| brand-domain-in-title | 17 | 10 | 4 | S12 |
| brand-offer-off-domain | 15 | 13 | 1 | S12 |
| fake-human-check | 9 | 8 | 0 | S9 |
| brand-official-claim | 9 | 3 | 1 | S12 |
| password-form-cross-origin | 8 | 0 | 0 | S3 |
| block-page-on-free-hosting | 7 | 7 | 0 | S9 |
| brand-lookalike-domain | 6 | 4 | 5 | S3 |
| brand-name-disguised | 4 | 3 | 0 | S12 |
| brand-alert-off-domain | 2 | 0 | 1 | S12 |
| brand-look-off-domain (screenshot) | 1 | 1 | 0 | S1 |
| password-under-threat | 1 | 1 | 0 | S19 |
| card-form-in-page | 0 | – | 0 | S19 |
| brand-footer-off-domain | 0 | – | 0 | S21 |
| brand-favicon-off-domain | 0 | – | 0 | S6, removed S14 |

(`brand-presented-off-domain` counted at medium only in set 1; it was demoted to `info` after it, for flagging 6 harmless pages.)

## Why the after-the-set rules don't carry

- **Kits move faster than the sets.** A set is a few hundred URLs from one or two feed updates; the kits in it are that day's operations. The S12 lure rules were built on the Shopee prize draw and the Ledger "start" guide pages; both kept coming (25 of the lure rules' held-out catches: Ledger 14, Shopee 11; all other brands 15), while most other lure families seen once never came back.
- **Brands have a long tail.** Each set's misses named brands the list lacked (Xfinity, Scotiabank, ConstructConnect, Banco CTT, Israel's National Insurance...). Adding them works when the brand comes back: of the 13 brands added after sets 5 and 6, 4 returned in the next sets (AR24, Gemini, Xfinity, Netcoins), and all 5 of their pages were caught; the other 9 haven't been seen since. Hosting services have the same tail (typedream.app, cleverapps.io, b12sites.com and the like are not on the free-hosting list).
- **Rules without a brand are few and narrow.** The brandless rules that held up (`block-page-on-free-hosting`, `fake-human-check`, `password-under-threat`) each describe one deceptive act precisely; a broader brandless sign-in rule was tried (S17) and fired on self-hosted software (Authelia, Healthchecks, a Cloudflare Access page) every day in the CT stream.
- **Lures ask for nothing.** Of the 217 held-out misses, 118 are lures and 135 have no password field and nothing to type into: guide pages, prize draws, homepage copies, blank pages. Their brand is often only in an image.

## False alarms

27 at medium and up in 304 non-phishing pages, from five causes: a brand named with sign-in wording or a form on harmless pages (tutorial clones with "Sign in", a mod-APK site, a LinkedIn tool twice, a security write-up, an IT firm called "iCloud Support", a Santander sign-in on an agency's domain; 9), forms on free hosting (private apps with a login, four WordPress comment forms; 8), look-alike domains of unrelated sites (`amazonex.app`, `facebookno.live`, `test.cticloud.dev`; 5), tutorial clones whose title writes the brand's domain or calls itself official (4), an offer word on an ad tool (1). Each fix after a set removed the false alarms it was written for, and none since (on about 8,000 stored runs) added one.

## Limits

- One analyst labelled every page; labels follow written conventions (homepage tutorial clones are benign, sign-in clones are phishing, a blank page with a brand title is unsure), but there is no second opinion.
- The pages are one free feed's newest URLs and a CT name scorer's picks over a week, through one VPN exit; a paid feed or another vantage point would see other kits.
- The OpenPhish free list changed only once or twice a day; most sets are one or two of its updates, so a set's pages are correlated (one kit on many hosts).
- Held-out numbers use the rules of their day; the in-sample column below shows how far rules written after seeing a set lift it.

| Set | Held-out (its freeze) | Today's rules (`a863671`, in-sample for all but set 8) |
| --- | --- | --- |
| 1 | 11 / 34 | 29 / 34 |
| 2 | 8 / 30 | 23 / 30 |
| 3 | 34 / 88 | 77 / 88 |
| 4 | 17 / 26 | 23 / 26 |
| 5 | 38 / 74 | 50 / 74 |
| 6 | 23 / 37 | 31 / 37 |
| 7 | 19 / 41 | 21 / 41 |
| 8 | 40 / 77 | 40 / 77 |

## Next

Coverage, measured the same way: a rule for device gates ("this content needs a Windows computer", set 8's new kit on three hosts), payment pages (0 of 5 in set 8: send-crypto and fake shop product pages), and brands from set 8's misses; each tested on a ninth held-out set.
