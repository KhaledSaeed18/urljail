# Feed ingestion (design, live gate)

Status: **built (P6 M1), OpenPhish Community only**; URLhaus waits for an Auth-Key. Differences from the design are marked *As built*. Source decision (2026-10-12, Q13): **free feeds first**: OpenPhish Community and URLhaus ([research/feeds.md](./research/feeds.md)). Good enough to build ingestion and run live mode end to end; cloaking statistics will need a fresher phishing source later (OpenPhish Academic/paid, or own CT-log discovery).

## Principles

1. **Feeds are untrusted input; URLs are data** (threat model rule 3). A URL is never interpolated into a command, a file path or a log format string; it's a JSON string from fetch to report.
2. **Never in the root daemon.** Fetching and parsing feed lists runs in an unprivileged process as the operator. The daemon only ever receives one URL string per `Detonate` call and applies the same policy as for a URL typed by hand (`internal/policy`: http/https only, ports 80/443, length limit, live mode required for non-allowlisted hosts).
3. **Within each provider's terms** ([research/feeds.md](./research/feeds.md)): their access method only, their fetch limits, no redistribution of the lists, attribution where required.
4. **Gentle on targets.** Phishing often sits on compromised legitimate sites: per-domain rate limits, no retries that hammer.

## Shape

```
 urljail feeds run   (operator uid, no privileges)
   ├─ fetchers: openphish-community, urlhaus-recent      ── HTTPS from the host network
   ├─ parser: line/JSON → candidate URL (strict, capped)
   ├─ queue:  ~/.local/share/urljail/feeds/queue.jsonl   (dedup, first-seen, provenance)
   └─ scheduler ──gRPC Detonate(url, provenance)──► urljaild (root): policy check, run, report
```

- **Separate command** (`urljail feeds run|status|pause`), not a daemon module: a parser bug in list handling stays in an unprivileged process.
- **Only in live mode:** the scheduler checks the daemon's egress mode (`Version` RPC) and refuses to submit unless it is `live` (in `dev`/`live-test` the daemon would refuse non-allowlisted URLs anyway).

## Fetching

| Feed | Endpoint | Cadence | Notes |
| ---- | -------- | ------- | ----- |
| OpenPhish Community | the plain-text feed URL OpenPhish publishes | conditional GET (`If-Modified-Since`/ETag) at most hourly; the feed changes every 12 h | no timestamps per URL: first-seen is when urljail first saw it |
| URLhaus | "recent URLs" API with the operator's `Auth-Key` | at most every 5 minutes (their stated limit for dumps) | has `date_added`, threat type and tags; mostly malware distribution, so runs will mostly be downloads (stay on the guest's `noexec` tmpfs, destroyed with the VM) |

The Auth-Key lives in `~/.config/urljail/feeds.toml` (`0600`), never in run records.

## Parsing a candidate

1. One line (OpenPhish) or one JSON field (URLhaus); anything else is skipped and counted.
2. Cap: 2048 bytes; reject control characters and anything that doesn't parse as an absolute URL.
3. Normalize: scheme and host lowercased, default ports dropped, fragment dropped; keep path and query as given (cloaking can depend on them).
4. Pre-check with the same `internal/policy` rules the daemon uses, minus the mode (so obviously invalid entries never reach the daemon).

## Queue and scheduling

- **Dedup** by normalized URL; keep `first_seen` (ours), `feed_time` (if the feed has one) and the feed name.
- **Freshness first:** newest entries first; drop entries older than a configurable age (default 24 h): stale phishing is mostly dead, and dead URLs waste runs.
- **Per-domain limit:** at most one detonation per registrable domain (eTLD+1) per 10 minutes, and a daily cap per domain.
- **Concurrency:** no more than the daemon's free slots; the daemon's own busy refusal is the backstop.
- **Pause:** `urljail feeds pause` stops submissions immediately (the queue keeps filling).

*As built (M1):* state in `~/.local/share/urljail/feeds/state.json` (`0600`, one JSON document, not `queue.jsonl`); one detonation at a time; `urljail feeds run -n N` fetches what's due, then runs at most N. OpenPhish's feed has no per-URL time, so every URL from one fetch shares a first-seen time and "newest first" only separates fetches.

## Provenance in the run

*As built (M1):* no daemon change yet. `urljail feeds run` writes `feed.json` (feed name, first seen) into the run directory, which the operator owns, and rebuilds the report locally, so `run.feed` is set. `feed.json` is written by the operator's process, never by the guest or the daemon, and the report builder treats it as untrusted bytes (fuzzed). Moving provenance into `Detonate` can come with the next daemon change.

`Detonate` gains an optional provenance message (feed name, feed time, first seen), recorded in `meta.json` and the report (`run.feed`), so P6 can measure *time since first seen*, the dominant variable for cloaking (research/anti-cloaking.md).

## Storage and sharing

- Run reports contain the URLs. They stay local; publishing results means aggregate numbers, not the lists (no redistribution).
- Queue and reports fall under the retention policy (P7).

## Tests (when built)

Fuzz the feed parsers; unit-test normalization and dedup; a fake feed server for the fetchers (conditional GET, rate limits); an end-to-end run in `live-test` with an allowlisted URL injected as if from a feed (the policy must still refuse any non-allowlisted one there).

## CT discovery (own source, P6)

Decision (2026-10-13): the free feeds are hours old and most of their URLs are dead by then (P6 journal), so urljail also finds candidates itself in **Certificate Transparency**: a phishing site on its own domain needs a certificate, and the certificate is public within seconds.

- **Logs:** Let's Encrypt's current static-ct-api logs (`internal/ctlog`), picked from Chrome's log list at start (shards rotate every six months). Only full tiles are read; a follower more than 20 tiles behind skips ahead, since only fresh names matter. Checkpoint signatures aren't verified: the logs are a source of names to try, nothing more.
- **Parsing:** each entry is read only as far as the certificate's dNSName SANs, with every length bounded; DNS-character names only; fuzzed.
- **Scoring** (`feeds.Score`): a brand in the registered name (+3) or a subdomain (+2), lookalike spelling (+1), action words (+1 each, up to 3), a cheap TLD (+1), two or more hyphens in the registered name (+1), machine-generated labels (−2). Candidate at 4 or more, and only with a brand, unless three action words sit on a cheap TLD. The brands' own domains and hosting platforms are excluded. Every point is recorded with the candidate (`reasons`) so hit rates can be measured per rule.
- **Scheduling:** `urljail feeds watch` waits `-min-age` (default 5 min) after the certificate's log timestamp, then runs each candidate under every profile, newest first, with the same per-domain limits; CT candidates expire after 6 h.
- **Volume** (first sample, 2026-10-13): about 31 new unique names per second across both logs; brand impersonation is rare, about 1 candidate in 7,500 names, so this is a slow trickle of very fresh URLs.
- **Queue safety:** commands that change the queue take a lock; `feeds pause` is a file, so it reaches a running `watch`.
- **Tuning:** `urljail feeds ct -for 10m -dry-run -dump names.txt` records names for offline scoring (`URLJAIL_CT_DUMP=names.txt go test ./internal/feeds/ -run TestScoreDump -v`).

