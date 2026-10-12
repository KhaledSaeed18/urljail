# Feeds: terms of use and fitness for P6 (open question Q13)

Researched 2026-10-12 for the live gate. **Not legal advice; accepting terms is the operator's decision.** Quotes are from the providers' pages on that date.

| Feed | Access | Terms that matter here | Freshness | Content | Fit for P6 |
| ---- | ------ | ---------------------- | --------- | ------- | ---------- |
| **OpenPhish Community** | free, plain text, no account | Terms allow use "for academic, independent, or personal research" (not supporting an organization's business); no commercial use without written consent; no redistribution; access only "using the interface and instructions that OpenPhish provides" | **every 12 hours** (paid tiers: 5 minutes) | phishing URLs, "limited" volume | Allowed for independent research, but 12 h is too stale for cloaking measurements (P6 needs minutes) |
| **OpenPhish Academic** | by application, academic email only | non-commercial, must credit OpenPhish (site + access date), no sharing with third parties; 60 days, extendable; limited seats | real-time | phishing URLs + metadata, 30-day archive | Best fit, **if** the operator has an academic affiliation |
| **URLhaus** (abuse.ch) | free API/dumps with an **Auth-Key** (account) | "Authenticated Users may access the Platforms for not-for-profit purposes" within volume limits; no high-volume harvesting; dumps "not more often than every 5 minutes"; no redistribution or derivative works without consent; commercial use may need a paid Spamhaus subscription | minutes | mostly **malware distribution** URLs, not phishing pages | Allowed (not-for-profit), fresh, but the wrong content for phishing-cloaking research; useful for download handling later |
| **PhishTank** (Cisco Talos) | needs an account | — | — | phishing | **Unavailable:** new registrations closed since 2020 for abuse; still closed in 2026 per Wikipedia, pending a rebuild (no official reopening notice found) |

## Implications

- Free sources don't meet P6's freshness requirement for phishing: OpenPhish Community is phishing but 12 h old; URLhaus is fresh but malware.
- Options, roughly by effort:
  1. **OpenPhish Academic** (if eligible): real-time phishing, research use explicitly allowed, attribution required.
  2. **OpenPhish paid tier**: 5-minute updates; commercial-style licensing questions to settle with them for a personal research project.
  3. **Own discovery from Certificate Transparency logs** (new certificates for look-alike names, e.g. via a CT log stream): no feed terms involved and very fresh, but urljail would be judging what's phishing itself, which needs care (false positives are real sites).
  4. **OpenPhish Community + URLhaus** as-is: legal for not-for-profit research, good enough to exercise live mode end to end, not for cloaking statistics.
- Whatever is chosen: one feed fetch at a time within each provider's stated limits, URLs handled strictly as data (threat-model rule 3), no redistribution of the URL lists, attribution where required, and the run reports (which contain the URLs) not published as a dataset without checking the terms.

## Sources

- OpenPhish: [Terms of Use](https://openphish.com/terms.html), [Phishing Feeds](https://openphish.com/phishing_feeds.html), [Academic Use](https://openphish.com/academic_use.html)
- abuse.ch: [Terms of Use](https://abuse.ch/terms-of-use/), [URLhaus API](https://urlhaus.abuse.ch/api/)
- PhishTank: [Wikipedia](https://en.wikipedia.org/wiki/PhishTank), [Cisco Community thread](https://community.cisco.com/t5/web-security/does-cisco-own-phishtank/m-p/5033988/highlight/true)
