# Name check (round 2): urljail, linkopsy, detonbox, burnervm, phishcage, phishjail

**Recommendation:** urljail: free on every surface checked including `.com`, zero competitors or collisions, and it says what the tool does when you read it (suspicious URLs get locked in a jail; echoes Firecracker's *jailer*). Real risk: a reader might first assume it *blocks* URLs (a blocklist) rather than *detonates and analyzes* them, which the tagline has to fix.
**Checked:** 2026-10-10 · Go host agent + CLI that detonates suspicious URLs in throwaway Firecracker microVMs and reports their behavior
**Why round 2:** round 1's pick (flashpan) was rejected because it doesn't read as what the tool does. This round only considers names whose meaning is visible on first read.

## Verdict at a glance

| Candidate | .com | .dev | .io | .sh | .app | .net | GitHub handle | GitHub repos | crates | Homebrew | Docker Hub | AUR/Debian/Fedora | npm/PyPI | Go modules | Collisions | Verdict |
| --------- | ---- | ---- | --- | --- | ---- | ---- | ------------- | ------------ | ------ | -------- | ---------- | ----------------- | -------- | ---------- | ---------- | ------- |
| urljail   | free | free | free | free | free | free | free | 0 | free | free | free | free | free | free | none | **recommended** |
| linkopsy  | free | free | free | free | free | free | free | 0 | free | free | free | free | free | free | Linkody (SEO SaaS), weak | runner-up |
| detonbox  | free | free | free | free | free | free | free | 0 | free | free | free | free | free | free | none, but "deton" isn't a word | ok |
| burnervm  | free | free | free | free | free | free | free | 0 | free | free | free | free | free | free | **BunkerVM**: Firecracker disposable-VM sandbox | blocked |
| phishcage | taken (2019) | free | free | free | free | free | free | 0 | free | free | free | free | free | free | none | weaker |
| phishjail | taken (2023) | free | free | free | free | free | free | 0 | free | free | free | free | free | free | none | weaker |

## Screen (GitHub repo search, `in:name`, sorted by stars)

Free (0 repos): urljail, phishcage, urlcage, detonvm, detonbox, phishvm, burnervm, urlburner, linkopsy, urlopsy, phishopsy, lurecage, baitcage, linkdetonator, urldetonator, phishjail, phishchamber, linkchamber, clickjail, detonlab.
Taken/noisy: detonator (182 repos; dobin/detonator is a malware-detonation tool, same space), linkcage (8), lurebox (5), linkjail (2, Bliss-Browser LinkJail), blastchamber (1), clickcage (1).

## urljail

| Surface | Checked via | Result | Verdict |
| ------- | ----------- | ------ | ------- |
| .com .dev .io .sh .app .net | `curl -sL https://rdap.org/domain/urljail.<tld>` | 404 on all six | free |
| GitHub handle | `gh api users/urljail` | 404 | free |
| GitHub repos | repo search `urljail in:name` | 0 | free |
| Near misses | repo search `url-jail` / `urljails`; npm `url-jail`, `urljails` | 2 / 0 repos (0★); npm 404 / 404 | free |
| Go modules | `pkg.go.dev/search?q=urljail&m=package` (control `chromedp` = 25 hits) | 0 package hits | free |
| crates.io | API | 404 | free |
| Homebrew formula / cask | `formulae.brew.sh/api/...` | 404 / 404 | free |
| Docker Hub | library repo + search | 404, no results | free |
| AUR / Debian / Fedora | RPC / sources API / src.fedoraproject API | 0 / not found / 404 | free |
| npm / PyPI | registry APIs | 404 / 404 | free |
| Local command | `command -v urljail` | none | free |
| Web search | `"urljail"` | nothing; only a 2007 IVLE function `url_to_jailpaths` | free |

**Collisions:** none. **Findability:** owns its exact-match results from day one; "url jail" as two words drifts into physical-jail results, so always write it as one word. **Trademark signals:** none found by web search (not a register search; not legal advice). **Reading:** "U-R-L jail", instantly parsable, 7 characters, easy CLI (`urljail https://…`). **Risks:** "jail" can suggest blocking rather than analysis; FreeBSD "jails" association (harmless, even fitting).

## linkopsy

Fully free on every surface, including `.com`. "Link + autopsy": it names the *output* (a post-mortem of what a link does), which is creative and memorable. Weaker than urljail because the reading is a beat slower ("link-OP-see") and the nearest web hit is Linkody, an SEO backlink tool, close enough in spelling to blur searches. Good fit as the name of the *report*, even if not the project.

## detonbox

Fully free, no collisions, but "deton" is not a word, so it reads as a coined fragment ("deh-ton-box"). Generic "detonate" search space is crowded (Elastic's internal *Detonate*, EclecticIQ docs).

## burnervm: blocked

Free on registries, but [BunkerVM](https://alternativeto.net/software/bunkervm/about) is an open-source Firecracker microVM disposable sandbox: a one-letter-swap near miss in the exact same technology. Support-ticket generator.

## phishcage / phishjail

`.com` registered (2019 / 2023); otherwise free. They also narrow the scope to phishing, while the tool detonates any suspicious URL.

## Not checked

- **Trademark registers (USPTO / EUIPO / WIPO):** unverified; search UIs need a browser. Search `urljail` in classes 9 and 42 before anything commercial.
- **Social handles:** skipped (not a consumer product).
- **App stores, VS Code, Maven, RubyGems, Packagist, NuGet, JSR:** n/a.
- **Other-language meanings:** not verified by native speakers; none known.

## If you take urljail

1. GitHub repo `KhaledSaeed18/urljail` (Go module `github.com/KhaledSaeed18/urljail`).
2. GitHub org `urljail` is free: claim it now if you might ever move the repo to an org.
3. `urljail.dev` or `urljail.com` (both free today): the most contested surface long-term; register when you're ready to commit.
4. Docker Hub `khaledsaeed18/urljail`, Homebrew tap: when there's something to ship.
