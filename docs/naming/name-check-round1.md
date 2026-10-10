# Name check: pyre, touchpaper, flashpan, uncloak, detcord

**Recommendation:** flashpan: clean on every package registry, no software product or competitor uses it, `.dev`/`.io`/`.sh`/`.app` are unregistered. Real risk: the idiom "flash in the pan" also means "a promising start that fizzles", and the bare `flashpan` GitHub handle is held by a dormant account.
**Checked:** 2026-10-10 · Go host agent + `detonate` CLI that runs suspicious URLs in throwaway Firecracker microVMs (open source on GitHub; possible Docker image, Homebrew formula, docs domain later)

## Verdict at a glance

| Candidate  | .com  | .dev  | .io  | GitHub handle | crates | Homebrew | Docker Hub | Distro pkgs | Other registries | Collisions / web | Verdict |
| ---------- | ----- | ----- | ---- | ------------- | ------ | -------- | ---------- | ----------- | ---------------- | ---------------- | ------- |
| pyre       | n/c   | n/c   | n/c  | n/c           | n/c    | n/c      | n/c        | n/c         | n/c              | Meta `pyre-check` 7.2k★ + `pyrefly` 7.1k★ | **blocked** |
| touchpaper | taken | free  | free | taken         | free   | free     | free       | free        | PyPI taken       | Touchpaper Group (UK ITSM software, trademark) | risky |
| flashpan   | taken | free  | free | taken (dormant) | free | free     | free       | free        | npm/PyPI free    | none             | **recommended** |
| uncloak    | taken | taken | free | taken         | free   | free     | free       | free        | npm taken        | common verb; PhishDecloaker (USENIX '24) near miss | weak |
| detcord    | taken | free  | free | taken (dormant) | free | free     | free       | free        | npm/PyPI free    | active Discord tool "Detcord"; search = explosives | weak |

n/c = not checked: pyre was eliminated at the collision screen.

## Screened out before the full sweep (GitHub collision screen, sorted by stars)

| Name | Why it died |
| ---- | ----------- |
| pyre | facebook/pyre-check (7171★), facebook/pyrefly (7073★): same dev-tool space, owns all search results |
| ignite | weaveworks ignite: a Firecracker microVM manager, exact same space |
| flintlock | liquidmetal-dev/flintlock (1512★): Firecracker microVM manager, exact same space |
| pyrebox | Cisco-Talos/pyrebox (1685★): malware sandbox, exact same space |
| kindling | harmonycloud/kindling (1064★): eBPF observability, same space |
| firepit | opencybersecurityalliance/firepit: security tooling |
| sootbox | free (0 repos) but one letter from TheresAFewConors/Sooty (1491★), a SOC-analyst CLI |
| cinder, pyrite, squib, singe, mayfly, fuze, ember, tinderbox | large unrelated projects own the name |

## flashpan

| Surface | Checked via | Result | Verdict |
| ------- | ----------- | ------ | ------- |
| .com | `rdap.org/domain/flashpan.com` | 200, registered 2001-03-06 | taken |
| .dev | RDAP | 404 | free |
| .io | RDAP | 404 | free |
| .sh | RDAP | 404 | free |
| .app | RDAP | 404 | free |
| GitHub handle `flashpan` | `api.github.com/users/flashpan` | 200, user created 2015, 0 repos | taken (dormant) |
| GitHub handles `flashpan-dev`, `flashpanhq`, `flashpan-sh`, `flashpanvm` | `api.github.com/users/<h>` | 404 | free |
| GitHub repo collisions | repo search `flashpan` | 13 hits, all 0–1★, all "flashpanel"/"flashpanorama"/"FlashPanda" | free |
| Go modules | `pkg.go.dev/search?q=flashpan` | 0 results | free |
| crates.io | `crates.io/api/v1/crates/flashpan` | 404 | free |
| Homebrew formula / cask | `formulae.brew.sh/api/{formula,cask}/flashpan.json` | 404 / 404 | free |
| Docker Hub | `hub.docker.com/v2/repositories/library/flashpan` + search | 404; search only fuzzy-matches `xflashpanda/*` | free |
| AUR | `aur.archlinux.org/rpc/v2/info?arg[]=flashpan` | resultcount 0 | free |
| Debian | `sources.debian.org/api/src/flashpan/` | not found | free |
| Fedora | `src.fedoraproject.org/api/0/rpms/flashpan` | 404 | free |
| npm / PyPI | registry APIs | 404 / 404 | free |
| Local command | `command -v flashpan` | none | free |

**Collisions:** no product, library, or security tool named flashpan. Nearest: FlashPanel (BetterCloud, Google Workspace admin tool), a different name in a different space.
**Findability:** "flashpan" alone mixes with Adobe Flash / flash-panorama results; "flashpan sandbox" / "flashpan firecracker" will be unique from day one.
**Trademark signals:** none found by web search. Not legal advice, and not a register search (see Not checked).
**Meaning:** the flash pan is the priming pan on a flintlock, where the powder ignites first: a small, contained ignition, which is what a single detonation VM is. It also fits the Firecracker theme. Reads and spells easily ("flash-pan").
**Risks:** (1) the idiom "a flash in the pan" can read as "fizzles out"; (2) the `flashpan` GitHub handle is dormant but taken, so the repo lives at `KhaledSaeed18/flashpan` (fine for a Go module path) or under `flashpan-dev` if you ever want an org.

## touchpaper

Strong meaning ("light the touchpaper and stand back"), and `.dev`/`.io`/`.sh` are free, but:
- **Touchpaper Group**, a UK IT service-management *software* company with a trademark filed 2001 (software class), acquired by Avocent. A real trademark signal in software. ([CB Insights](https://www.cbinsights.com/company/touchpaper), [Justia trademarks](https://trademark.justia.com/owners/touchpaper-group-limited-1762967))
- PyPI `touchpaper` is taken (an EC2 instance launcher CLI); `touchpaper.com` registered since 2001; GitHub handle taken.
- 10 characters is long for a CLI you type all day.

## uncloak

Names the research goal, but `.com`, `.dev`, `.app`, npm (`uncloak`, a reveal.js theme editor) and the GitHub handle are all taken. It's a common verb, so it's hard to find in search. And [PhishDecloaker (USENIX Security '24)](https://www.usenix.org/conference/usenixsecurity24/presentation/teoh) sits in exactly this research space, so the near miss would confuse readers.

## detcord

Registries are clean, but canaryframe/detcord is an actively maintained Discord bulk-delete tool (pushed 2026-09), nullmonk/detcord is a red-team autopwn tool, and web search for the word returns only explosives ([Wikipedia](https://en.wikipedia.org/wiki/Detonating_cord), [Dyno Nobel](https://www.dynonobel.com/products-services/products/initiation-systems/det-cord/)). An explosives term on a security tool can also trip content filters or read as malware.

## Not checked

- **Trademark registers (USPTO / EUIPO / WIPO):** unverified; their search UIs need a browser. Only web-search trademark signals were gathered. Search `flashpan` in classes 9 and 42 at tmsearch.uspto.gov and tmdn.org/tmview before anything commercial.
- **Social handles (X, Reddit):** skipped, not a public consumer product.
- **App stores, VS Code Marketplace, Maven, RubyGems, Packagist, NuGet, JSR:** n/a for a Go/Linux systems tool.
- **Meaning in other languages:** not verified by a native speaker; no unfortunate meaning known.

## If you take flashpan

1. Create the GitHub repo `KhaledSaeed18/flashpan` (Go module path `github.com/KhaledSaeed18/flashpan`), the surface that matters immediately.
2. Optionally grab the `flashpan-dev` GitHub org now (free, unclaimed) so a future org move is possible.
3. `flashpan.dev`: only if/when the project gets a docs site.
4. Docker Hub `khaledsaeed18/flashpan` and a Homebrew tap: when there's something to ship.
