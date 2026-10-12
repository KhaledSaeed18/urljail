# 0012: Google Chrome stable in the guest, pinned and archived

- Status: Accepted
- Date: 2026-10-12

## Context
The guest browser's build is visible to the pages being detonated, and it's the component most exposed to hostile content (open question Q17). On 2026-10-12:

| Build | Version |
| ----- | ------- |
| Google Chrome stable (Linux) | 155.0.8059.39 |
| Debian `chromium`, sid | 155.0.8059.39 |
| Debian `chromium`, trixie (Debian 13, our base) | 150.0.7871.181 |

## Decision
Install **Google Chrome stable** from Google's official `.deb` into the Debian 13 rootfs.

- **Pinned:** the exact version is recorded in the image manifest and every run's `meta.json`.
- **Archived:** Google's download only serves the current version (and its pool drops old ones), so each `.deb` used is kept in `~/.local/share/urljail/cache/` with its SHA-256. The image build verifies the hash.
- **No self-updates in the image:** the package's apt source and cron job are removed. Updating means rebuilding the image with a new pinned `.deb`.
- **Policy path:** `/etc/opt/chrome/policies/managed/urljail.json` (Chrome's location, not Chromium's).

## Alternatives considered
- **Debian trixie `chromium`:** five major versions behind stable today, which is both a security gap for the component facing hostile content and an "outdated browser" signal. It also reports the brand `Chromium` in `navigator.userAgentData.brands`, where real users' Chrome reports `Google Chrome`.
- **Debian sid `chromium` in a trixie image:** current, but mixes suites in the base image and still reports the `Chromium` brand.
- **Chrome for Testing:** built for automation and easy to pin, but it's a distinct build intended for tests, not what users run; its fingerprint would need checking separately. Kept as a possible P6 comparison condition.

## Consequences
- Fingerprint closer to real users (brand, version currency, proprietary codecs).
- Chrome's license allows this use; urljail images aren't redistributed.
- Image rebuilds follow Chrome stable releases; the manifest diff shows exactly what changed.
- [guest-image.md](../guest-image.md) policy path and browser row updated.
