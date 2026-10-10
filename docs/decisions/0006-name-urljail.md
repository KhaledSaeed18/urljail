# 0006: Project name: urljail

- Status: Accepted
- Date: 2026-10-10

## Context
The name must say what the tool does on first read and be free across registries, domains and code hosts.

## Decision
**urljail**: suspicious URLs get locked in a jail; echoes Firecracker's *jailer*.

## Alternatives considered
Two rounds with the `project-name-check` skill: see [naming/name-check-round1.md](../naming/name-check-round1.md) and [naming/name-check-round2.md](../naming/name-check-round2.md).
- pyre: owned by Meta's Python type checkers.
- flashpan: clean but rejected; it doesn't read as what the tool does.
- linkopsy: runner-up; kept as a possible name for the report ("a linkopsy").
- burnervm: blocked by BunkerVM (Firecracker sandbox) near miss.

## Consequences
- Free on all checked surfaces as of 2026-10-10, including `urljail.com`, `.dev`, the GitHub handle, Go modules, crates, Homebrew, Docker Hub, distro repos, npm, PyPI.
- Trademark registers not searched (browser-only); do so before anything commercial.
- Tagline should counter the "blocks URLs" misreading: *detonate suspicious URLs in disposable microVMs*.
