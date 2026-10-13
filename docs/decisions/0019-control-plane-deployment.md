# 0019: Control plane runs unprivileged, on localhost, behind a token

- Status: Accepted
- Date: 2026-10-13
- Builds on: [0005](./0005-cli-first-control-plane-last.md) (NestJS + Postgres + BullMQ + Next.js, last)

## Context
P7 adds a web dashboard and an orchestrator. It is the first urljail component with a network listener, and it displays data chosen by attackers: page titles, URLs, redirect chains, screenshots. The daemon must stay the only privileged component (P7 exit criterion).

## Decision
- **Everything runs as the operator.** Postgres and Redis in rootless podman containers as systemd user services (Quadlet); the NestJS API and the Next.js dashboard as systemd user services. No sudo to install or run. The API reaches `urljaild` over its existing Unix socket, as the CLI does, and reads run directories, which the operator owns.
- **Localhost only.** Every listener binds 127.0.0.1: Postgres 55432, Redis 56379, API 7801, dashboard 7800. Secrets (database and Redis passwords) are podman secrets; the API token and connection strings live in `~/.config/urljail/control-plane.env` (0600).
- **A token on the API.** Every API request needs `Authorization: Bearer <token>`: other local processes, and web pages in the operator's own browser (CSRF, DNS rebinding), can't submit URLs or read reports. The dashboard's server holds the token and calls the API itself; the browser never sees it. The dashboard rejects requests whose `Host` isn't `localhost`/`127.0.0.1` (rebinding) and cross-origin form posts.
- **Hostile data is never active.** Report text is rendered as text (React escaping, no raw HTML anywhere); captured URLs are shown, never linked, so the operator can't open a phishing page by accident; the captured DOM is never rendered (offered as a `text/plain` download at most); screenshots are served only after checking the PNG signature, as `image/png` with `nosniff`; a strict Content-Security-Policy allows nothing from other origins.
- **Postgres holds runs and reports; files stay where they are.** Run directories remain the evidence; Postgres stores the submission, the run state from the daemon's stream, and the report (JSONB) for listing and search. Retention ([P7 M1](../journal/p7-control-plane.md#m1-retention)) stays file-based.

## Alternatives considered
- **Run the control plane in containers too:** more isolation for Node, but it then needs the daemon's socket and the run directories mounted in, and gains little over a localhost user service. Possible later.
- **No token (localhost is enough):** any web page the operator visits could POST to `127.0.0.1:7801`.

## Consequences
- Single operator, single machine; not exposed to a LAN.
- Losing the token file means re-running `control-plane/scripts/setup.sh`, which rotates it.
