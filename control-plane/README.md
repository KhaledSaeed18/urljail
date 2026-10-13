# urljail control plane

Dashboard and orchestrator for urljail (P7, [ADR 0019](../docs/decisions/0019-control-plane-deployment.md)). Everything here runs as the operator, on 127.0.0.1; `urljaild` stays the only privileged component.

```
 browser ──► web (Next.js, :7800) ──token──► api (NestJS, :7801) ──gRPC unix socket──► urljaild (root)
                                              ├─ BullMQ queue ── Redis (:56379, rootless podman)
                                              ├─ runs + reports ── Postgres (:55432, rootless podman)
                                              └─ reads ~/.local/share/urljail/runs (operator-owned)
```

## Set up

```bash
cd control-plane/api && npm ci && npm run build && cd -
cd control-plane/web && npm ci && npm run build && cd -
control-plane/scripts/setup.sh
```

`setup.sh` (no root): creates the podman secrets and `~/.config/urljail/control-plane.env` (0600), installs Postgres and Redis as Quadlet units and the API and dashboard as systemd user services, and starts them. Open http://127.0.0.1:7800.

Re-running it rotates the API token and keeps the data. Logs: `journalctl --user -u urljail-api -u urljail-web -u urljail-postgres -u urljail-redis`.

## Security rules

- **Localhost only**: every listener binds 127.0.0.1; both the API and the dashboard refuse requests whose `Host` isn't `127.0.0.1` or `localhost` (DNS rebinding).
- **Token**: every API call needs `Authorization: Bearer $URLJAIL_API_TOKEN`. Only the dashboard's server holds it; submissions go through a Server Action, which checks the request's origin.
- **Hostile data stays inert**: titles, URLs, redirect chains and gaps are rendered as text; captured URLs are shown, never linked; the captured DOM is never rendered; screenshots are served only after a PNG signature check, as `image/png` with `nosniff`; the CSP allows nothing from other origins.
- **No automatic retries**: a detonation is a visit to a live site, repeated only on purpose.
