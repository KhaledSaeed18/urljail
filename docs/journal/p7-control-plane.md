# P7: control plane

Status: **in progress** (started 2026-10-13)

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
- **Open item (guest coverage):** www.bbc.com's report was "not consistent" over one DNS lookup, `logx.optimizely.com`, that appears nowhere in the guest's CDP events or DOM. The guest agent enables the Network domain on the page's own session only, so requests from web workers (and, likely, out-of-process iframes) are invisible to it while the host still sees them. Built: the page session auto-attaches (paused, flattened) to workers and out-of-process iframes; each gets the Network domain and auto-attach for its own children, then is released (always, even if setup failed, so a page can't be left frozen). Only Network, never `Runtime.enable`. Needs the new image; verification after the next daemon restart.

