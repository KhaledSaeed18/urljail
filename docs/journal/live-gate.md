# Live gate

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [live gate](../roadmap.md#live-gate-before-p6-next)
- Exit: every item on the roadmap's live-gate checklist done; live mode then starts only through its interlock.

## WireGuard egress (done with a local test peer; real VPN pending)

- **As designed in [ADR 0003](../decisions/0003-wireguard-netns-egress.md):** `wg0` is created in the host namespace (its encrypted UDP leaves through the host's network) and moved into `uj-egress`, where it holds the **only** default route. In live mode there is no link from the egress namespace to the host at all: with the tunnel down there is no route out. Configured over netlink (`wgctrl`), so `wireguard-tools` isn't needed. Input is a standard wg-quick file (`-wg-config`, must be `0600`).
- **Resolver in live mode** forwards to the VPN's DNS (from the config). A VPN's DNS is often private (Mullvad: `10.64.0.1`), so the egress output rules allow exactly those upstream addresses on the exit before the private-address drop.
- **Live interlock** (in the daemon, not convention): `-egress live` is refused while `/etc/sudoers.d/urljail-dev` exists, without a WireGuard config, or until the tunnel has a handshake; the daemon then runs its own isolation self-test and refuses to serve unless it passes. Every run's preflight requires a handshake under 3 minutes old (keepalive 25 s), exactly one default route via the exit, and the usual ruleset hashes.
- **Live self-test checks:** *VPN down ⇒ no egress* (the tunnel is really taken down; the guest must not reach a public IP; the tunnel is restored and must handshake again) and *public IP seen by the guest is the VPN exit* (the guest fetches `https://api.ipify.org`; the host asks the same from its own namespace; they must differ).
- **`-egress live-test`:** the same WireGuard path to a local peer in namespace `uj-testvpn`, which terminates the tunnel and NATs out through the host. Its exit IP is the home IP, so the URL policy stays the dev allowlist and the exit-IP check is skipped (it correctly saw guest and host both at `185.160.227.25`).

### Result in live-test mode

Startup self-test passed through the tunnel, including **VPN down ⇒ no egress: `connect: network is unreachable`** with the tunnel down; the egress namespace held only `lo` and `wg0`, with `default dev wg0`. Detonations ran through the tunnel (navigate 220 ms, reports consistent); a non-allowlisted URL was refused. Shutdown left no namespace, `wg0`, test-peer link or `DOCKER-USER` rule. Dev mode passed a regression run afterwards.

### Bugs found by the tunnel

- **MTU:** `wg0` has MTU 1420, the guest 1500, so the egress namespace sent ICMP "need to frag" for most connections. Path-MTU discovery coped here, but VPN paths often drop that ICMP. Clamping only outgoing SYNs (`rt mtu`) wasn't enough: the guest takes its segment size from the server's SYN-ACK. Now SYNs both ways across the exit are clamped to the exit MTU − 40 (1380 on WireGuard, 1460 on the dev exit): zero "need to frag" afterwards.
- **IP fragments counted as flows:** a run showed 365 flows, 345 of them to random ports. Non-first IP fragments carry no TCP/UDP header, and the BPF program read their payload as ports. It now skips L4 parsing for fragments: back to 23–25 flows.

## Running as a service (installed and verified 2026-10-12)

The dev sudoers rule has to go before live mode, and with it passwordless `sudo bin/urljaild`. Replacement: `deploy/urljaild.service` plus `scripts/install-daemon.sh` (run once with sudo, and again after each rebuild).

- **Root never executes operator-writable binaries:** in dev, the root daemon ran `bin/urljaild`, `~/.local/bin/jailer` and `~/.local/bin/firecracker`, all writable by the operator account, which made them root-equivalent like the sudoers rule. The script installs root-owned copies (`/usr/local/sbin/urljaild`, `/usr/local/libexec/urljail/{jailer,firecracker}`) and the policy module (`/usr/local/share/urljail/`); the unit runs only those. Settings live in `/etc/urljail/urljaild.env` (`0600`): operator, egress mode, extra flags such as `-wg-config /etc/urljail/wg0.conf`.
- **SELinux:** started by systemd, the daemon runs as `unconfined_service_t`, not `unconfined_t`, so the policy (1.2.0) defines the VMM transition from both. Without that, every run would have been refused by the per-run confinement check: failing closed, but unusable.
- **Verified as a service:** the daemon runs from `/usr/local/sbin` as `system_u:system_r:unconfined_service_t`; `doctor` healthy (SELinux enforcing, VMMs in `urljail_vmm_t`, zero denials); detonation (navigate ~210–290 ms, consistent report); self-test passes, with the VMM confined via the new transition from `unconfined_service_t`.

### Bug: a second daemon broke the first one's network

- When the service was first enabled, a dev daemon (started with sudo) was still running. The service crash-looped on "another urljaild is listening", but each attempt first ran its whole setup, which **deletes and rebuilds the namespaces**, breaking the running daemon's network on every restart. The socket check came far too late.
- **Fix:** an exclusive `flock` on `/run/urljail/urljaild.lock`, taken right after argument parsing and before anything is touched. Verified with the service holding it: a second daemon exits at once ("lock … held") and the service stays healthy.
- **My mistake while fixing it:** I tested the fix against the running service *before* the service had the fix. The old binary held no lock, so the test daemon took it, rebuilt the namespaces and wiped the service's egress namespace. The service failed closed (preflight refused runs: "egress ruleset changed or unreadable", no run directory) until the operator reinstalled and restarted it. Lesson: a mutual-exclusion fix protects nothing until both sides run it.

## Fuzzing (from the threat-model review)

Go native fuzz targets for every parser the root daemon runs on guest-controlled bytes (`make fuzz`, 30 s each by default): ClientHello, HTTP Host, segment reassembly, the report builder (guest events and done.json; host flows, DNS and blocked records, through to protojson marshalling), unbound's log, NFLOG packets, nft counters.

**Found:** `parseHTTPHost` lowercased the guest's `Host:` header after checking its length; `strings.ToLower` turns each invalid UTF-8 byte into U+FFFD (3 bytes), so junk passed and grew. Guest-supplied hostnames (Host and SNI) now pass only as DNS characters; anything else becomes `invalid:<hex of the first 32 bytes>`, kept as evidence. The crashing input stays in `testdata/fuzz/` as a regression test.

## First start in live mode (Proton VPN Free, US-FREE#61)

- The tunnel came up and the real exit checks passed: **guest public IP `149.88.25.131` (Proton) vs home `185.160.227.25`**; **VPN down ⇒ `network is unreachable`**. 20 of 21 self-test checks passed.
- **Bug, mine:** the check "Dev mode refuses a non-allowlisted URL" also ran in live mode, where allowing any public URL is the point, so live mode could never pass its interlock. The check is now mode-aware: in live mode it verifies that `file:`, `javascript:` and non-web ports are still refused.
- **Flaky free server:** one start's IP-echo request timed out. The exit-IP probe now waits 10 s and tries up to 3 times.
- **Crash loop:** each failed interlock exited 1 and systemd restarted it every 5 s (6 times in a minute), re-running the whole self-test each time. An interlock failure now exits with status 3 and the unit has `RestartPreventExitStatus=3`: it stays stopped and the journal says why.

## Checklist

| Item | State |
| ---- | ----- |
| WireGuard-in-netns egress working; `live` mode interlock in the daemon | done with the test peer; needs a run with the real VPN config |
| Full isolation test plan in `live` mode, incl. "VPN down ⇒ no egress" | passes in live-test; the exit-IP check needs the real VPN |
| Dev sudo rule removed | done 2026-10-12: `sudo -n` now asks for a password; `doctor` reports it gone; the service keeps working |
| Threat model reviewed against what was built | done ([review](../threat-model.md#review-against-the-built-system-2026-10-12)): one false claim corrected (downloads), diagram fixed, 8 new threats; adds "fuzz the root parsers" before live |
| Feed terms of use checked (Q13) | done: free feeds first (operator's decision) |
| Feed ingestion design, URLs strictly as data | done ([feed-ingestion.md](../feed-ingestion.md)): unprivileged `urljail feeds`, never in the root daemon |
| VPN config (Proton VPN Free, [ADR 0017](../decisions/0017-proton-vpn-free.md)) | pending (operator) |
