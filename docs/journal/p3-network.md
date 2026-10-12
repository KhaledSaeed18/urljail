# P3: Network layer

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P3](../roadmap.md#p3-network-layer-next)
- Exit: isolation test plan passes in `dev` mode; reports contain DNS, flows, SNI, blocked attempts, reconciliation.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Root daemon ([ADR 0014](../decisions/0014-root-daemon-unprivileged-vmm.md)); per-VM + egress namespaces; nftables rulesets with hash check; unbound with rebind protection; per-run DNS log | done |
| M2 | Isolation test plan, automated through guest probes | |
| M3 | eBPF (TCX) flow + TLS SNI/ALPN capture; pcap; blocked attempts from NFLOG | |
| M4 | Host-side report sections, host/guest reconciliation, background-traffic labels, `urljail doctor` | |

## M1 notes

- **Privileges:** the daemon is root; Firecracker runs via `ip netns exec <ns> setpriv --reuid --regid --clear-groups --no-new-privs`. Checked during a run: Firecracker is a direct child of the daemon, uid 1000, no groups, `CapEff 0`, `NoNewPrivs 1`, in `uj-vm-0`. Run directories, logs and the socket are the operator's.
- **Setup needed once:** `sudo dnf install unbound` (1.26.1; the system `unbound.service` stays disabled), and `bin/urljaild` added to the dev sudoers drop-in.
- **Topology as built:** see [network.md → As built](../network.md#as-built-p3).
- **Fail closed, tested:** flushing the egress ruleset by hand made the next run fail at preflight in 4 ms ("egress ruleset changed", hash of an empty ruleset), with no VM and no run directory.
- **Clean shutdown, tested:** SIGTERM to the daemon removed `uj-egress`, `uj-host`, unbound, the `DOCKER-USER` rules, the `trusted` binding and the masquerade it had added.
- **Timing:** example.com in 9.3–9.6 s, slightly faster than P2's host networking (TAP setup no longer goes through firewalld per run).

### Finding: the browser's own traffic, seen only by the host

The first host-side DNS log showed what CDP never did: besides `example.com`, Chrome looked up `redirector.gvt1.com`, `edgedl.me.gvt1.com`, `clients2.google.com`, `update.googleapis.com`, `accounts.google.com`, `www.google.com`, `android.clients.google.com` and `mtalk.google.com` during a single run, despite `--disable-background-networking`. These are browser-internal requests (component updater, sign-in, GCM), which the page's `Network` domain doesn't report. This is exactly what the two-witness design (G2) is for.

Adding the `ComponentUpdatesEnabled: false` policy cut it from 11 to 8 names; the rest is what real Chrome does. Decision: keep the policy, and label known browser-background destinations in the report (M4) instead of trying to hide them.
