# P3: Network layer

- Status: **in progress**
- Started: 2026-10-12
- Roadmap: [P3](../roadmap.md#p3-network-layer-next)
- Exit: isolation test plan passes in `dev` mode; reports contain DNS, flows, SNI, blocked attempts, reconciliation.

## Milestones

| # | Milestone | State |
| - | --------- | ----- |
| M1 | Root daemon ([ADR 0014](../decisions/0014-root-daemon-unprivileged-vmm.md)); per-VM + egress namespaces; nftables rulesets with hash check; unbound with rebind protection; per-run DNS log | done |
| M2 | Isolation test plan automated: `urljail selftest`, guest `Probe` RPC + host drop counters / DNS log | done |
| M3 | Blocked attempts from NFLOG (per packet); pcap via tcpdump; self-test requires per-destination evidence | done |
| M4 | eBPF (TCX) flow records + SNI/ALPN (and HTTP Host); host sections + reconciliation in the report | done |
| M5 | `urljail doctor`, reconciliation in the CLI summary, exit criterion | |

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

## M2 notes

- **`urljail selftest`** boots a VM (the shared `bootVM` path, so the test exercises exactly what detonations use) and asks the guest agent to `Probe`: TCP connects, a UDP datagram, and DNS lookups, all concurrently from inside the guest. The guest only reports what happened; the daemon judges.
- **Two-sided evidence per check:** the guest's outcome (e.g. `timeout`) plus host evidence: the nftables drop counter for that rule rising (`private`, `quic`, `other`, `input` in the egress namespace; `vm-input` in the VM namespace; rules now carry comments so `nft -j` counters can be read), or the probe's unique name appearing in the host DNS log. The self-test holds every VM slot, so nothing else moves the counters.
- **Rebind checks have a positive control:** `1.1.1.1.nip.io` must resolve, so a broken `nip.io` can't make `192.168.1.1.nip.io` / `127.0.0.1.nip.io` "pass" by not answering.
- **The host's own LAN is probed by discovery:** default gateway, the host's addresses on the default interface, Docker's bridge (`192.168.0.1`, `192.168.0.116`, `172.17.0.1` here).

### Result (dev mode, 2026-10-12): 16 pass, 0 fail, 2 skipped (live only)

| Check | Guest | Host |
| ----- | ----- | ---- |
| Public HTTPS (control) | connected | — |
| Public non-web port (1.1.1.1:22) | timeout | `other` +2 |
| Cloud metadata 169.254.169.254 | timeout | `private` |
| Another VM (10.200.1.2) | timeout | `private` |
| Host side of the exit (10.199.0.1) | timeout | `private` |
| Egress namespace itself | timeout | `input` +2 |
| VM namespace itself (172.16.0.1:22) | timeout | `vm-input` +2 |
| QUIC (UDP 443) | no reply | `quic` +1 |
| DNS sent to 8.8.8.8 | answered (NXDOMAIN) | name in host DNS log |
| Rebind control `1.1.1.1.nip.io` | resolved 1.1.1.1 | — |
| Rebind to RFC 1918 / loopback | no answer | — |
| Default gateway, host address, Docker bridge | timeout | `private` |
| Non-allowlisted URL in dev mode | — | refused by policy |

**Known weakness, to fix in M3:** the six `private` checks share one counter (all saw +12), so the host evidence is "private drops happened", not "this destination was dropped". Each still needs its own guest-side timeout, and an allowed probe would have connected or been refused instead, so it can't pass by accident; but M3's NFLOG listener sees each dropped packet's destination, and the checks should then require per-destination evidence.

## M3 notes

- **NFLOG, per packet:** the egress rules `log group 2`; the daemon opens the NFLOG netlink socket *inside* `uj-egress` (netlink sockets belong to a namespace: lock the OS thread, `setns`, open, `setns` back; a thread that can't switch back stays locked and is discarded). Each drop gives reason (from the log prefix), source, destination, protocol and port, routed by source (`10.200.<n>.2`) into the run's `host/blocked.jsonl`, capped at 20 000 records per run (the overflow is counted). Under a flood the netlink buffer can overflow (ENOBUFS): lines are lost, the drops still happen.
- **Self-test tightened:** every egress drop check now also needs its own destination and port in the blocked log with the right reason, fixing M2's shared-counter weakness. All checks pass with per-destination evidence (e.g. `private tcp 192.168.0.1:80`, `quic udp 1.1.1.1:443`).
- **pcap:** tcpdump in the VM namespace on `tap0`, started before the VM boots, writing raw packets only, after dropping to the operator (`-Z`), capped at 500 000 packets. example.com: 847 packets, 633 KB; the ClientHellos show SNI in clear (ECH is off by policy): `example.com` plus the Google hosts from the DNS log. tcpdump creates the file `0644`; teardown makes it `0600` like the rest of the run.
- **Not verified yet:** offline TLS decryption with the key log (no Wireshark/tshark on this host). The pieces are there (`host/capture.pcap` + `guest/sslkeys.log`).

## M4 notes

- **eBPF on the TAP** (`internal/capture`, C + bpf2go, cilium/ebpf v0.22.0, generated object committed): TCX ingress (guest → out) and egress (→ guest) on `tap0`, attached from inside the VM namespace (ifindexes are per namespace; same `setns` helper as NFLOG). It only observes: always `TCX_NEXT`. Per flow (oriented from the guest): packets, bytes, first/last seen, TCP flags. The first 4 outgoing data segments of each TCP flow go to a ring buffer; Go reassembles them by sequence number and parses the TLS ClientHello (SNI, ALPN) or, for plain HTTP, the `Host` header. Parsers are tested against real Go ClientHellos: whole, split out of order with a retransmission, truncated at every byte. Compiled with `-mcpu=v3` (the fetch-add needs `BPF_FETCH`).
- **Report:** new host sections `network.dns` (host.dns), `network.flows` (host.ebpf), `network.blocked` (host.fw, grouped by destination), and `reconciliation`. Each host flow gets a label: `page` (matches a guest request by remote address or SNI/Host), `browser-background` (known Chrome endpoint, `internal/report/background.go`, only when the page didn't request that host), `dns`, `no-data` (preconnects, dropped attempts, ICMP only received), or `unexplained`. A run is `consistent` when nothing is unexplained and every guest request that should have crossed the network was seen by the host. Host sections are reported even when the guest failed.
- **Result on example.com/.org:** consistent; 2–3 page flows (SNI `example.com`/`example.org`, ALPN `h2,http/1.1`), 7–12 browser-background flows, plain-HTTP `clients2.google.com` identified by its Host header.

### Bugs and findings

- **Teardown hung on the ring buffer** (left a root daemon wedged): a deadline set while `ringbuf.Reader.Read` is already blocked doesn't wake it. Reads now poll with a 200 ms deadline; closing the probe is bounded at 2 s (then the reader is closed); daemon shutdown waits at most 30 s for teardowns, and a second signal exits at once.
- **Orphaned unbound:** after the wedged daemon was killed, unbound kept running in the deleted egress namespace. Privilege-dropping children (unbound, tcpdump) lose their parent-death signal. Fix: before any urljail namespace is deleted, every process still in it is killed (`ip netns pids`), at start and at each VM teardown. Verified: the next start killed the orphan and rebuilt cleanly.
- **SNI empty at first:** Chrome 155's ClientHello (post-quantum key share) is 1729–1745 bytes and, with TSO/GSO, reaches the TAP as one packet larger than the MTU; the program copied only 1600 bytes. Now 4096 bytes, and the parser reads whatever extensions a truncated hello still has.
- **Home LAN address leaked to the guest (dev mode):** during an internet outage the host sent ICMP "host unreachable" for forwarded packets, sourced from its LAN address `192.168.0.116`, and the eBPF records showed them reaching the guest. A compromised guest (A3) could learn the home address. Fix: the egress namespace drops anything arriving from the exit with a private source, before the established/related accept (ICMP errors are "related"). Live mode doesn't route through the host, so it's dev-only, but the rule applies in both.
- **Flaky internet during the session:** the host lost its upstream twice. The self-test then failed only the checks that need the internet (every isolation check still passed). It now reports those as inconclusive when its public control fails (exit code 2), instead of an isolation failure; `doctor` (M5) checks the exit's connectivity directly.
