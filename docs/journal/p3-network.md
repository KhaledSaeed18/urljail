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
| M4 | eBPF (TCX) flow records + TLS ClientHello SNI/ALPN | |
| M5 | Host-side report sections, host/guest reconciliation, background-traffic labels, `urljail doctor` | |

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
