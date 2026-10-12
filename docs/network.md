# Network design

Status: **design draft**. This is the most safety-critical part of urljail. Read with [threat-model.md](./threat-model.md).

## Goals

1. A detonated page can reach **the public internet on TCP 80/443 only**, through a controlled exit.
2. It can **never** reach the host, the LAN, link-local/metadata addresses, or other VMs.
3. It can **never** egress from the operator's home IP when running live (untrusted) URLs.
4. DNS goes **only** to our resolver, which logs everything and refuses private answers.
5. Every packet is observable on the host, independent of the guest.

## Topology

```
 ┌─ netns: uj-vm-<id> (one per VM; identical inside for every clone) ─┐
 │                                                                    │
 │   guest eth0 172.16.0.2/30 ◄──► tap0 172.16.0.1/30                 │
 │                                   │   ▲ eBPF (TCX ingress+egress)  │
 │                                   │   │ + pcap                     │
 │                     SNAT 172.16.0.2 → 10.200.<n>.2                 │
 │                     DNAT udp/tcp 53 → resolver                     │
 │                                   │                                │
 │                           veth-vm 10.200.<n>.2/30                  │
 └───────────────────────────────────┼────────────────────────────────┘
                                     │
 ┌─ netns: uj-egress (one, shared) ──┼────────────────────────────────┐
 │                           veth-eg-<n> 10.200.<n>.1/30              │
 │                                   │                                │
 │   nftables: allowlist + blocklist (below)                          │
 │   unbound resolver (logs, rebind protection)                       │
 │                                   │                                │
 │                 live mode: wg0 (default route) ── masquerade        │
 │                 dev mode:  veth-host ── to host NAT (benign URLs)  │
 └───────────────────────────────────┼────────────────────────────────┘
                                     │  encrypted WireGuard UDP
 ═══════════════ host netns ═════════╪════════ Wi-Fi ══► VPN provider ══► internet
```

### Why every clone is identical inside
A snapshot captures the guest's network config. Every clone restored from it expects the **same** TAP name, guest IP and MAC. Running each clone in its own netns lets them all be `172.16.0.2` behind `tap0`, while SNAT to a unique `10.200.<n>.2` gives each run a distinct identity outside (this is the pattern in Firecracker's `snapshotting/network-for-clones.md`, confirmed for v1.17.0).

### Why WireGuard lives in a netns
Create `wg0` in the host namespace, then move it into `uj-egress`. WireGuard keeps its UDP socket in the namespace it was **created** in, so encrypted packets leave via the host's Wi-Fi, while the plaintext interface (and the only default route) exists only inside `uj-egress`.

**Fail-closed property:** if the tunnel is down, `uj-egress` has no route to the internet at all. There is no fallback path to the home IP, not as a firewall rule that could be forgotten but as an absence of routing.

## As built (P3)

The topology above is implemented in `internal/netns` ([ADR 0014](./decisions/0014-root-daemon-unprivileged-vmm.md): the daemon is root, each Firecracker runs as the operator inside its VM namespace).

- **VM namespace `uj-vm-<n>`:** `tap0 172.16.0.1/30` (guest `172.16.0.2`, MAC `06:00:AC:10:00:02`, identical for every VM), `veth-vm 10.200.<n>.2/30`. Ruleset (`table ip urljail`): DNAT any TCP/UDP 53 from `tap0` to the resolver at `10.200.<n>.1`, masquerade out `veth-vm`, input drop (the guest can't reach the namespace itself), forward only `tap0 → veth-vm`. IPv6 disabled by sysctl.
- **Egress namespace `uj-egress`:** `veth-eg-<n> 10.200.<n>.1/30` per VM; dev exit `eg-host 10.199.0.2/30` to the host's `uj-host 10.199.0.1/30`, the only default route. Ruleset (`table inet urljail`): forward drop by default; established first; `@private4` dropped and logged; UDP 443 dropped and logged; TCP 80/443 to the exit accepted; everything else logged and dropped. Input accepts only DNS from `10.200.0.0/16`. Output allows the resolver's upstream (53/853) to the exit and nothing private. Drops log to NFLOG group 2.
- **Resolver:** unbound (Fedora 1.26.1) in `uj-egress`, forwarding to `1.1.1.1`/`9.9.9.9` through the exit, rebind protection via `private-address`, `log-replies` on stderr; the daemon routes each reply to the run whose VM asked (`10.200.<n>.2`) into `host/dns.jsonl`. No DNSSEC validation yet (`module-config: iterator`); answers aren't logged (only name, type, rcode).
- **Load and verify:** each ruleset is checked with `nft -c -f -`, loaded with `nft -f -`, then hashed from `nft -s list ruleset`. Every run re-hashes both and checks the resolver is alive; any difference refuses the run (tested by flushing the egress ruleset by hand: refused in 4 ms, no VM, no run directory).
- **Dev exit on the host:** `uj-host` in firewalld's `trusted` zone, masquerade on the default zone, and two tagged `DOCKER-USER` accepts. The host only ever receives what the egress namespace already allowed.
- **Teardown:** deleting a VM namespace destroys its TAP and both veth ends; daemon shutdown deletes `uj-egress` (and with it `uj-host`) and removes the host-side rules. Leftover namespaces from a crashed daemon are deleted at start.

### Live exit (as built, live gate)

`wg0` created in the host namespace, moved into `uj-egress`, configured over netlink; the only default route there is `default dev wg0`, and there is no link to the host. The resolver forwards to the VPN's DNS, allowed by exact address on the exit. SYNs across the exit are MSS-clamped to its MTU − 40 (1380 on WireGuard). `-egress live-test` runs the same path to a local peer (`uj-testvpn`) for testing. Interlock and checks: [live-gate journal](./journal/live-gate.md).

## Egress modes

| Mode | Route out | Allowed URL sources | Purpose |
| ---- | --------- | ------------------- | ------- |
| `off` | none | — | default; nothing leaves |
| `dev` | host NAT via physical interface | **allowlisted benign domains only** (example.com, test pages we host) | Phases 1–5, development |
| `live-test` | `wg0` to a local test peer, which exits through the host | allowlisted benign domains only | Testing the live exit without a VPN account |
| `live` | `wg0` only | anything, including phishing feeds | Phase 6+, real detonations |

`urljaild` refuses to detonate a non-allowlisted URL unless mode is `live` **and** `wg0` is up with a recent handshake. This interlock is code, not convention.

## nftables policy (egress netns)

Default **drop** on forward. Order matters: blocklist first, then allowlist.

The daemon generates the ruleset as a single `nft -f` file. It validates it with `nft -c -f`, applies it atomically, and records its hash; preflight refuses runs if the loaded ruleset's hash doesn't match. The file is readable and diffable as an artifact. The google/nftables library is only worth it if incremental per-VM updates become necessary.

```
# --- always drop (destination) ---
10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16      # RFC1918 (home LAN, Docker, our own nets)
100.64.0.0/10                                  # CGNAT
127.0.0.0/8, 0.0.0.0/8                         # loopback / this-network
169.254.0.0/16                                 # link-local, cloud metadata
224.0.0.0/4, 240.0.0.0/4, 255.255.255.255      # multicast, reserved, broadcast
::1, fc00::/7, fe80::/10, ff00::/8             # IPv6 loopback, ULA, link-local, multicast
# (IPv6: give guests no IPv6 at all in v1. In P1 the CI guest brought up an fe80:: link-local address
#  on eth0 by default, so disable it in the guest image, e.g. net.ipv6.conf.all.disable_ipv6=1)

# --- allow ---
tcp dport {80, 443}  → out (via wg0 in live mode)
udp/tcp 53           → only to local unbound (DNAT'd in vm netns); never to the internet

# --- explicitly drop ---
udp dport 443        # QUIC: forces TCP fallback so SNI/TLS stays observable
everything else      # log + drop (counters feed the report: "page attempted X")
```

Inter-VM traffic: each VM's veth is a separate /30 and forward between `veth-eg-*` interfaces is dropped.

Docker on this host installs its own iptables-nft rules and sets the FORWARD policy to DROP in the **host** namespace, and **those rules stay loaded after Docker is stopped** (found in P1). firewalld also filters host forwarding. Each namespace has its own netfilter hooks, so traffic between the VM netns and `uj-egress` never meets either. Exits differ:

- **`live`:** WireGuard's encrypted UDP comes from a socket in the host namespace, so it crosses the host's **OUTPUT** hook, not FORWARD. Docker's FORWARD drop doesn't apply.
- **`dev`:** traffic routed out through the host namespace is **forwarded** there, so it meets Docker's FORWARD chain and firewalld exactly as in P1. Needs the same `DOCKER-USER` accept rules (tagged, removed on teardown) or masquerading inside `uj-egress` onto a host-side veth that firewalld trusts.

`urljail doctor` reports Docker's tables (even with the service stopped), firewalld's state and zones, and the effective forward policies.

## DNS

- `unbound` runs inside `uj-egress`, upstream over the same exit (wg0 in live mode, so lookups don't leak from the home IP either).
- Every guest query is DNAT'd to it, regardless of which server the guest asked for.
- **Rebind protection:** `private-address:` for all RFC1918, loopback, ULA and link-local ranges, so a public name resolving to a private address returns nothing.
  - For LAN targets this is defense in depth: nftables already drops the packets.
  - For **loopback it is the only defense**: a name rebinding to `127.0.0.1` targets the guest's *own* loopback, which never crosses the host firewall. That is where Chromium's debugging endpoint would live, so a page could take over the browser and tamper with evidence. Hence: refuse loopback answers here, **and** drive Chromium over `--remote-debugging-pipe` instead of a TCP port (see [guest-image.md](./guest-image.md)).
- Logs: query name, type, answer, timestamp, attributed to a run via the source veth IP.
- Chromium: DoH disabled by policy (otherwise DNS hides inside HTTPS to 1.1.1.1/8.8.8.8).

## Host-side capture

| Tap point | What | How |
| --------- | ---- | --- |
| `tap0` in VM netns | full pcap | `tcpdump -i tap0 -s 0 -U -w host/capture.pcap -Z <operator> -c 500000` inside the VM netns, started before the VM boots (the daemon waits for "listening"). Writes raw packets only, no dissection. Decrypt offline: `wireshark -o tls.keylog_file:guest/sslkeys.log host/capture.pcap` |
| `tap0` TCX ingress/egress | flow records: 5-tuple, bytes, packets, first/last seen, TCP flags; TLS ClientHello SNI + ALPN, or HTTP Host | eBPF (`internal/capture`: cilium/ebpf, TCX attached inside the VM namespace, observe-only). First 4 outgoing data segments per TCP flow (up to 4 KiB each, since GSO hands over >MTU packets) → ring buffer → reassembled and parsed in Go → `host/flows.jsonl` |
| unbound | DNS queries/answers | log stream |
| nftables | dropped-packet counters/logs | `log group 2` → NFLOG socket opened inside `uj-egress` (setns on a locked thread) → per-packet reason/src/dst/port, routed by source to `host/blocked.jsonl` (capped at 20 000 per run). Commented rules give per-reason counters |

Decryption: Chromium writes `SSLKEYLOGFILE` in the guest; the guest agent ships it back; pcap + key log decrypt offline in Wireshark/tshark. No MITM proxy, so the server sees Chrome's real TLS fingerprint (see [ADR 0004](./decisions/0004-sslkeylog-instead-of-mitm.md)).

### Why bother with eBPF when CDP sees requests?
CDP is the browser's own account. eBPF on the TAP sees what *actually left the VM*: service-worker traffic, prefetch, anything the browser doesn't report, and anything a compromised guest would hide. The report diffs the two views; mismatches are flagged.

## Isolation test plan (must pass before `live` mode is enabled)

Automated from P3: `urljail selftest` boots a VM and runs these from inside it (guest agent `Probe` RPC); each check needs the guest's outcome **and** host evidence (the matching drop counter rising, or the query in the host DNS log). The self-test takes every VM slot, so counters can only move because of it. Results go to `runs/<id>/selftest.json`. Rows marked *live* are skipped in `dev` mode.


| Test | Expected |
| ---- | -------- |
| Guest → `192.168.1.1` (router), host LAN IP, `10.x` Docker bridge | dropped, logged |
| Guest → `169.254.169.254` | dropped |
| Guest → other VM's `10.200.<m>.2` | dropped |
| Guest DNS to `8.8.8.8:53` | answered by our unbound (DNAT), logged |
| Name resolving to RFC1918 (test record) | empty answer |
| Guest → UDP 443 | dropped |
| `wg0` down, guest → any public IP | no route; detonation refused at preflight |
| Live-feed URL in `dev` mode | refused by daemon |
| Public IP seen by guest (`ifconfig.me` in live mode) | VPN exit IP, never home IP |
