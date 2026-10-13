# Threat model

Status: **reviewed against the built system on 2026-10-12** (live gate); see [the review](#review-against-the-built-system-2026-10-12) at the end. Revisit when any layer changes.

urljail deliberately loads hostile content. The question isn't *whether* the guest gets attacked but how many layers must fail before something we care about is hurt.

## Assets

| Asset | Why it matters |
| ----- | -------------- |
| **Host machine** | Operator's daily laptop: files, SSH keys, browser sessions, tokens |
| **Home LAN** | Router admin, other devices, printers, NAS |
| **Home IP reputation** | Detonations from it get it blocklisted and tip off phishing operators |
| **Evidence integrity** | A report the attacker can forge is worse than no report |
| **Other runs** | One run must not see or influence another |
| **Operator credentials** | Must never be typed into or reachable by a detonated page |

## Adversaries

| ID | Adversary | Capability |
| -- | --------- | ---------- |
| A1 | Phishing kit / ordinary malicious page | JS in the browser sandbox: fingerprinting, redirects, cloaking, fetches |
| A2 | Page exploiting the browser | Code execution in a Chromium renderer, possibly escaping to browser process (guest user) |
| A3 | Guest root | Full control of the guest kernel: can lie over vsock, craft packets, tamper with artifacts before upload |
| A4 | VMM escape | Exploit in Firecracker's device emulation → code execution as the jailed VMM process on the host |
| A5 | Operator error | Running live URLs without the VPN, a misloaded firewall, leaked VMs |

## Layers (from page outward)

```
 page JS ─► Chromium sandbox ─► guest user ─► guest kernel ─► KVM + Firecracker (minimal devices, rate limits)
        ─► jailer (chroot, per-slot uid, own mount/PID/net namespace, cgroup v2 limits, seccomp)
        ─► SELinux urljail_vmm_t (enforcing)
 network: guest ─► VM netns (DNAT DNS, forward only to egress) ─► egress netns (nftables, resolver,
          WireGuard as the only route in live mode); the host's own namespace holds no urljail policy
```

## Threats and mitigations

| Threat | Adversary | Mitigation | Residual risk |
| ------ | --------- | ---------- | ------------- |
| Page scans/attacks LAN | A1 | nftables blocks all private/link-local destinations; DNS rebind protection | Bug in ruleset → isolation tests + `doctor` hash check |
| Page attacks guest-local services via DNS rebinding to 127.0.0.1 | A1 | Resolver refuses loopback answers; CDP over pipe, no TCP debug port; no other listeners in guest | Low |
| Guest learns the home LAN address | A3 | In dev mode the host's ICMP errors for forwarded packets carry its LAN address (found in P3); the egress namespace drops anything from the exit with a private source | Dev mode only; live mode doesn't route through the host |
| Detonation leaks home IP | A1, A5 | WireGuard-in-netns fails closed; daemon interlock refuses live URLs without healthy tunnel; DNS upstream also via VPN | VPN provider sees traffic (accepted) |
| Browser exploit → guest compromise | A2 | Disposable VM per URL; nothing persistent; patched Chromium in image | Expected to happen eventually; contained by VM |
| Guest lies in report | A3 | Host-side capture (pcap, eBPF, resolver) is independent; report marks guest-only claims; host/guest diff flagged | Guest can still fake screenshot/DOM: labeled "guest-attested" |
| Guest floods host (CPU, disk, vsock) | A3 | cgroup v2 CPU/memory/pids limits via the jailer; Firecracker rate limiters on net/block, read back and verified on every run; per-run caps on artifacts, events, host records and pcap bytes; wall-clock kill (see [P5 journal](./journal/p5-hardening.md#every-cap-per-run-as-of-p5)) | Low; run directories accumulate until retention (P7) |
| VMM escape | A4 | Firecracker's minimal device model; every VMM jailed ([ADR 0016](./decisions/0016-every-vmm-jailed.md)): chroot with only its own files, own mount and PID namespace (PID 1), per-slot uid 64000+ with no capabilities and NoNewPrivs, cgroup memory/pids/cpu limits, seccomp filters; SELinux: confined in `urljail_vmm_t` (enforcing; may touch only its jail, read images/snapshots, append to its console); keep Firecracker updated | Low probability, high impact |
| Cross-run contamination | A1–A3 | Fresh clone per run; separate netns; snapshot taken pre-network (no shared cookies/caches) | Identical RNG state across clones: see [research/snapshot-entropy.md](./research/snapshot-entropy.md) |
| Credentials typed into phishing page | A5 | Detonation never types real credentials; form interaction (if ever) uses generated canary values only | — |
| Malicious download executed | A1 | Downloads land on a `noexec` tmpfs in the guest (`/run/urljail/downloads`) and are destroyed with the VM; the report lists them from CDP. They are **not** collected or hashed yet | — |
| Leaked VM keeps running | A5 | Teardown always runs (each step with its own deadline; shutdown bounded); daemon reaps orphan VMMs and namespaces at startup, killing every process still inside a urljail namespace first (privilege-dropping children like unbound and tcpdump outlive a killed daemon, found in P3); `doctor` lists leftovers. VMMs are tracked by pidfd | — |
| Any process running as the operator gains root through the dev sudo rule | A5 | `/etc/sudoers.d/urljail-dev` grants NOPASSWD `ip`, `firewall-cmd`, `nft`, `sysctl` and (from P3) the user-writable `bin/urljaild` for development; each is root-equivalent. Remove it before the live gate; `urljaild` becomes the single privileged component instead | Accepted for P1–P5 on this laptop only |

## Explicitly out of scope (v1)

- Attackers with physical access to the laptop.
- Firecracker/KVM 0-days beyond keeping versions current.
- Protecting the VPN provider relationship (they see exit traffic by design).
- Side channels between co-resident VMs (Spectre-class); acceptable for a single-operator tool.

## Operating rules

1. `live` mode only after all tests in [network.md → Isolation test plan](./network.md#isolation-test-plan-must-pass-before-live-mode-is-enabled) pass.
2. Never detonate on a machine holding something you can't afford to lose without reconsidering layer by layer. (This laptop qualifies only because of the layers above; revisit if any is weakened.)
3. Feeds are untrusted input: URLs from feeds are data, never shell arguments.
4. Keep Firecracker, guest kernel and Chromium updated; record versions in every run's `meta.json`.
5. No passwordless sudo rule survives the live gate: `/etc/sudoers.d/urljail-dev` is a development convenience only.

## Review against the built system (2026-10-12)

Each threat above, against what exists after P1–P5 and the live-gate work. *Verified* means tested on this host with the evidence named; *built* means implemented but not exercised end to end.

| Threat | State | Evidence |
| ------ | ----- | -------- |
| Page scans/attacks LAN | verified | Self-test: router, host address, Docker bridge, metadata, other VMs, the exit's host side, the namespaces themselves: each dropped, with the exact destination in the host's blocked log (P3 M3) |
| DNS rebinding to loopback / private | verified | Self-test with a positive control (`1.1.1.1.nip.io` resolves; `127.0.0.1.nip.io`, `192.168.1.1.nip.io` don't); CDP over a pipe, no debug port |
| Guest learns the home LAN address | fixed, dev only | Found in P3 (host ICMP errors); the exit drops private-source packets |
| Detonation leaks home IP | verified (live) | `wg0` is the only route in live mode; with Proton VPN Free the guest's public IP was `149.88.25.131`, the home IP `185.160.227.25`; *VPN down ⇒ no egress* passed (`network is unreachable`); the interlock refuses live without handshake / passing self-test / with the dev sudo rule |
| Browser exploit → guest compromise | built | Disposable clone per run; Chrome sandboxed (uid 1000, namespaces, seccomp in the guest); Chrome pinned and rebuilt per release |
| Guest lies in report | verified | Host-attested DNS, flows (SNI/ALPN/Host), blocked attempts and pcap, reconciled against CDP per run; `consistent` flag; screenshot/DOM labeled guest-attested |
| Guest floods host | verified | cgroup limits read on a live VMM; rate limits read back from the VMM on every run (fail closed); caps table in the P5 journal |
| VMM escape | verified | Every run checks its VMM's uid, NoNewPrivs, seccomp, cgroup, chroot and `urljail_vmm_t` and refuses otherwise; `doctor` flags any unjailed Firecracker on the host (negative test passed); SELinux enforcing, zero denials |
| Cross-run contamination | verified (kernel), open (userspace) | Fresh reflinked disk and namespace per run; snapshot built with no network; VMGenID reseed logged per clone; 25/25 distinct ClientHello randoms across 3 clones; Chrome's userspace RNG state is cloned (R2) |
| Credentials typed into a page | holds | No interaction is simulated at all |
| Malicious download executed | holds | `noexec` in the guest, destroyed with the VM (claim above corrected: not collected) |
| Leaked VM keeps running | built | Teardown bounded per step; startup reaping kills everything in urljail namespaces and cgroups; VM cgroups under the service's own, so a daemon crash takes them along (closed 2026-10-13: VMMs verified in the service's cgroup, [P5 journal](./journal/p5-hardening.md#follow-ups-from-the-threat-model-2026-10-13)) |
| Dev sudo rule | removed (2026-10-12) | urljaild runs as a systemd service from root-owned binaries; live mode would refuse to start if the rule came back |

### New threats found while building

| Threat | Adversary | Current mitigation | Recommendation |
| ------ | --------- | ------------------ | -------------- |
| **The root daemon parses guest-controlled data**: the gRPC/HTTP2 stream over vsock, CDP event JSON, artifacts, ClientHello and HTTP bytes from eBPF, and the report built from all of it | A3 | Go (memory-safe); artifact name allowlist; size, count and record caps; tolerant parsers that skip bad input; **fuzzed** (`make fuzz`). **The report (the largest parser: CDP events, DOM, host records) is built by an unprivileged child** (`urljaild __build-report`, 2026-10-13): the operator's uid, no_new_privs, memory, file and output caps, 60 s limit, after the run directory is handed to the operator | Still in the root daemon: the vsock gRPC stream, artifact intake, eBPF ClientHello/Host parsing (fuzzed) |
| **unbound parses attacker-controlled DNS answers** (a phishing domain's own nameservers) | A1 | Runs as user `unbound` in the egress namespace, forwarding only; **started in SELinux's `named_t`** (Fedora's resolver domain) when the daemon runs as the service, config in its own type `urljail_dns_conf_t`; the daemon refuses to start if unbound isn't in `named_t`; `doctor` reports its domain and `named_t` denials (2026-10-13) | Development runs (sudo) leave it unconfined |
| **Root executing operator-writable binaries** (`bin/urljaild`, `~/.local/bin/{jailer,firecracker}`) | A5 | Resolved: the service runs root-owned copies only | — |
| **Daemon crash leaves live VMs browsing** | A5 | **VM cgroups live under the service's own cgroup** (`Delegate=cpu memory pids`; the daemon moves itself into a `daemon/` leaf, VMs go under `vms/`), so a stop or a crash kills every VMM with the daemon (2026-10-13); restart also reaps leftovers | Development runs keep `/sys/fs/cgroup/urljail` |
| **Agent and Chrome share a uid in the guest** | A2 | Host treats all guest output as guest-attested | **Later:** separate uid for Chrome |
| **live-test exits from the home IP** | A5 | URL policy stays the dev allowlist in live-test | — |
| **Images and snapshots are operator-writable** | A5 | Operator is trusted; the root daemon only reflinks and links them; VMMs can't write them (DAC and SELinux) | Accepted (single operator) |
| **WireGuard private key on disk** | — | Live mode refuses a config not `0600` | — |

### Before enabling live mode

1. ~~Install the daemon as a service from root-owned binaries, then delete `/etc/sudoers.d/urljail-dev`~~ done.
2. A real VPN config; the self-test's exit-IP check must pass (the daemon enforces this at start).
3. ~~Fuzz the parsers that run as root on guest data~~ done (`make fuzz`); rerun after parser changes.
4. Feed terms decided (Q13) and ingestion designed with URLs strictly as data.
5. Re-read this table if any layer changes.
