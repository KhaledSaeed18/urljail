# Threat model

Status: **design draft**. Revisit before enabling `live` egress mode.

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
 page JS ─► Chromium sandbox ─► guest user ─► guest kernel ─► KVM + Firecracker (minimal devices)
        ─► jailer (chroot, unprivileged uid, cgroup v2 limits, seccomp, own netns)
        ─► SELinux (enforcing) ─► host netns policy (nftables) ─► egress netns (VPN only)
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
| Guest floods host (CPU, disk, vsock) | A3 | cgroup v2 CPU/memory/pids limits via jailer; Firecracker rate limiters on net/block; per-run artifact size caps; wall-clock kill | Low |
| VMM escape | A4 | Firecracker's minimal device model; every VMM jailed ([ADR 0016](./decisions/0016-every-vmm-jailed.md)): chroot with only its own files, own mount and PID namespace (PID 1), per-slot uid 64000+ with no capabilities and NoNewPrivs, cgroup memory/pids/cpu limits, seccomp filters; SELinux (see P5); keep Firecracker updated | Low probability, high impact |
| Cross-run contamination | A1–A3 | Fresh clone per run; separate netns; snapshot taken pre-network (no shared cookies/caches) | Identical RNG state across clones: see [research/snapshot-entropy.md](./research/snapshot-entropy.md) |
| Credentials typed into phishing page | A5 | Detonation never types real credentials; form interaction (if ever) uses generated canary values only | — |
| Malicious download executed | A1 | Downloads hashed and stored, never executed; stored outside any exec path, `noexec` mount | — |
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
