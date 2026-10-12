# Report schema (draft v0)

Status: **design draft**. `report.json` is *derived* from raw artifacts (see storage layout in [architecture.md](./architecture.md#storage-layout-per-run)) and can always be regenerated. Every observation carries its **source** so readers know who attests to it.

## Sources

| `source` | Meaning | Trust |
| -------- | ------- | ----- |
| `host.ebpf` | eBPF on the VM's TAP device | high (outside the guest) |
| `host.pcap` | packet capture (+ key log decryption) | high for metadata; payload decryption depends on guest-supplied keys |
| `host.dns` | our resolver's log | high |
| `host.fw` | nftables drop logs | high |
| `guest.cdp` | Chromium DevTools Protocol events | guest-attested |
| `guest.agent` | guest agent (screenshot, DOM) | guest-attested |

## Top-level shape

```jsonc
{
  "schema": "urljail.report/v0",
  "run": {
    "id": "019…",                       // UUIDv7
    "submitted_url": "https://…",
    "profile": "baseline",
    "egress": { "mode": "live", "exit": "wg:mullvad-de-fra-001" },
    "started_at": "…", "ended_at": "…",
    "status": "completed",               // completed | timeout | error | refused
    "versions": { "urljail": "…", "firecracker": "…", "guest_kernel": "…", "chromium": "…", "snapshot": "…" }
  },

  "navigation": {
    "final_url": "https://…",
    "redirect_chain": [
      { "url": "https://bit.ly/…", "status": 301, "kind": "http",   "source": "guest.cdp" },
      { "url": "https://…/land",   "status": 200, "kind": "js",     "source": "guest.cdp" }   // http | meta | js | client-hint
    ],
    "title": "…",
    "dwell_ms": 15000
  },

  "network": {
    "requests":  [ { "url": "…", "method": "GET", "type": "script", "status": 200, "remote_ip": "…", "bytes": 1234, "initiator": "…", "source": "guest.cdp" } ],
    "dns":       [ { "qname": "…", "qtype": "A", "answers": ["…"], "rcode": "NOERROR", "source": "host.dns" } ],
    "flows":     [ { "proto": "tcp", "dst_ip": "…", "dst_port": 443, "sni": "…", "alpn": ["h2"], "bytes_out": 0, "bytes_in": 0, "source": "host.ebpf" } ],
    "tls":       [ { "sni": "…", "version": "TLS1.3", "cert_subject": "…", "cert_issuer": "…", "not_before": "…", "source": "guest.cdp" } ],
    "blocked":   [ { "dst": "192.168.1.1:80", "reason": "private-destination", "count": 3, "source": "host.fw" } ],
    "domains":   [ "…" ]                    // union, de-duplicated, eTLD+1 grouped
  },

  "reconciliation": {
    // host vs guest views of the same traffic
    "host_only_flows":  [ /* seen leaving the VM but never reported by CDP */ ],
    "guest_only_requests": [ /* reported by CDP but never seen on the wire (cache, blocked, or lie) */ ],
    "consistent": true
  },

  "page": {
    "forms": [
      { "action": "https://…/post.php", "method": "POST", "cross_origin_action": true,
        "fields": [ { "name": "email", "type": "email" }, { "name": "pass", "type": "password" } ],
        "has_password": true, "source": "guest.cdp" }
    ],
    "dialogs": [], "console": [], "permission_requests": [],
    "downloads": [ { "sha256": "…", "size": 0, "mime": "…", "filename": "…" } ],
    "iframes": [], "service_workers": []
  },

  "artifacts": {
    "screenshot": "guest/screenshot.png",
    "dom": "guest/dom.html",
    "pcap": "host/capture.pcapng",
    "sslkeylog": "guest/sslkeys.log"
  },

  "indicators": [
    // simple, explainable heuristics, not verdicts
    { "id": "password-form-cross-origin", "severity": "high",   "evidence": ["page.forms[0]"] },
    { "id": "brand-mismatch",             "severity": "medium", "evidence": ["navigation.title", "navigation.final_url"] },
    { "id": "anti-bot-script",            "severity": "info",   "evidence": ["network.requests[12]"] }
  ],

  "gaps": [
    // what we could NOT observe, stated explicitly (design principle G4)
    "ECH disabled by policy; SNI reflects real hostname",
    "No interaction simulated; content behind click-gates not reached"
  ]
}
```

## Open schema questions

- ~~Source of truth~~: decided. Protobuf in `api/proto/`, `report.json` via protojson (`UseProtoNames`), JSON Schema generated from the proto ([ADR 0008](./decisions/0008-protobuf-report-schema.md)). This page stays the readable reference.
- HAR export for interop with existing tools (cheap to add from CDP events).
- Perceptual hash of screenshot (pHash) for visual similarity / brand matching later.
