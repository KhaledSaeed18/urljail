package netns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
)

// LogGroup is the NFLOG group the rulesets log dropped packets to ("blocked attempts").
const LogGroup = 2

// egressRules is the policy of the egress namespace (docs/network.md#nftables-policy-egress-netns).
// Order matters: established traffic, then the private blocklist, then the allowlist.
var egressRules = template.Must(template.New("egress").Parse(`flush ruleset
table inet urljail {
	# Never reachable from a VM: RFC 1918, CGNAT, loopback, link-local and cloud metadata,
	# documentation, benchmarking, multicast, reserved and broadcast.
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
			172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16,
			198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		# The resolver, for VMs (their DNS is DNAT'd here in their own namespace).
		iifname "veth-eg-*" ip saddr 10.200.0.0/16 meta l4proto { tcp, udp } th dport 53 accept
		iifname "veth-eg-*" log prefix "uj input " group {{.LogGroup}} counter drop comment "input"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		# Nothing from the internet has a private source. In dev mode the host's own ICMP errors
		# do (they'd tell a guest the home LAN address, found in P3), and they're "related", so
		# this comes before the established/related accept.
		iifname "{{.Exit}}" ip saddr @private4 counter drop comment "exit-private-src"
		ct state established,related accept
		iifname "veth-eg-*" ip daddr @private4 log prefix "uj private " group {{.LogGroup}} counter drop comment "private"
		# QUIC: forces TCP so SNI and TLS stay observable.
		iifname "veth-eg-*" udp dport 443 log prefix "uj quic " group {{.LogGroup}} counter drop comment "quic"
		iifname "veth-eg-*" oifname "{{.Exit}}" tcp dport { 80, 443 } counter accept
		iifname "veth-eg-*" log prefix "uj other " group {{.LogGroup}} counter drop comment "other"
	}

	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		ct state established,related accept
		ip daddr @private4 counter drop
		# The resolver's upstream queries.
		oifname "{{.Exit}}" meta l4proto { tcp, udp } th dport { 53, 853 } accept
		counter drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat;
		oifname "{{.Exit}}" masquerade
	}
}
`))

// vmRules is the policy of one VM's namespace: the guest's DNS goes to our resolver whatever
// server it asked, its traffic leaves only towards the egress namespace, and the namespace
// itself isn't reachable from the guest.
var vmRules = template.Must(template.New("vm").Parse(`flush ruleset
table ip urljail {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		iifname "{{.Tap}}" meta l4proto { tcp, udp } th dport 53 dnat to {{.Resolver}}
	}

	chain postrouting {
		type nat hook postrouting priority srcnat;
		oifname "{{.Veth}}" masquerade
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		counter drop comment "vm-input"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		iifname "{{.Tap}}" oifname "{{.Veth}}" accept
		counter drop comment "vm-forward"
	}
}
`))

// loadRules loads a ruleset into ns with `nft -f`, checking it first with `nft -c`, and
// returns the hash of what the kernel then reports (docs/network.md: load + verify hash).
func loadRules(ctx context.Context, ns string, t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	text := buf.String()
	if _, err := run(ctx, strings.NewReader(text), "ip", "netns", "exec", ns, "nft", "-c", "-f", "-"); err != nil {
		return "", fmt.Errorf("ruleset for %s doesn't check: %w", ns, err)
	}
	if _, err := run(ctx, strings.NewReader(text), "ip", "netns", "exec", ns, "nft", "-f", "-"); err != nil {
		return "", fmt.Errorf("loading ruleset into %s: %w", ns, err)
	}
	return rulesHash(ctx, ns)
}

// rulesHash hashes the ruleset currently loaded in ns, without counters.
func rulesHash(ctx context.Context, ns string) (string, error) {
	out, err := in(ctx, ns, "nft", "-s", "list", "ruleset")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(out))
	return hex.EncodeToString(sum[:]), nil
}
