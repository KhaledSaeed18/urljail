// Package policy decides which URLs a detonation may open, given the daemon's egress mode.
// This is the interlock from docs/network.md#egress-modes: it is enforced in code at preflight,
// before any VM exists.
package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EgressMode is what network exit detonations may use.
type EgressMode string

const (
	EgressOff  EgressMode = "off"  // nothing leaves; every detonation is refused
	EgressDev  EgressMode = "dev"  // host NAT; allowlisted benign domains only
	EgressLive EgressMode = "live" // WireGuard only; any URL (after the live gate)
)

// DefaultDevAllowlist holds domains reserved for documentation (RFC 2606), safe to fetch in dev mode.
var DefaultDevAllowlist = []string{"example.com", "example.net", "example.org"}

// ParseEgressMode parses "off", "dev" or "live".
func ParseEgressMode(s string) (EgressMode, error) {
	switch m := EgressMode(s); m {
	case EgressOff, EgressDev, EgressLive:
		return m, nil
	}
	return "", fmt.Errorf("unknown egress mode %q (want off, dev or live)", s)
}

// ErrRefused wraps every policy refusal, so callers can tell refusals from bugs.
var ErrRefused = errors.New("refused by policy")

// Policy checks submitted URLs.
type Policy struct {
	Mode      EgressMode
	Allowlist []string // dev mode: exact hosts or parent domains
}

// Check parses raw and returns it if this policy allows detonating it.
func (p Policy) Check(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, refuse("not a valid URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, refuse("scheme %q not allowed (http and https only)", u.Scheme)
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return nil, refuse("URL has no host")
	}
	// Egress allows TCP 80 and 443 only (docs/network.md); refuse other ports up front
	// rather than letting the firewall silently drop them mid-run.
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return nil, refuse("port %s not allowed (80 and 443 only)", port)
	}

	switch p.Mode {
	case EgressOff:
		return nil, refuse("egress mode is off")
	case EgressDev:
		if net.ParseIP(host) != nil {
			return nil, refuse("dev mode: IP literal %s is not allowlisted", host)
		}
		if !p.allowed(host) {
			return nil, refuse("dev mode: %s is not on the allowlist %v", host, p.Allowlist)
		}
	case EgressLive:
		// Any public URL; isolation is the network layer's job.
	default:
		return nil, refuse("unknown egress mode %q", p.Mode)
	}
	return u, nil
}

func (p Policy) allowed(host string) bool {
	for _, d := range p.Allowlist {
		d = normalizeHost(d)
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}
