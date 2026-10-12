// Package feeds ingests phishing feeds for P6 (docs/feed-ingestion.md). It runs in the
// unprivileged CLI, never in the root daemon: feed lists are untrusted input, and a URL from a
// feed is data from fetch to report, never part of a command or a path.
package feeds

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/KhaledSaeed18/urljail/internal/policy"
)

const maxURLLen = 2048

// livePolicy applies the rules every URL must pass in live mode (scheme, port), so obviously
// unusable entries never reach the daemon, which checks again anyway.
var livePolicy = policy.Policy{Mode: policy.EgressLive}

// Normalize turns one feed entry into the URL urljail detonates, or says why it's unusable.
// Scheme and host are lowercased, default ports and the fragment dropped; path and query stay
// as given (cloaking can depend on them).
func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return "", errors.New("empty")
	case len(raw) > maxURLLen:
		return "", fmt.Errorf("longer than %d bytes", maxURLLen)
	}
	for _, r := range raw {
		if r < 0x21 || r == 0x7f {
			return "", errors.New("control character or space")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" || !u.IsAbs() {
		return "", errors.New("not an absolute URL with a host")
	}
	port := u.Port()
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	u.Host = host
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	s := u.String()
	if _, err := livePolicy.Check(s); err != nil {
		return "", err
	}
	return s, nil
}

// Domain is the registrable domain (eTLD+1) of a normalized URL, for per-domain limits.
func Domain(normalized string) string {
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if net.ParseIP(h) != nil {
		return h
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d
	}
	return h
}
