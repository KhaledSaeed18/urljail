package policy

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	dev := Policy{Mode: EgressDev, Allowlist: DefaultDevAllowlist}
	live := Policy{Mode: EgressLive}
	off := Policy{Mode: EgressOff}

	tests := []struct {
		name string
		p    Policy
		url  string
		ok   bool
	}{
		{"dev allowlisted", dev, "https://example.com/", true},
		{"dev subdomain", dev, "https://www.example.org/path?q=1", true},
		{"dev case and trailing dot", dev, "https://EXAMPLE.com./", true},
		{"dev explicit port 443", dev, "https://example.com:443/", true},
		{"dev not allowlisted", dev, "https://evil.test/", false},
		{"dev suffix trick", dev, "https://notexample.com/", false},
		{"dev allowlisted as subdomain of other", dev, "https://example.com.evil.test/", false},
		{"dev IP literal", dev, "http://93.184.215.14/", false},
		{"bad scheme", dev, "file:///etc/passwd", false},
		{"javascript scheme", live, "javascript:alert(1)", false},
		{"no host", dev, "https:///path", false},
		{"other port", live, "https://example.com:8443/", false},
		{"live any host", live, "https://phish.test/login", true},
		{"off refuses all", off, "https://example.com/", false},
		{"garbage", dev, "://", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.p.Check(tt.url)
			if tt.ok && err != nil {
				t.Fatalf("Check(%q) = %v, want allowed", tt.url, err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("Check(%q) allowed, want refused", tt.url)
				}
				if !errors.Is(err, ErrRefused) {
					t.Fatalf("Check(%q) error %v doesn't wrap ErrRefused", tt.url, err)
				}
			}
		})
	}
}

func TestParseEgressMode(t *testing.T) {
	for _, s := range []string{"off", "dev", "live"} {
		if _, err := ParseEgressMode(s); err != nil {
			t.Errorf("ParseEgressMode(%q) = %v", s, err)
		}
	}
	if _, err := ParseEgressMode("open"); err == nil {
		t.Error(`ParseEgressMode("open") succeeded`)
	}
}
