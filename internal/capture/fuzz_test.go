package capture

import (
	"strings"
	"testing"
)

// The daemon (root) runs these on bytes a hostile guest sent.

func FuzzParseClientHello(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := parseClientHello(b)
		if err == nil && (len(h.SNI) > 253 || h.SNI != "" && !validOrMarked(h.SNI)) {
			t.Fatalf("SNI %q", h.SNI)
		}
	})
}

func FuzzParseHTTPHost(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if h := parseHTTPHost(b); len(h) > 253 || h != "" && !validOrMarked(h) {
			t.Fatalf("host %q", h)
		}
	})
}

func FuzzReassemble(f *testing.F) {
	f.Add(uint32(1000), []byte("abc"), uint32(1003), []byte("def"))
	f.Fuzz(func(t *testing.T, s1 uint32, d1 []byte, s2 uint32, d2 []byte) {
		out := reassemble([]seg{{seq: s1, data: d1}, {seq: s2, data: d2}})
		if len(out) > len(d1)+len(d2) {
			t.Fatalf("reassembled more than was captured")
		}
	})
}

// validOrMarked: a lowercase DNS-ish name, or the hex-encoded "invalid:" marker.
func validOrMarked(s string) bool {
	if strings.HasPrefix(s, "invalid:") {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
