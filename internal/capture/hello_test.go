package capture

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// clientHello captures a real ClientHello from Go's TLS stack.
func clientHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	c.Close()
	return buf[:n]
}

func TestParseClientHello(t *testing.T) {
	b := clientHello(t, "login.phish.test", []string{"h2", "http/1.1"})
	h, err := parseClientHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "login.phish.test" || len(h.ALPN) != 2 || h.ALPN[0] != "h2" {
		t.Fatalf("hello = %+v", h)
	}
}

func TestReassembledAcrossSegments(t *testing.T) {
	b := clientHello(t, "example.com", []string{"h2"})
	// Split as two TCP segments, delivered out of order, plus a retransmission of the first.
	cut := len(b) / 3
	segs := []seg{{seq: 1000 + uint32(cut), data: b[cut:]}, {seq: 1000, data: b[:cut]}, {seq: 1000, data: b[:cut]}}
	h, err := parseClientHello(reassemble(segs))
	if err != nil || h.SNI != "example.com" {
		t.Fatalf("hello = %+v, %v", h, err)
	}
}

func TestTruncatedExtensions(t *testing.T) {
	b := clientHello(t, "example.com", []string{"h2"})
	// Cut inside the extensions block, past the server_name extension Go writes first.
	h, err := parseClientHello(b[:len(b)-20])
	if err != nil || h.SNI != "example.com" {
		t.Fatalf("hello = %+v, %v", h, err)
	}
}

func TestParseHTTPHost(t *testing.T) {
	cases := map[string]string{
		"GET /service/update2 HTTP/1.1\r\nhost: Clients2.Google.com:80\r\nUser-Agent: x\r\n\r\n": "clients2.google.com",
		"POST / HTTP/1.1\r\nContent-Length: 0\r\nHost: example.com\r\n\r\n":                      "example.com",
		"GET / HTTP/1.1\r\n\r\n": "",
		"\x16\x03\x01 not http":  "",
	}
	for in, want := range cases {
		if got := parseHTTPHost([]byte(in)); got != want {
			t.Errorf("parseHTTPHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostileInput(t *testing.T) {
	b := clientHello(t, "example.com", nil)
	for i := 0; i < len(b); i++ {
		_, _ = parseClientHello(b[:i]) // truncation anywhere must not panic
	}
	bad := append([]byte{}, b...)
	bad[len(bad)-1] = 0xff
	_, _ = parseClientHello(bad)
	if _, err := parseClientHello([]byte("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("HTTP parsed as a ClientHello")
	}
}
