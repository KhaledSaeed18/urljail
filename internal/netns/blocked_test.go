package netns

import "testing"

func TestParseBlocked(t *testing.T) {
	// IPv4 TCP SYN 10.200.0.2:40000 → 169.254.169.254:80 (headers only).
	pkt := []byte{
		0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0,
		10, 200, 0, 2, 169, 254, 169, 254,
		0x9c, 0x40, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0,
	}
	b, ok := parseBlocked("uj private ", pkt)
	if !ok || b.Reason != "private" || b.Src != "10.200.0.2" || b.Dst != "169.254.169.254" || b.Proto != "tcp" || b.Port != 80 {
		t.Fatalf("parseBlocked = %+v, %v", b, ok)
	}
	if _, ok := parseBlocked("uj quic ", []byte{0x60, 0, 0}); ok {
		t.Fatal("parsed a non-IPv4 packet")
	}
}
