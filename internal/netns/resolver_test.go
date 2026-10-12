package netns

import "testing"

func TestParseReply(t *testing.T) {
	q, ok := parseReply("[1760281234] unbound[12:0] info: 10.200.1.2 example.com. A IN NOERROR 0.033149 0 56")
	if !ok || q.Client != "10.200.1.2" || q.Name != "example.com." || q.Type != "A" || q.Rcode != "NOERROR" || q.RTT != 0.033149 || q.Cached {
		t.Fatalf("parseReply = %+v, %v", q, ok)
	}
	for _, line := range []string{
		"[1760281234] unbound[12:0] info: start of service (unbound 1.22.0).",
		"[1760281234] unbound[12:0] info: 127.0.0.1 example.com. A IN NOERROR 0.01 0 56", // not a VM
		"[1760281234] unbound[12:0] notice: init module 0: iterator",
	} {
		if _, ok := parseReply(line); ok {
			t.Errorf("parsed %q as a VM reply", line)
		}
	}
}
