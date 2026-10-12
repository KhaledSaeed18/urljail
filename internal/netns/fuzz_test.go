package netns

import "testing"

// Run by the root daemon on unbound's log (answers come from attacker-controlled nameservers)
// and on packets a guest sent.

func FuzzParseReply(f *testing.F) {
	f.Add("[1760281234] unbound[12:0] info: 10.200.1.2 example.com. A IN NOERROR 0.033149 0 56")
	f.Fuzz(func(t *testing.T, line string) { _, _ = parseReply(line) })
}

func FuzzParseBlocked(f *testing.F) {
	f.Add("uj private ", []byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 200, 0, 2, 169, 254, 169, 254, 0x9c, 0x40, 0x00, 0x50})
	f.Fuzz(func(t *testing.T, prefix string, pkt []byte) { _, _ = parseBlocked(prefix, pkt) })
}

func FuzzParseCounters(f *testing.F) {
	f.Add([]byte(`{"nftables":[{"rule":{"comment":"private","expr":[{"counter":{"packets":3}}]}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseCounters(b) })
}
