package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeHost(t *testing.T, dir string) {
	t.Helper()
	h := filepath.Join(dir, "host")
	os.MkdirAll(h, 0o700)
	files := map[string]string{
		"dns.jsonl": `{"time":"2026-10-12T13:00:00Z","qname":"land.example.org.","qtype":"A","rcode":"NOERROR"}
{"time":"2026-10-12T13:00:00Z","qname":"update.googleapis.com.","qtype":"A","rcode":"NOERROR"}
{"time":"2026-10-12T13:00:00Z","qname":"beacon.evil.test.","qtype":"A","rcode":"NOERROR"}
{"time":"2026-10-12T13:00:01Z","qname":"beacon.evil.test.","qtype":"HTTPS","rcode":"NOERROR"}
`,
		"flows.jsonl": `{"proto":"udp","dst":"172.16.0.1","dport":53,"pkts_out":1,"bytes_out":80,"pkts_in":1,"bytes_in":120}
{"proto":"tcp","dst":"192.0.2.2","dport":443,"pkts_out":9,"bytes_out":2200,"pkts_in":8,"bytes_in":7000,"tcp_flags_out":"FIN,SYN,PSH,ACK","sni":"land.example.org","alpn":["h2"]}
{"proto":"tcp","dst":"142.250.1.1","dport":443,"pkts_out":7,"bytes_out":2100,"pkts_in":7,"bytes_in":4500,"tcp_flags_out":"SYN,PSH,ACK","sni":"update.googleapis.com"}
{"proto":"tcp","dst":"142.250.1.2","dport":5228,"pkts_out":2,"bytes_out":148,"tcp_flags_out":"SYN"}
{"proto":"tcp","dst":"203.0.113.9","dport":443,"pkts_out":5,"bytes_out":1900,"pkts_in":4,"bytes_in":3000,"tcp_flags_out":"SYN,PSH,ACK","sni":"beacon.evil.test"}
`,
		"blocked.jsonl": `{"time":"2026-10-12T13:00:02Z","reason":"private","dst":"192.168.0.1","proto":"tcp","dst_port":80}
{"time":"2026-10-12T13:00:03Z","reason":"private","dst":"192.168.0.1","proto":"tcp","dst_port":80}
{"time":"2026-10-12T13:00:04Z","reason":"quic","dst":"1.1.1.1","proto":"udp","dst_port":443}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(h, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostReconciliation(t *testing.T) {
	dir := writeRun(t, true) // guest saw short.test (192.0.2.1), land.example.org (192.0.2.2), ...
	writeHost(t, dir)
	r, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, f := range r.GetNetwork().GetFlows() {
		labels[f.GetDstIp()+":"+itoa(f.GetDstPort())] = f.GetLabel()
	}
	want := map[string]string{
		"172.16.0.1:53":    "dns",
		"192.0.2.2:443":    "page",
		"142.250.1.1:443":  "browser-background",
		"142.250.1.2:5228": "no-data",
		"203.0.113.9:443":  "unexplained",
	}
	for k, v := range want {
		if labels[k] != v {
			t.Errorf("flow %s labeled %q, want %q", k, labels[k], v)
		}
	}
	rec := r.GetReconciliation()
	if rec.GetConsistent() {
		t.Error("an unexplained flow must make the run inconsistent")
	}
	if got := strings.Join(rec.GetUnexplainedFlows(), "|"); !strings.Contains(got, "beacon.evil.test") {
		t.Errorf("unexplained flows = %q", got)
	}
	if got := strings.Join(rec.GetUnexplainedDns(), "|"); got != "beacon.evil.test" {
		t.Errorf("unexplained dns = %q (deduplicated, background and page names excluded)", got)
	}
	// short.test (192.0.2.1:443) is in the guest's requests but has no host flow.
	if got := strings.Join(rec.GetGuestOnlyRequests(), "|"); !strings.Contains(got, "https://short.test/a") {
		t.Errorf("guest-only = %q", got)
	}
	b := r.GetNetwork().GetBlocked()
	if len(b) != 2 || b[0].GetDstIp() != "192.168.0.1" || b[0].GetCount() != 2 || b[1].GetReason() != "quic" {
		t.Errorf("blocked = %v", b)
	}
	if strings.Contains(strings.Join(r.GetGaps(), "\n"), "No host-side records") {
		t.Error("host records present but reported missing")
	}
}

func TestHostWithoutGuestEvents(t *testing.T) {
	dir := writeRun(t, false)
	writeHost(t, dir)
	r, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.GetNetwork().GetFlows()) != 5 || r.GetReconciliation() == nil {
		t.Fatalf("a run without guest events must still report host flows: %v", r.GetNetwork().GetFlows())
	}
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func TestPageHints(t *testing.T) {
	dir := writeRun(t, true)
	writeHost(t, dir)
	// beacon.evil.test is unexplained in writeHost; a preconnect hint in the DOM explains it.
	dom := `<html><head><link rel="preconnect" href="//beacon.evil.test"><link rel=stylesheet href="https://x.test/a.css"></head></html>`
	os.WriteFile(filepath.Join(dir, "guest", "dom.html"), []byte(dom), 0o600)
	r, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.GetNetwork().GetFlows() {
		if f.GetSni() == "beacon.evil.test" && f.GetLabel() != "page-hint" {
			t.Errorf("hinted flow labeled %q", f.GetLabel())
		}
	}
	if len(r.GetReconciliation().GetUnexplainedFlows()) != 0 || len(r.GetReconciliation().GetUnexplainedDns()) != 0 {
		t.Errorf("hinted host still unexplained: %v %v", r.GetReconciliation().GetUnexplainedFlows(), r.GetReconciliation().GetUnexplainedDns())
	}
}
