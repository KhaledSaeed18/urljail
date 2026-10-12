package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Build runs in the root daemon over guest-written files: it must never panic or hang.
func FuzzBuild(f *testing.F) {
	f.Add([]byte(`{"method":"Network.responseReceived","params":{"requestId":"1","response":{"url":"https://x.test/","headers":{"Report-To":"{\"endpoints\":[{\"url\":\"https://r.test/\"}]}","Reporting-Endpoints":"a=\"https://e.test/\""}}}}`), []byte(`{"navigation_error":"net::ERR_NAME_NOT_RESOLVED"}`), []byte(``))
	f.Add([]byte(events), []byte(`{"final_url":"https://x.test/","dwell":"3.5s","dropped_events":"2"}`), []byte(`<link rel="preconnect" href="//a.test">`))
	f.Add([]byte(`{"method":"Network.requestWillBeSent","params":{"requestId":"1","redirectResponse":{"status":1e999}}}`), []byte(`[]`), []byte(`<link rel=dns-prefetch href=::>`))
	f.Fuzz(func(t *testing.T, ev, done, dom []byte) {
		dir := t.TempDir()
		if err := WriteMeta(dir, Meta{RunID: "r", URL: "https://x.test/", Status: "completed", StartedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		g := filepath.Join(dir, "guest")
		os.MkdirAll(g, 0o700)
		os.WriteFile(filepath.Join(g, "events.jsonl"), ev, 0o600)
		os.WriteFile(filepath.Join(g, "done.json"), done, 0o600)
		os.WriteFile(filepath.Join(g, "dom.html"), dom, 0o600)
		os.WriteFile(filepath.Join(dir, FeedFile), done, 0o600) // any JSON-ish bytes
		if _, err := Build(dir); err != nil {
			t.Fatal(err)
		}
	})
}

// The host records carry guest-influenced strings (SNI, Host, queried names).
func FuzzBuildHost(f *testing.F) {
	f.Add([]byte(`{"proto":"tcp","dst":"192.0.2.2","dport":443,"sni":"x.test","tcp_flags_out":"SYN,PSH"}`),
		[]byte(`{"qname":"x.test.","qtype":"A","rcode":"NOERROR"}`), []byte(`{"reason":"private","dst":"10.0.0.1","proto":"tcp","dst_port":80}`))
	f.Fuzz(func(t *testing.T, flows, dns, blocked []byte) {
		dir := t.TempDir()
		if err := WriteMeta(dir, Meta{RunID: "r", URL: "https://x.test/", Status: "completed", StartedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		h := filepath.Join(dir, "host")
		os.MkdirAll(h, 0o700)
		os.WriteFile(filepath.Join(h, "flows.jsonl"), flows, 0o600)
		os.WriteFile(filepath.Join(h, "dns.jsonl"), dns, 0o600)
		os.WriteFile(filepath.Join(h, "blocked.jsonl"), blocked, 0o600)
		if _, err := Write(dir); err != nil { // Write: the report must also marshal
			t.Fatal(err)
		}
	})
}
