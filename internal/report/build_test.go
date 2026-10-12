package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A run that hits a 302, then a script-initiated navigation, with a subresource, a data: URL,
// a failed request and a dialog.
const events = `{"method":"Page.frameNavigated","params":{"frame":{"id":"MAIN","url":"about:blank"}}}
{"method":"Network.requestWillBeSent","params":{"requestId":"1","frameId":"MAIN","type":"Document","request":{"url":"https://short.test/a","method":"GET"},"initiator":{"type":"other"}}}
{"method":"Network.requestWillBeSent","params":{"requestId":"1","frameId":"MAIN","type":"Document","request":{"url":"https://land.example.org/","method":"GET"},"initiator":{"type":"other"},"redirectResponse":{"url":"https://short.test/a","status":302,"remoteIPAddress":"192.0.2.1","protocol":"h2","securityDetails":{"protocol":"TLS 1.3","subjectName":"short.test","issuer":"Test CA","validFrom":1700000000,"validTo":1800000000,"sanList":["short.test"]}}}}
{"method":"Network.responseReceived","params":{"requestId":"1","frameId":"MAIN","type":"Document","response":{"url":"https://land.example.org/","status":200,"remoteIPAddress":"192.0.2.2","protocol":"h2"}}}
{"method":"Network.loadingFinished","params":{"requestId":"1","encodedDataLength":1234}}
{"method":"Network.requestWillBeSent","params":{"requestId":"2","frameId":"MAIN","type":"Script","request":{"url":"https://cdn.example.org/x.js","method":"GET"},"initiator":{"type":"parser"}}}
{"method":"Network.loadingFailed","params":{"requestId":"2","errorText":"net::ERR_CONNECTION_REFUSED"}}
{"method":"Network.requestWillBeSent","params":{"requestId":"3","frameId":"MAIN","type":"Image","request":{"url":"data:image/png;base64,AAAA","method":"GET"},"initiator":{"type":"parser"}}}
{"method":"Page.javascriptDialogOpening","params":{"url":"https://land.example.org/","message":"Verify your account","type":"alert"}}
{"method":"Page.frameRequestedNavigation","params":{"frameId":"MAIN","reason":"scriptInitiated","url":"https://login.phish.test/"}}
{"method":"Network.requestWillBeSent","params":{"requestId":"4","frameId":"MAIN","type":"Document","request":{"url":"https://login.phish.test/","method":"GET"},"initiator":{"type":"script"}}}
{"method":"Network.responseReceived","params":{"requestId":"4","frameId":"MAIN","type":"Document","response":{"url":"https://login.phish.test/","status":200}}}
not json at all
{"method":"Network.loadingFinished","params":"wrong shape"}
`

func writeRun(t *testing.T, withGuest bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := WriteMeta(dir, Meta{
		RunID: "01a1", URL: "https://short.test/a", Egress: "dev", Status: "completed",
		StartedAt: time.Unix(1, 0), EndedAt: time.Unix(2, 0), Versions: map[string]string{"browser": "155"},
		Clone: &Clone{Snapshot: "img-baseline", GuestClockSkewMs: 214, VMGenIDReseed: true},
	}); err != nil {
		t.Fatal(err)
	}
	if withGuest {
		g := filepath.Join(dir, "guest")
		os.MkdirAll(g, 0o700)
		os.WriteFile(filepath.Join(g, "events.jsonl"), []byte(events), 0o600)
		os.WriteFile(filepath.Join(g, "done.json"), []byte(`{"final_url":"https://login.phish.test/","title":"Sign in","dwell":"3.5s","dwell_reason":"network idle","dropped_events":"2"}`), 0o600)
		os.WriteFile(filepath.Join(g, "screenshot.png"), []byte("png"), 0o600)
	}
	return dir
}

func TestBuild(t *testing.T) {
	r, err := Build(writeRun(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if c := r.GetRun().GetClone(); c.GetSnapshot() != "img-baseline" || !c.GetVmgenidReseed() || c.GetGuestClockSkewMs() != 214 {
		t.Fatalf("clone = %v", c)
	}
	if r.GetSchema() != Schema || r.GetRun().GetVersions()["browser"] != "155" {
		t.Fatalf("run = %v", r.GetRun())
	}
	n := r.GetNavigation()
	if n.GetFinalUrl() != "https://login.phish.test/" || n.GetTitle() != "Sign in" || n.GetDwellMs() != 3500 {
		t.Fatalf("navigation = %v", n)
	}

	type hop struct {
		url    string
		status int32
		kind   string
	}
	want := []hop{
		{"https://short.test/a", 302, "initial"},
		{"https://land.example.org/", 200, "http"},
		{"https://login.phish.test/", 200, "js"},
	}
	got := n.GetRedirectChain()
	if len(got) != len(want) {
		t.Fatalf("chain = %v", got)
	}
	for i, w := range want {
		if got[i].GetUrl() != w.url || got[i].GetStatus() != w.status || got[i].GetKind() != w.kind {
			t.Errorf("hop %d = %v, want %+v", i, got[i], w)
		}
	}

	reqs := r.GetNetwork().GetRequests()
	if len(reqs) != 4 { // the redirect splits request 1 in two; the data: URL is omitted
		t.Fatalf("requests = %d: %v", len(reqs), reqs)
	}
	if reqs[0].GetStatus() != 302 || reqs[0].GetRemoteIp() != "192.0.2.1" || reqs[1].GetBytes() != 1234 {
		t.Errorf("redirected request split wrong: %v / %v", reqs[0], reqs[1])
	}
	if reqs[2].GetError() != "net::ERR_CONNECTION_REFUSED" {
		t.Errorf("failed request = %v", reqs[2])
	}

	if tls := r.GetNetwork().GetTls(); len(tls) != 1 || tls[0].GetHost() != "short.test" || tls[0].GetNotAfter().GetSeconds() != 1800000000 {
		t.Errorf("tls = %v", tls)
	}
	var regs []string
	for _, d := range r.GetNetwork().GetDomains() {
		regs = append(regs, d.GetRegistrable()+"="+strings.Join(d.GetHosts(), ","))
	}
	if got := strings.Join(regs, " "); got != "example.org=cdn.example.org,land.example.org phish.test=login.phish.test short.test=short.test" {
		t.Errorf("domains = %s", got)
	}
	if d := r.GetPage().GetDialogs(); len(d) != 1 || d[0].GetMessage() != "Verify your account" {
		t.Errorf("dialogs = %v", d)
	}
	gaps := strings.Join(r.GetGaps(), "\n")
	for _, w := range []string{"guest-attested", "2 CDP events were dropped", "1 data: URLs omitted"} {
		if !strings.Contains(gaps, w) {
			t.Errorf("gaps missing %q:\n%s", w, gaps)
		}
	}
	if r.GetArtifacts().GetScreenshot() != "guest/screenshot.png" || r.GetArtifacts().GetDom() != "" {
		t.Errorf("artifacts = %v", r.GetArtifacts())
	}
}

func TestBuildWithoutGuest(t *testing.T) {
	r, err := Write(writeRun(t, false))
	if err != nil {
		t.Fatal(err)
	}
	gaps := strings.Join(r.GetGaps(), "\n")
	if !strings.Contains(gaps, "no result") || !strings.Contains(gaps, "No guest events") {
		t.Errorf("gaps = %s", gaps)
	}
}
