package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHAR(t *testing.T) {
	dir := writeRun(t, true)
	if _, err := Write(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "har.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h harLog
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	if h.Log.Version != "1.2" || len(h.Log.Pages) != 1 {
		t.Fatalf("log = %+v", h.Log)
	}
	// short.test → 302 → land.example.org, the failed script, login.phish.test; data: URLs skipped.
	var got []string
	for _, e := range h.Log.Entries {
		got = append(got, e.Request.URL)
	}
	want := []string{"https://short.test/a", "https://land.example.org/", "https://cdn.example.org/x.js", "https://login.phish.test/"}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
	e := h.Log.Entries
	if e[0].Response.Status != 302 || e[0].Response.RedirectURL != "https://land.example.org/" || e[0].ServerIPAddress != "192.0.2.1" || e[0].Response.HTTPVersion != "HTTP/2.0" {
		t.Errorf("redirect hop = %+v", e[0])
	}
	if e[1].Response.Status != 200 || e[1].TransferSize != 1234 {
		t.Errorf("landing = %+v", e[1].Response)
	}
	if e[2].Error != "net::ERR_CONNECTION_REFUSED" {
		t.Errorf("failed request error = %q", e[2].Error)
	}
	if e[3].Comment == "" {
		t.Error("an unfinished request should say so")
	}
	r, _ := Build(dir)
	if r.GetArtifacts().GetHar() != "har.json" {
		t.Errorf("artifacts.har = %q", r.GetArtifacts().GetHar())
	}
}
