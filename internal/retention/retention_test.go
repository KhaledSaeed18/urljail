package retention

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KhaledSaeed18/urljail/internal/report"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func mkRun(t *testing.T, dir, id string, age time.Duration, pcap int) string {
	t.Helper()
	d := filepath.Join(dir, id)
	os.MkdirAll(filepath.Join(d, "host"), 0o700)
	os.MkdirAll(filepath.Join(d, "guest"), 0o700)
	if err := report.WriteMeta(d, report.Meta{RunID: id, URL: "https://x.test/", Status: "completed", StartedAt: now.Add(-age)}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "host", "capture.pcap"), make([]byte, pcap), 0o600)
	os.WriteFile(filepath.Join(d, "guest", "sslkeys.log"), []byte("CLIENT_RANDOM x y\n"), 0o600)
	return d
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	old := mkRun(t, dir, "old", 10*24*time.Hour, 100)
	mid := mkRun(t, dir, "mid", 3*24*time.Hour, 300)
	recent := mkRun(t, dir, "recent", 2*time.Hour, 300)
	young := mkRun(t, dir, "young", time.Minute, 300) // may still be running

	p := Policy{PcapMaxAge: 7 * 24 * time.Hour, PcapCap: 700, MinAge: 15 * time.Minute, Now: now, DryRun: true}
	res, err := Prune(dir, p)
	if err != nil || len(res.Pruned) != 2 || !exists(filepath.Join(old, "host/capture.pcap")) {
		t.Fatalf("dry run: %+v %v", res, err)
	}

	p.DryRun = false
	res, err = Prune(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	// old by age; then 300+300+300 = 900 > 700: mid goes (oldest first); recent and young stay.
	if len(res.Pruned) != 2 || res.Pruned[0].Run != "old" || res.Pruned[1].Run != "mid" || res.Freed != 400 {
		t.Fatalf("pruned %+v", res.Pruned)
	}
	for _, d := range []string{old, mid} {
		if exists(filepath.Join(d, "host/capture.pcap")) || exists(filepath.Join(d, "guest/sslkeys.log")) {
			t.Errorf("%s: capture or keys left", d)
		}
		r, err := report.Build(d)
		if err != nil {
			t.Fatal(err)
		}
		if r.GetArtifacts().GetPcap() != "" || !strings.Contains(strings.Join(r.GetGaps(), "|"), "deleted by retention on 2026-10-20") {
			t.Errorf("%s: report pcap %q gaps %v", d, r.GetArtifacts().GetPcap(), r.GetGaps())
		}
	}
	for _, d := range []string{recent, young} {
		if !exists(filepath.Join(d, "host/capture.pcap")) {
			t.Errorf("%s pruned", d)
		}
	}
	if res2, _ := Prune(dir, p); len(res2.Pruned) != 0 {
		t.Errorf("second pass pruned %+v", res2.Pruned)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"10G": 10 << 30, "500M": 500 << 20, "1.5GiB": 3 << 29, "2048": 2048, "64kb": 64 << 10} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "10Q", "-1G"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}
