package feeds

import (
	"bufio"
	"os"
	"testing"
)

// TestScoreDump scores a name dump from `urljail feeds ct -dump` when URLJAIL_CT_DUMP is set.
func TestScoreDump(t *testing.T) {
	path := os.Getenv("URLJAIL_CT_DUMP")
	if path == "" {
		t.Skip("set URLJAIL_CT_DUMP")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n, hits := 0, 0
	for sc.Scan() {
		n++
		if s, why := Score(sc.Text()); s >= CandidateScore {
			hits++
			t.Logf("%2d %s %v", s, sc.Text(), why)
		}
	}
	t.Logf("%d of %d names are candidates", hits, n)
}
