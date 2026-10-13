package visual

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLoadNeighborsGroups(t *testing.T) {
	dir := t.TempDir()
	write := func(run, phash, final, navErr string, status int) {
		os.MkdirAll(filepath.Join(dir, run), 0o700)
		body := `{"navigation":{"final_url":"` + final + `","title":"t","error":"` + navErr +
			`","redirect_chain":[{"status":` + strconv.Itoa(status) + `}]},"page":{"screenshot_phash":"` + phash + `"}}`
		os.WriteFile(filepath.Join(dir, run, "report.json"), []byte(body), 0o600)
	}
	write("01a1", "ffff000000000000", "https://login.kit-one.example/", "", 200)
	write("01a2", "ffff000000000003", "https://www.kit-two.co.uk/x", "", 200) // 2 bits from 01a1
	write("01a3", "ffff00000000003f", "https://kit-three.example/", "", 200)  // 6 from 01a1, 4 from 01a2
	write("01a4", "0000ffff00000000", "https://other.example/", "", 200)
	write("01a5", "0000ffff00000000", "https://dead.example/", "net::ERR_NAME_NOT_RESOLVED", 0)
	write("01a6", "", "https://blank.example/", "", 200) // no hash: skipped
	os.WriteFile(filepath.Join(dir, "stray"), nil, 0o600)

	es, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 5 {
		t.Fatalf("loaded %d entries, want 5: %+v", len(es), es)
	}
	byRun := map[string]Entry{}
	for _, e := range es {
		byRun[e.Run] = e
	}
	if byRun["01a2"].Domain != "kit-two.co.uk" || !byRun["01a2"].Loaded || byRun["01a5"].Loaded {
		t.Errorf("entries: %+v", byRun)
	}

	n := Neighbors(es, byRun["01a1"].Hash, 4)
	if len(n) != 2 || n[0].Run != "01a1" || n[1].Run != "01a2" || n[1].Distance != 2 {
		t.Errorf("neighbors = %+v", n)
	}

	// Leader clustering: 01a3 is 6 from the leader 01a1, so with 5 it starts its own group even
	// though it's 4 from 01a2 (no chaining).
	gs := Groups(es, 5)
	if len(gs) != 3 || len(gs[0].Members) != 2 || gs[0].Members[0].Run != "01a1" {
		t.Fatalf("groups = %+v", gs)
	}
	if len(gs[0].Domains) != 2 || gs[0].Domains[0] != "kit-one.example" && gs[0].Domains[0] != "kit-two.co.uk" {
		t.Errorf("domains = %v", gs[0].Domains)
	}
}
