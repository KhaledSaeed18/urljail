package daemon

import "testing"

func TestProfiles(t *testing.T) {
	ps := profiles("America/Chicago")
	if ps[0].name != DefaultProfile || describe(ps[0].browser) != `ua=false webdriver=false tz="" lang=""` {
		t.Fatalf("first profile %s %s", ps[0].name, describe(ps[0].browser))
	}
	seen := map[string]bool{}
	for _, p := range ps {
		d := describe(p.browser)
		if seen[p.name] || seen[d] {
			t.Errorf("duplicate profile %s (%s)", p.name, d)
		}
		seen[p.name], seen[d] = true, true
	}
	if len(ps) != 5 {
		t.Errorf("%d profiles with a timezone, want 5", len(ps))
	}
	if n := len(profiles("")); n != 4 {
		t.Errorf("%d profiles without a timezone, want 4 (no stealth-no-tz)", n)
	}
}
