package main

import (
	"strings"
	"testing"
)

func TestParseLabels(t *testing.T) {
	in := "set\trun\tlabel\tkind\tbrand\tnote\n" +
		"heldout6\t01a137ad-aab7-7505-a0e3-069260643bbb\tphish\tlure\tledger\tsetup guide\n" +
		"heldout6\t01a137ad-aab7-7505-a0e3-069260643bbb\tbenign\t-\t-\tduplicate, ignored\n" +
		"heldout6\tnot-a-run\tphish\t-\t-\t\n" +
		"heldout6\t01a137ad-f9bf-70c8-a255-2a532f797891\treal-site\t-\tfacebook\t\n"
	ls, err := parseLabels(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d labels, want 2: %+v", len(ls), ls)
	}
	if l := ls[0]; l.verdict != "phish" || l.kind != "lure" || l.set != "heldout6" {
		t.Errorf("first label = %+v", l)
	}
	if l := ls[1]; l.verdict != "real-site" || l.kind != "" || l.brand != "facebook" {
		t.Errorf("second label = %+v (\"-\" should read as empty)", l)
	}
}

func TestFlagged(t *testing.T) {
	if (&dumped{inds: []string{"brand-presented-off-domain/info"}}).flagged() {
		t.Error("info alone counted as flagged")
	}
	if !(&dumped{inds: []string{"brand-presented-off-domain/info", "kit-match/medium"}}).flagged() {
		t.Error("medium not counted as flagged")
	}
}
