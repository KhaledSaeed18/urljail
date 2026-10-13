package outcome

import (
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"
)

func run(t *testing.T, report, dom string) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "guest"), 0o700)
	os.WriteFile(filepath.Join(dir, "report.json"), []byte(report), 0o600)
	if dom != "" {
		os.WriteFile(filepath.Join(dir, "guest", "dom.html"), []byte(dom), 0o600)
	}
	return dir
}

func TestClassify(t *testing.T) {
	sub := "https://login-paypal.example.top/x"
	cases := []struct{ report, dom, want string }{
		{`{"run":{"profile":"baseline"},"navigation":{"finalUrl":"https://login-paypal.example.top/","error":"net::ERR_NAME_NOT_RESOLVED"}}`, "", Dead},
		{`{"navigation":{"finalUrl":"x","error":"navigation timed out after 12s (no response)"}}`, "", NoResponse},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"example.top | 521: Web server is down"}}`, "", OriginDown},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"Suspected Phishing | Cloudflare"}}`, "", Blocked},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"Verify you are human"}}`, "", Gate},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"x"}}`, `<div class="cf-turnstile"></div>`, Gate},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"Sign in"}}`, `<form><input type="password"></form>`, Login},
		{`{"navigation":{"finalUrl":"https://example.top/","title":"403","redirectChain":[{"status":403}]}}`, "", ErrorPage},
		{`{"navigation":{"finalUrl":"https://www.google.com/","title":"Google"}}`, "<p>", RedirectAway},
		{`{"navigation":{"finalUrl":"https://shop.example.top/","title":"Shop"}}`, "<p>", Content},
		{`not json`, "", Failed},
	}
	for i, c := range cases {
		if got := Classify(run(t, c.report, c.dom), sub).Label; got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func TestCompareFactor(t *testing.T) {
	// The Amazon case from the first watch hour: only the User-Agent decided.
	forbidden := Outcome{Label: ErrorPage, FinalDomain: "amazon.dev"}
	login := Outcome{Label: RedirectAway, FinalDomain: "amazon.com"}
	at := func(o Outcome, p string) Outcome { o.Profile = p; return o }
	c := Compare("https://mirror.tools.amazon.dev/", []Outcome{
		at(forbidden, "baseline"), at(login, "stealth"), at(forbidden, "stealth-no-ua"),
		at(login, "stealth-no-webdriver"), at(login, "stealth-no-tz"),
	})
	if !c.Differs || c.Factor != "ua" {
		t.Fatalf("differs %v factor %q groups %v", c.Differs, c.Factor, c.Groups)
	}
	// Baseline alone differs: every factor fits, so none is named.
	c = Compare("u", []Outcome{at(forbidden, "baseline"), at(login, "stealth"), at(login, "stealth-no-ua"),
		at(login, "stealth-no-webdriver"), at(login, "stealth-no-tz")})
	if !c.Differs || c.Factor != "" {
		t.Errorf("baseline-only split: factor %q", c.Factor)
	}
	// One headful run out of line: noise until its control agrees.
	six := func(extra ...Outcome) []Outcome {
		return append([]Outcome{at(login, "baseline"), at(login, "stealth"), at(login, "stealth-no-ua"),
			at(login, "stealth-no-webdriver"), at(login, "stealth-no-tz"), at(forbidden, "stealth-headful")}, extra...)
	}
	if c := Compare("u", six()); !c.Differs || c.Factor != "" {
		t.Errorf("single headful run: factor %q", c.Factor)
	}
	if c := Compare("u", six(at(forbidden, "stealth-headful~control"))); c.Factor != "headful" {
		t.Errorf("headful with agreeing control: factor %q", c.Factor)
	}
	if c := Compare("u", six(at(login, "stealth-headful~control"))); c.Factor != "" {
		t.Errorf("headful with disagreeing control: factor %q", c.Factor)
	}
	same := Compare("u", []Outcome{at(login, "baseline"), at(login, "stealth")})
	if same.Differs || !same.Reached {
		t.Errorf("same: %+v", same)
	}
	ctl := Compare("u", []Outcome{at(login, "baseline"), at(login, "stealth"), at(forbidden, "baseline~control")})
	if ctl.Differs || ctl.ControlAgrees != 0 {
		t.Errorf("control: differs %v agrees %d (a control never makes profiles differ)", ctl.Differs, ctl.ControlAgrees)
	}
	if c := Compare("u", []Outcome{at(login, "baseline"), at(login, "baseline~control")}); c.ControlAgrees != 1 {
		t.Errorf("agreeing control: %d", c.ControlAgrees)
	}
	dead := Compare("u", []Outcome{at(Outcome{Label: Dead}, "baseline")})
	if dead.Reached {
		t.Error("dead counted as reached")
	}
}

func TestAverageHash(t *testing.T) {
	img := func(left bool) image.Image {
		m := image.NewGray(image.Rect(0, 0, 64, 32))
		for y := 0; y < 32; y++ {
			for x := 0; x < 64; x++ {
				if (x < 32) == left {
					m.SetGray(x, y, color.Gray{255})
				}
			}
		}
		return m
	}
	a, b := averageHash(img(true)), averageHash(img(false))
	if ScreenDistance(a, a) != 0 || ScreenDistance(a, b) < 50 || ScreenDistance(a, 0) != -1 {
		t.Errorf("distances %d %d", ScreenDistance(a, b), ScreenDistance(a, 0))
	}
}
