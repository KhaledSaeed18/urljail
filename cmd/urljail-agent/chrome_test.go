package main

import (
	"slices"
	"strings"
	"testing"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

func TestChromeArgsProfile(t *testing.T) {
	base := chromeArgs("/tmp/p", nil, "155.0.8059.39-1")
	for _, a := range base {
		if strings.HasPrefix(a, "--user-agent") || strings.Contains(a, "AutomationControlled") || strings.HasPrefix(a, "--lang") {
			t.Errorf("baseline has %q", a)
		}
	}
	if !slices.Contains(base, "--headless=new") || slices.Contains(base, "--ozone-platform=x11") {
		t.Error("baseline must be headless")
	}
	hf := chromeArgs("/tmp/p", &guestv1.BrowserProfile{Headful: true}, "155.0.8059.39-1")
	if slices.Contains(hf, "--headless=new") || !slices.Contains(hf, "--ozone-platform=x11") || !slices.Contains(hf, "--enable-unsafe-swiftshader") {
		t.Errorf("headful args %v", hf)
	}
	if base[len(base)-1] != "about:blank" {
		t.Errorf("last arg %q", base[len(base)-1])
	}
	st := chromeArgs("/tmp/p", &guestv1.BrowserProfile{DesktopUserAgent: true, HideWebdriver: true, Language: "de-DE"}, "155.0.8059.39-1")
	for _, want := range []string{
		"--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		"--disable-blink-features=AutomationControlled", "--lang=de-DE", "--accept-lang=de-DE,de",
	} {
		if !slices.Contains(st, want) {
			t.Errorf("stealth args miss %q", want)
		}
	}
	// Values that would smuggle extra flags are dropped.
	bad := chromeArgs("/tmp/p", &guestv1.BrowserProfile{DesktopUserAgent: true, Language: "en --no-sandbox"}, "x --no-sandbox")
	for _, a := range bad {
		if strings.Contains(a, "no-sandbox") || strings.HasPrefix(a, "--user-agent") {
			t.Errorf("unsafe arg %q", a)
		}
	}
	for tz, ok := range map[string]bool{"America/Chicago": true, "UTC": true, "America/Argentina/Buenos_Aires": true, "../etc/x": false, "a b": false, "": false} {
		if validTimezone.MatchString(tz) != ok {
			t.Errorf("validTimezone(%q) != %v", tz, ok)
		}
	}
}
