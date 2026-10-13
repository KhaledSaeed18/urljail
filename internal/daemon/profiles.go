package daemon

import (
	"fmt"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

// DefaultProfile is the run condition when a request names none: Chrome as installed.
const DefaultProfile = "baseline"

// browserProfile is one experimental condition (P6, docs/research/anti-cloaking.md): how
// Chrome presents itself. Each has its own snapshot.
type browserProfile struct {
	name    string
	browser *guestv1.BrowserProfile
}

// profiles are the conditions: baseline, stealth (every countermeasure), and stealth minus one
// countermeasure each, for ablation. exitTimezone is the VPN exit's zone; without it there is
// no timezone countermeasure and no ablation for it.
func profiles(exitTimezone string) []browserProfile {
	stealth := func(ua, webdriver, tz bool) *guestv1.BrowserProfile {
		// No language override: Chrome's default (en-US,en) already fits the US exit, and
		// overriding it made navigator.languages differ from baseline (P6 M2).
		p := &guestv1.BrowserProfile{DesktopUserAgent: ua, HideWebdriver: webdriver}
		if tz {
			p.Timezone = exitTimezone
		}
		return p
	}
	ps := []browserProfile{
		{DefaultProfile, &guestv1.BrowserProfile{}},
		{"stealth", stealth(true, true, true)},
		{"stealth-no-ua", stealth(false, true, true)},
		{"stealth-no-webdriver", stealth(true, false, true)},
	}
	if exitTimezone != "" {
		ps = append(ps, browserProfile{"stealth-no-tz", stealth(true, true, false)})
	}
	// Stealth with a (virtual) display instead of headless mode. Its User-Agent is already the
	// desktop one, so no override.
	headful := stealth(false, true, true)
	headful.Headful = true
	ps = append(ps, browserProfile{"stealth-headful", headful})
	return ps
}

// describe is the profile's settings as recorded in its snapshot manifest; a change means a
// rebuild.
func describe(p *guestv1.BrowserProfile) string {
	s := fmt.Sprintf("ua=%t webdriver=%t tz=%q lang=%q",
		p.GetDesktopUserAgent(), p.GetHideWebdriver(), p.GetTimezone(), p.GetLanguage())
	if p.GetHeadful() { // only when set: existing snapshots' descriptions stay valid
		s += " headful=true"
	}
	return s
}
