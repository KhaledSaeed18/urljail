package outcome

import (
	"slices"
	"strings"
)

// Countermeasures are the factors the stealth profiles switch (daemon profiles.go).
var Countermeasures = []string{"ua", "webdriver", "tz", "headful"}

// countermeasures returns which factors a profile applies, from its name: baseline none,
// stealth all, stealth-no-<f> all but f. Unknown names: nil, false.
func countermeasures(profile string) (map[string]bool, bool) {
	switch {
	case profile == "baseline":
		return map[string]bool{}, true
	case profile == "stealth":
		return map[string]bool{"ua": true, "webdriver": true, "tz": true}, true
	case profile == "stealth-headful": // a headful browser's User-Agent is the desktop one
		return map[string]bool{"ua": true, "webdriver": true, "tz": true, "headful": true}, true
	case strings.HasPrefix(profile, "stealth-no-"):
		f := strings.TrimPrefix(profile, "stealth-no-")
		if !slices.Contains(Countermeasures, f) {
			return nil, false
		}
		m := map[string]bool{"ua": true, "webdriver": true, "tz": true}
		delete(m, f)
		return m, true
	}
	return nil, false
}

// Comparison is one URL across profiles.
type Comparison struct {
	URL      string    `json:"url"`
	Outcomes []Outcome `json:"outcomes"`
	// Differs: the profiles didn't all get the same outcome (label or final domain).
	Differs bool `json:"differs"`
	// Groups: profiles by outcome ("login@paypal-x.top" → profiles).
	Groups map[string][]string `json:"groups,omitempty"`
	// Factor: the one countermeasure whose presence splits the profiles exactly as the
	// outcomes do ("ua", "webdriver", "tz"); empty when none or several fit.
	Factor string `json:"factor,omitempty"`
	// Visual: largest screenshot hash distance between two runs with the same outcome
	// (rendering or timing noise vs. different content; -1 if not comparable).
	Visual int `json:"visual"`
	// Reached: at least one profile got a page (not dead, no response or origin down).
	Reached bool `json:"reached"`
	// ControlAgrees: 1 when the control run ("<profile>~control") got the same outcome as its
	// twin, 0 when not (noise: timing, rotation), -1 without a control.
	ControlAgrees int `json:"control_agrees"`
}

// ControlSuffix marks a control run's profile key.
const ControlSuffix = "~control"

func key(o Outcome) string { return o.Label + "@" + o.FinalDomain }

// Compare puts a URL's outcomes side by side.
func Compare(u string, all []Outcome) Comparison {
	c := Comparison{URL: u, Outcomes: all, Groups: map[string][]string{}, Visual: -1, ControlAgrees: -1}
	var outs, controls []Outcome
	for _, o := range all {
		if strings.HasSuffix(o.Profile, ControlSuffix) {
			controls = append(controls, o)
		} else {
			outs = append(outs, o)
		}
	}
	for _, ctl := range controls {
		twin := strings.TrimSuffix(ctl.Profile, ControlSuffix)
		for _, o := range outs {
			if o.Profile == twin && o.Label != Failed && ctl.Label != Failed {
				if key(o) == key(ctl) {
					c.ControlAgrees = max(c.ControlAgrees, 1)
				} else if c.ControlAgrees < 0 {
					c.ControlAgrees = 0
				}
			}
		}
	}
	for _, o := range outs {
		c.Groups[key(o)] = append(c.Groups[key(o)], o.Profile)
		switch o.Label {
		case Failed, Dead, NoResponse, OriginDown:
		default:
			c.Reached = true
		}
	}
	for i := range outs {
		for j := i + 1; j < len(outs); j++ {
			if key(outs[i]) == key(outs[j]) {
				c.Visual = max(c.Visual, ScreenDistance(outs[i].Screen, outs[j].Screen))
			}
		}
	}
	if len(c.Groups) < 2 {
		c.Groups = nil
		return c
	}
	c.Differs = true
	// Failed runs say nothing about the page: leave them out of the attribution. Controls
	// count on their twin's side, so a side of one profile needs its control to agree.
	var known []Outcome
	for _, o := range all {
		if _, ok := countermeasures(strings.TrimSuffix(o.Profile, ControlSuffix)); ok && o.Label != Failed {
			known = append(known, o)
		}
	}
	var fits []string
	for _, f := range Countermeasures {
		if splitsBy(known, f) {
			fits = append(fits, f)
		}
	}
	if len(fits) == 1 {
		c.Factor = fits[0]
	}
	return c
}

// splitsBy reports whether outcomes are the same exactly when factor f's presence is, with at
// least two runs on each side: one run alone can't be told from noise (4% in P6 M4).
func splitsBy(outs []Outcome, f string) bool {
	with, without := map[string]bool{}, map[string]bool{}
	nWith, nWithout := 0, 0
	for _, o := range outs {
		cm, _ := countermeasures(strings.TrimSuffix(o.Profile, ControlSuffix))
		if cm[f] {
			with[key(o)] = true
			nWith++
		} else {
			without[key(o)] = true
			nWithout++
		}
	}
	if len(with) != 1 || len(without) != 1 || nWith < 2 || nWithout < 2 {
		return false
	}
	for k := range with {
		return !without[k]
	}
	return false
}
