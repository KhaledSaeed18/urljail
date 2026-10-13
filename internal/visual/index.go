package visual

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DefaultMaxDistance is the distance up to which two screenshots count as the same page. In
// P7's corpus (761 loaded pages, 215k pairs from different domains with different titles) 6
// gave no false match and found 60 % of same-page pairs; 8 found 75 % but matched an nginx
// welcome page to an unrelated login page (docs/journal/p7-control-plane.md).
const DefaultMaxDistance = 6

// Entry is one run's screenshot hash and what's needed to show it.
type Entry struct {
	Run      string // run directory name
	Hash     Hash
	FinalURL string
	Domain   string // registrable domain of the final URL
	Title    string
	// Loaded: the navigation succeeded and the last hop wasn't an HTTP error. Chrome's own
	// error page looks the same on every domain, so it's no evidence of a shared kit.
	Loaded bool
}

// reportFields are the parts of report.json the index reads.
type reportFields struct {
	Navigation struct {
		FinalURL      string `json:"final_url"`
		Title         string `json:"title"`
		Error         string `json:"error"`
		RedirectChain []struct {
			Status int `json:"status"`
		} `json:"redirect_chain"`
	} `json:"navigation"`
	Page struct {
		Phash string `json:"screenshot_phash"`
	} `json:"page"`
}

// maxReport caps how much of one report.json is read (reports are guest-influenced).
const maxReport = 64 << 20

// Load reads the screenshot hash of every run under runsDir that has one. Unreadable reports
// are skipped.
func Load(runsDir string) ([]Entry, error) {
	dirs, err := os.ReadDir(runsDir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if e, ok := loadOne(filepath.Join(runsDir, d.Name())); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func loadOne(dir string) (Entry, bool) {
	f, err := os.Open(filepath.Join(dir, "report.json"))
	if err != nil {
		return Entry{}, false
	}
	defer f.Close()
	var r reportFields
	if err := json.NewDecoder(io.LimitReader(f, maxReport)).Decode(&r); err != nil {
		return Entry{}, false
	}
	h, err := Parse(r.Page.Phash)
	if err != nil {
		return Entry{}, false
	}
	e := Entry{Run: filepath.Base(dir), Hash: h, FinalURL: r.Navigation.FinalURL, Title: r.Navigation.Title}
	if u, err := url.Parse(r.Navigation.FinalURL); err == nil {
		host := strings.ToLower(u.Hostname())
		if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			e.Domain = reg
		} else {
			e.Domain = host
		}
	}
	e.Loaded = r.Navigation.Error == ""
	if n := len(r.Navigation.RedirectChain); n > 0 {
		s := r.Navigation.RedirectChain[n-1].Status
		e.Loaded = e.Loaded && s >= 200 && s < 400
	}
	return e, true
}

// Match is an entry and its distance from the one searched for.
type Match struct {
	Entry
	Distance int
}

// Neighbors returns the entries within maxDist of h, closest first (run name breaks ties).
func Neighbors(entries []Entry, h Hash, maxDist int) []Match {
	var out []Match
	for _, e := range entries {
		if d := Distance(e.Hash, h); d <= maxDist {
			out = append(out, Match{e, d})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distance != out[j].Distance {
			return out[i].Distance < out[j].Distance
		}
		return out[i].Run < out[j].Run
	})
	return out
}

// Group is pages that look alike: every member is within the distance of the first one (the
// leader), so groups don't chain A~B~C into one when A and C differ.
type Group struct {
	Members []Entry
	Domains []string // distinct registrable domains, most runs first
}

// Groups clusters the entries: each entry joins the first group whose leader is within maxDist,
// or leads a new one. Entries are taken in run order (oldest first: run names are UUIDv7).
// Groups are returned largest first.
func Groups(entries []Entry, maxDist int) []Group {
	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Run < sorted[j].Run })
	var groups []Group
	for _, e := range sorted {
		joined := false
		for i := range groups {
			if Distance(groups[i].Members[0].Hash, e.Hash) <= maxDist {
				groups[i].Members = append(groups[i].Members, e)
				joined = true
				break
			}
		}
		if !joined {
			groups = append(groups, Group{Members: []Entry{e}})
		}
	}
	for i := range groups {
		count := map[string]int{}
		for _, m := range groups[i].Members {
			count[m.Domain]++
		}
		for d := range count {
			groups[i].Domains = append(groups[i].Domains, d)
		}
		ds := groups[i].Domains
		sort.Slice(ds, func(a, b int) bool {
			if count[ds[a]] != count[ds[b]] {
				return count[ds[a]] > count[ds[b]]
			}
			return ds[a] < ds[b]
		})
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].Members) > len(groups[j].Members) })
	return groups
}
