package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/kits"
	"github.com/KhaledSaeed18/urljail/internal/paths"
)

// cmdKits builds the kit references (internal/kits/refs.json) from labelled runs: every run
// labelled phishing whose page is large enough to fingerprint, except those that match a page
// labelled benign or the brand's real site elsewhere: a site builder's template, not a kit
// (found in P7, S19: a lure on sites.google.com matched an unrelated Google Sites page on its
// own domain). Brands' own pages aren't compared: kit-match never runs there.
func cmdKits(args []string) error {
	if len(args) == 0 || args[0] != "refs" {
		return errors.New("usage: urljail kits refs -labels labels.tsv > internal/kits/refs.json")
	}
	fs := flag.NewFlagSet("kits refs", flag.ContinueOnError)
	labels := fs.String("labels", "", "labels as TSV: the dashboard's /labels.tsv, or docs/research/data/p7-indicator-labels.tsv")
	if err := fs.Parse(args[1:]); err != nil || *labels == "" {
		return exitError(2)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	runsDir := filepath.Join(paths.DataDir(home), "runs")
	f, err := os.Open(*labels)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	// Columns by header name: "run" or "run_id"; "label" or "verdict".
	col := map[string]int{}
	var refs, others []kits.Ref
	seen := map[string]bool{}
	skipped := 0
	for line := 0; sc.Scan(); line++ {
		c := strings.Split(sc.Text(), "\t")
		if line == 0 {
			for i, name := range c {
				col[name] = i
			}
			continue
		}
		get := func(names ...string) string {
			for _, n := range names {
				if i, ok := col[n]; ok && i < len(c) {
					return c[i]
				}
			}
			return ""
		}
		run, verdict := get("run", "run_id"), get("label", "verdict")
		if !isRunID(run) || seen[run] {
			continue
		}
		seen[run] = true
		if verdict == "benign" || verdict == "real-site" {
			// Not a brand's own page: kit-match never runs there, and a faithful clone matches it.
			if ref, err := kitRef(filepath.Join(runsDir, run)); err == nil {
				if _, owned := brands.Owner(brands.DomainOf("https://" + ref.Host + "/")); !owned {
					others = append(others, ref)
				}
			}
			continue
		}
		if verdict != "phish" {
			continue
		}
		ref, err := kitRef(filepath.Join(runsDir, run))
		if err != nil {
			skipped++
			continue
		}
		ref.Kind, ref.Brand = strings.Trim(get("kind"), "-"), strings.Trim(get("brand"), "-")
		refs = append(refs, ref)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	kept := refs[:0]
	var dropped []string
	for _, r := range refs {
		if o, sim, ok := kits.Match(others, r.Fingerprint, r.Host); ok {
			dropped = append(dropped, fmt.Sprintf("  %s (%s) matches %s, not phishing (%.0f %%)", r.Host, r.Run, o.Host, sim*100))
			continue
		}
		kept = append(kept, r)
	}
	refs = kept
	fmt.Fprintf(os.Stderr, "%d kit references (%d phishing runs skipped: no DOM, or too small to fingerprint; %d dropped: they match a page that isn't phishing)\n",
		len(refs), skipped, len(dropped))
	for _, d := range dropped {
		fmt.Fprintln(os.Stderr, d)
	}
	out, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(out, '\n'))
	return err
}

func kitRef(runDir string) (kits.Ref, error) {
	b, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return kits.Ref{}, err
	}
	var rep struct {
		Run struct {
			StartedAt string `json:"started_at"`
		} `json:"run"`
		Navigation struct {
			FinalURL string `json:"final_url"`
		} `json:"navigation"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return kits.Ref{}, err
	}
	u, err := brands.ParseOrigin(rep.Navigation.FinalURL)
	if err != nil || u.Hostname() == "" {
		return kits.Ref{}, errors.New("no final URL")
	}
	d, err := os.Open(filepath.Join(runDir, "guest", "dom.html"))
	if err != nil {
		return kits.Ref{}, err
	}
	defer d.Close()
	fp, ok := kits.Of(d)
	if !ok {
		return kits.Ref{}, errors.New("too small")
	}
	date := rep.Run.StartedAt
	if len(date) >= 10 {
		date = date[:10]
	}
	return kits.Ref{Run: filepath.Base(runDir), Host: u.Hostname(), Labelled: date, Fingerprint: fp}, nil
}

func isRunID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4 && strings.Trim(s, "0123456789abcdef-") == ""
}
