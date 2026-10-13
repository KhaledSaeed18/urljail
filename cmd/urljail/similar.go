package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/visual"
)

// cmdSimilar finds runs whose screenshots look alike (page.screenshot_phash): the neighbours of
// one run, or groups across all runs that span several domains (one kit, many hosts).
func cmdSimilar(args []string) error {
	fs := flag.NewFlagSet("similar", flag.ContinueOnError)
	maxDist := fs.Int("max", visual.DefaultMaxDistance, "largest hash distance (of 64 bits) that counts as alike")
	groups := fs.Bool("groups", false, "list groups of look-alike pages across all runs instead of one run's neighbours")
	minDomains := fs.Int("min-domains", 2, "with -groups: only groups spanning at least this many domains")
	all := fs.Bool("all", false, "with -groups: include pages that didn't load (browser error pages look alike everywhere)")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	runsDir := filepath.Join(paths.DataDir(home), "runs")
	entries, err := visual.Load(runsDir)
	if err != nil {
		return err
	}

	if *groups {
		if fs.NArg() != 0 {
			return errors.New("usage: urljail similar -groups [-max n] [-min-domains n] [-all]")
		}
		var pool []visual.Entry
		for _, e := range entries {
			if e.Loaded || *all {
				pool = append(pool, e)
			}
		}
		shown := 0
		for _, g := range visual.Groups(pool, *maxDist) {
			if len(g.Domains) < *minDomains {
				continue
			}
			shown++
			lead := g.Members[0]
			fmt.Printf("%d runs, %d domains  %s  %q\n", len(g.Members), len(g.Domains), lead.Hash, clip(lead.Title, 60))
			fmt.Printf("    %s\n", strings.Join(firstN(g.Domains, 8), ", "))
		}
		fmt.Printf("%d groups (%d pages with a screenshot hash, distance ≤ %d)\n", shown, len(pool), *maxDist)
		return nil
	}

	if fs.NArg() != 1 {
		return errors.New("usage: urljail similar [-max n] <run-dir|run-id>")
	}
	run := filepath.Base(filepath.Clean(fs.Arg(0)))
	var self *visual.Entry
	for i := range entries {
		if entries[i].Run == run {
			self = &entries[i]
		}
	}
	if self == nil {
		return fmt.Errorf("run %s has no screenshot hash (no screenshot, a blank one, or a report from before the hash: rebuild it with urljail report)", run)
	}
	n := 0
	for _, m := range visual.Neighbors(entries, self.Hash, *maxDist) {
		if m.Run == run {
			continue
		}
		n++
		fmt.Printf("  %2d  %s  %-28s %q\n", m.Distance, m.Run, clip(m.Domain, 28), clip(m.Title, 50))
	}
	fmt.Printf("%d runs look like %s (%s, distance ≤ %d)\n", n, run, self.Hash, *maxDist)
	return nil
}

func clip(s string, n int) string {
	r := []rune(strings.ToValidUTF8(s, "?"))
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return string(r)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("+%d more", len(s)-n))
	}
	return s
}
