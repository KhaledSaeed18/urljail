package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/report"
)

// cmdIndicators measures a change to the indicator rules: dump rebuilds every stored run's
// indicators with this binary (nothing is written to the runs), score counts them against the
// labels, diff lists the runs whose indicators differ between two dumps. Before P7's S19 this was
// done by rebuilding report.json with each binary and diffing by hand.
func cmdIndicators(args []string) error {
	const use = "usage: urljail indicators dump [-runs dir] [-workers n] > dump.tsv\n" +
		"       urljail indicators score -labels f [-set s,...] [-v] dump.tsv\n" +
		"       urljail indicators diff [-labels f] old.tsv new.tsv"
	if len(args) == 0 {
		return errors.New(use)
	}
	switch args[0] {
	case "dump":
		return indicatorsDump(args[1:])
	case "score":
		return indicatorsScore(args[1:])
	case "diff":
		return indicatorsDiff(args[1:])
	}
	return errors.New(use)
}

// A dumped run: one TSV line, "run host indicators title", indicators as id/severity joined
// by commas, sorted.
type dumped struct {
	run, host, title string
	inds             []string
}

func indicatorsDump(args []string) error {
	fs := flag.NewFlagSet("indicators dump", flag.ContinueOnError)
	runsDir := fs.String("runs", "", "runs directory (default: the data dir's runs)")
	workers := fs.Int("workers", runtime.NumCPU(), "runs rebuilt at once")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	if *runsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*runsDir = filepath.Join(paths.DataDir(home), "runs")
	}
	ents, err := os.ReadDir(*runsDir)
	if err != nil {
		return err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() && isRunID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	out := make([]*dumped, len(ids))
	var wg sync.WaitGroup
	next := make(chan int)
	for range max(*workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				out[i] = dumpRun(filepath.Join(*runsDir, ids[i]))
			}
		}()
	}
	for i := range ids {
		next <- i
	}
	close(next)
	wg.Wait()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	n := 0
	for _, d := range out {
		if d == nil {
			continue
		}
		n++
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.run, d.host, strings.Join(d.inds, ","), d.title)
	}
	fmt.Fprintf(os.Stderr, "%d runs rebuilt (%d without a report: no metadata)\n", n, len(ids)-n)
	return nil
}

func dumpRun(runDir string) *dumped {
	r, err := report.Build(runDir)
	if err != nil {
		return nil
	}
	d := &dumped{run: filepath.Base(runDir), title: titleLine(r.GetNavigation().GetTitle())}
	if u, err := brands.ParseOrigin(r.GetNavigation().GetFinalUrl()); err == nil {
		d.host = u.Hostname()
	}
	for _, i := range r.GetIndicators() {
		d.inds = append(d.inds, i.GetId()+"/"+i.GetSeverity())
	}
	sort.Strings(d.inds)
	d.inds = compactStrings(d.inds)
	return d
}

func titleLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.ToValidUTF8(s, "?")
}

func compactStrings(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func readDump(path string) (map[string]*dumped, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]*dumped{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		c := strings.SplitN(sc.Text(), "\t", 4)
		if len(c) < 3 {
			continue
		}
		d := &dumped{run: c[0], host: c[1]}
		if c[2] != "" {
			d.inds = strings.Split(c[2], ",")
		}
		if len(c) == 4 {
			d.title = c[3]
		}
		out[d.run] = d
	}
	return out, sc.Err()
}

// flagged: an indicator of medium severity or above (info doesn't count).
func (d *dumped) flagged() bool {
	for _, i := range d.inds {
		if !strings.HasSuffix(i, "/info") {
			return true
		}
	}
	return false
}

// A label row: the set it belongs to, the verdict and the kind of phishing.
type label struct{ run, set, verdict, kind, brand, note string }

func readLabels(path string) ([]label, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseLabels(f)
}

// parseLabels reads labels as TSV with a header: the dashboard's /labels.tsv or
// docs/research/data/p7-indicator-labels.tsv ("run" or "run_id"; "label" or "verdict").
func parseLabels(r io.Reader) ([]label, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	col := map[string]int{}
	var out []label
	seen := map[string]bool{}
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
					return strings.Trim(c[i], "-")
				}
			}
			return ""
		}
		l := label{run: get("run", "run_id"), set: get("set"), verdict: get("label", "verdict"),
			kind: get("kind"), brand: get("brand"), note: get("note")}
		if !isRunID(l.run) || seen[l.run] {
			continue
		}
		seen[l.run] = true
		out = append(out, l)
	}
	return out, sc.Err()
}

func indicatorsScore(args []string) error {
	fs := flag.NewFlagSet("indicators score", flag.ContinueOnError)
	labelsPath := fs.String("labels", "", "labels as TSV")
	sets := fs.String("set", "", "only these label sets, comma-separated (default: all)")
	verbose := fs.Bool("v", false, "list the false alarms and the misses")
	if err := fs.Parse(args); err != nil || *labelsPath == "" || fs.NArg() != 1 {
		return exitError(2)
	}
	labels, err := readLabels(*labelsPath)
	if err != nil {
		return err
	}
	dump, err := readDump(fs.Arg(0))
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range strings.Split(*sets, ",") {
		if s != "" {
			want[s] = true
		}
	}

	type tally struct{ n, flagged int }
	kinds := map[string]*tally{}
	var phish, others tally
	fired := map[string][2]int{} // indicator → fired on phishing, on others
	var alarms, misses []string
	missing := 0
	for _, l := range labels {
		if len(want) > 0 && !want[l.set] {
			continue
		}
		d, ok := dump[l.run]
		if !ok {
			missing++
			continue
		}
		var t *tally
		switch l.verdict {
		case "phish":
			t = &phish
			if kinds[l.kind] == nil {
				kinds[l.kind] = &tally{}
			}
			kinds[l.kind].n++
			if d.flagged() {
				kinds[l.kind].flagged++
			}
		case "benign", "real-site":
			t = &others
		default:
			continue
		}
		t.n++
		if d.flagged() {
			t.flagged++
		}
		for _, i := range d.inds {
			id := strings.SplitN(i, "/", 2)[0]
			f := fired[id]
			if l.verdict == "phish" {
				f[0]++
			} else {
				f[1]++
			}
			fired[id] = f
		}
		line := fmt.Sprintf("  %s  %-40s %s  [%s] %s", l.run, d.host, strings.Join(d.inds, ","), l.kind+" "+l.brand, d.title)
		switch {
		case l.verdict == "phish" && !d.flagged():
			misses = append(misses, line)
		case l.verdict != "phish" && d.flagged():
			alarms = append(alarms, line)
		}
	}
	pct := func(t tally) string {
		if t.n == 0 {
			return "-"
		}
		return fmt.Sprintf("%d of %d (%.0f %%)", t.flagged, t.n, 100*float64(t.flagged)/float64(t.n))
	}
	fmt.Printf("medium and up: phishing %s, others (benign, real site) %s\n", pct(phish), pct(others))
	var ks []string
	for k := range kinds {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Printf("  %-12s %s\n", k, pct(*kinds[k]))
	}
	var ids []string
	for id := range fired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Println("indicator                      phishing  others")
	for _, id := range ids {
		fmt.Printf("  %-28s %8d  %6d\n", id, fired[id][0], fired[id][1])
	}
	if missing > 0 {
		fmt.Printf("(%d labelled runs not in the dump)\n", missing)
	}
	if *verbose {
		fmt.Printf("\nfalse alarms (%d):\n%s\n", len(alarms), strings.Join(alarms, "\n"))
		fmt.Printf("\nmisses (%d):\n%s\n", len(misses), strings.Join(misses, "\n"))
	}
	return nil
}

func indicatorsDiff(args []string) error {
	fs := flag.NewFlagSet("indicators diff", flag.ContinueOnError)
	labelsPath := fs.String("labels", "", "labels as TSV: each changed run is shown with its label")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		return exitError(2)
	}
	old, err := readDump(fs.Arg(0))
	if err != nil {
		return err
	}
	cur, err := readDump(fs.Arg(1))
	if err != nil {
		return err
	}
	byRun := map[string]label{}
	if *labelsPath != "" {
		ls, err := readLabels(*labelsPath)
		if err != nil {
			return err
		}
		for _, l := range ls {
			byRun[l.run] = l
		}
	}
	var runs []string
	for run := range cur {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	changed := 0
	for _, run := range runs {
		a, b := old[run], cur[run]
		if a == nil {
			continue
		}
		was, now := strings.Join(a.inds, ","), strings.Join(b.inds, ",")
		if was == now {
			continue
		}
		changed++
		lab := "unlabelled"
		if l, ok := byRun[run]; ok {
			lab = strings.TrimSpace(l.verdict + " " + l.kind + " " + l.set)
		}
		fmt.Printf("%s  %s  [%s]  %q\n    - %s\n    + %s\n", run, b.host, lab, b.title, was, now)
	}
	fmt.Printf("%d of %d runs changed\n", changed, len(runs))
	return nil
}
