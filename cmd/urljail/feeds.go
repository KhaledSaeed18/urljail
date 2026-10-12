package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/ctlog"
	"github.com/KhaledSaeed18/urljail/internal/feeds"
	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/report"
)

const feedsUsage = `usage: urljail feeds <command>

  fetch          fetch due feeds into the queue (no detonation)
  status         queue and source summary
  run [-n N] [-profiles all|p1,p2]
                 fetch, then detonate up to N queued URLs (default 3; live mode only), each
                 under every profile at once (default: all the daemon has)
  ct [-for d] [-dry-run]
                 follow Let's Encrypt's CT logs and queue names that look like phishing
                 (-dry-run: print candidates only)
  watch [-for 1h] [-min-age 5m] [-profiles all] [-max-urls N]
                 follow CT and detonate candidates under every profile once they're
                 min-age old (live mode only)
  pause|resume   stop or allow submissions (fetching continues)
`

// feedSources are the feeds urljail fetches (docs/feed-ingestion.md).
var feedSources = []feeds.Source{feeds.OpenPhishCommunity}

func cmdFeeds(ctx context.Context, c daemonv1.DaemonServiceClient, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, feedsUsage)
		return exitError(2)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	st, err := feeds.Open(filepath.Join(paths.DataDir(home), "feeds"))
	if err != nil {
		return err
	}
	switch args[0] {
	case "fetch", "run", "watch", "ct":
		unlock, err := st.Lock()
		if err != nil {
			return err
		}
		defer unlock()
		// The lock was taken after reading: read again so nothing a previous holder saved is lost.
		if st, err = feeds.Open(filepath.Join(paths.DataDir(home), "feeds")); err != nil {
			return err
		}
	}
	switch args[0] {
	case "fetch":
		if err := fetchFeeds(ctx, st); err != nil {
			return err
		}
	case "status":
		printFeedStatus(st)
		return nil
	case "run":
		fs := flag.NewFlagSet("feeds run", flag.ContinueOnError)
		n := fs.Int("n", 3, "maximum URLs to detonate")
		profs := fs.String("profiles", "all", `browser profiles per URL: "all" or a comma-separated list`)
		if err := fs.Parse(args[1:]); err != nil || *n < 1 {
			return exitError(2)
		}
		return runFeeds(ctx, c, st, *n, *profs)
	case "ct":
		fs := flag.NewFlagSet("feeds ct", flag.ContinueOnError)
		dur := fs.Duration("for", 10*time.Minute, "how long to follow the logs")
		dry := fs.Bool("dry-run", false, "print candidates, don't queue them")
		dump := fs.String("dump", "", "also write every scanned name to this file (for tuning the scoring)")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError(2)
		}
		cctx, cancel := context.WithTimeout(ctx, *dur)
		defer cancel()
		var dumpW io.Writer
		if *dump != "" {
			f, err := os.OpenFile(*dump, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			dumpW = f
		}
		n, err := followCT(cctx, dumpW, func(it *feeds.Item) {
			fmt.Printf("%s  %2d  %-60s %s\n", it.FirstSeen.Local().Format(time.TimeOnly), it.Score, it.URL, strings.Join(it.Reasons, " "))
			if !*dry {
				st.AddCandidate(it)
			}
		})
		fmt.Printf("%d certificate names scanned\n", n)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return err
		}
		if *dry {
			return nil
		}
	case "watch":
		fs := flag.NewFlagSet("feeds watch", flag.ContinueOnError)
		dur := fs.Duration("for", time.Hour, "how long to watch")
		minAge := fs.Duration("min-age", 5*time.Minute, "wait this long after a certificate appears (the site needs time to go up)")
		profs := fs.String("profiles", "all", `browser profiles per URL: "all" or a comma-separated list`)
		maxURLs := fs.Int("max-urls", 0, "stop after this many URLs (0: no limit)")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError(2)
		}
		wctx, cancel := context.WithTimeout(ctx, *dur)
		defer cancel()
		return watchCT(wctx, c, st, *profs, *minAge, *maxURLs)
	case "pause", "resume":
		if err := st.SetPaused(args[0] == "pause"); err != nil {
			return err
		}
		fmt.Printf("submissions %sd\n", args[0])
		return nil
	default:
		fmt.Fprint(os.Stderr, feedsUsage)
		return exitError(2)
	}
	return st.Save()
}

func fetchFeeds(ctx context.Context, st *feeds.Store) error {
	client := &http.Client{Timeout: 60 * time.Second}
	now := time.Now().UTC()
	var errs []error
	for _, src := range feedSources {
		urls, skipped, err := feeds.Fetch(ctx, client, src, st.Source(src.Name), now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if urls == nil {
			fmt.Printf("%-22s not due or unchanged\n", src.Name)
			continue
		}
		fmt.Printf("%-22s %d URLs (%d skipped), %d new\n", src.Name, len(urls), skipped, st.Add(src.Name, urls, now))
	}
	return errors.Join(errs...)
}

func printFeedStatus(st *feeds.Store) {
	if st.IsPaused() {
		fmt.Println("submissions PAUSED")
	}
	names := make([]string, 0, len(st.Sources))
	for n := range st.Sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := st.Sources[n]
		fmt.Printf("%-22s last fetch %s, %d URLs, %d skipped\n", n, s.LastFetch.Local().Format(time.DateTime), s.LastCount, s.LastSkipped)
	}
	c := st.Counts()
	fmt.Printf("queue: %d queued, %d done, %d failed, %d refused, %d expired\n", c["queued"], c["done"], c["failed"], c["refused"], c["expired"])
}

// liveProfiles checks the daemon is in live mode and resolves the profiles to run.
func liveProfiles(ctx context.Context, c daemonv1.DaemonServiceClient, profileList string) (profs []string, parallel int, err error) {
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	v, err := c.Version(vctx, &daemonv1.VersionRequest{})
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("daemon: %w", err)
	}
	if v.GetEgressMode() != "live" {
		return nil, 0, fmt.Errorf("the daemon is in %q mode: feed URLs are only detonated in live mode", v.GetEgressMode())
	}
	if profs, err = pickProfiles(profileList, v.GetProfiles()); err != nil {
		return nil, 0, err
	}
	return profs, max(1, min(int(v.GetMaxVms()), len(profs))), nil
}

func runFeeds(ctx context.Context, c daemonv1.DaemonServiceClient, st *feeds.Store, n int, profileList string) error {
	if st.IsPaused() {
		return errors.New("submissions are paused (urljail feeds resume)")
	}
	profs, parallel, err := liveProfiles(ctx, c, profileList)
	if err != nil {
		return err
	}
	if err := fetchFeeds(ctx, st); err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err) // the queue may still hold fresh URLs
	}
	batch := st.Next(n, time.Now().UTC(), feeds.DefaultLimits)
	if err := st.Save(); err != nil {
		return err
	}
	if len(batch) == 0 {
		fmt.Println("nothing to run (queue empty, expired or within per-domain limits)")
		return nil
	}
	var mu sync.Mutex
	for i, it := range batch {
		if ctx.Err() != nil {
			break
		}
		fmt.Printf("\n[%d/%d] ", i+1, len(batch))
		if err := runItem(ctx, c, st, &mu, it, profs, parallel); err != nil {
			return err
		}
	}
	return nil
}

// runItem detonates one queued URL under every profile and records the runs. mu guards st
// (feeds watch adds candidates while a URL runs).
func runItem(ctx context.Context, c daemonv1.DaemonServiceClient, st *feeds.Store, mu *sync.Mutex, it *feeds.Item, profs []string, parallel int) error {
	mu.Lock()
	fmt.Printf("%s (%s, first seen %s ago)\n", it.URL, it.Feed, time.Since(it.FirstSeen).Round(time.Second))
	if len(it.Reasons) > 0 {
		fmt.Printf("  score %d: %s\n", it.Score, strings.Join(it.Reasons, " "))
	}
	it.Status, it.RunAt = "running", time.Now().UTC()
	err := st.Save()
	mu.Unlock()
	if err != nil {
		return err
	}
	results := detonateProfiles(ctx, c, it.URL, profs, parallel)
	runs, ran, errs := map[string]string{}, 0, []string{}
	for _, res := range results {
		if res.runDir == "" {
			errs = append(errs, res.profile+": "+errString(res.err))
			continue
		}
		ran++
		runs[res.profile] = filepath.Base(res.runDir)
		if werr := report.WriteFeed(res.runDir, report.FeedMeta{Name: it.Feed, FirstSeen: it.FirstSeen}); werr == nil {
			report.Write(res.runDir) // rebuild with run.feed
		}
	}
	printProfileTable(results)
	mu.Lock()
	defer mu.Unlock()
	it.Runs, it.Status, it.Error = runs, "done", strings.Join(errs, "; ")
	if ran == 0 {
		it.Status = "refused"
	}
	return st.Save()
}

// watchCT follows the CT logs and detonates candidates once they're minAge old, newest first,
// until ctx ends or maxURLs have run (0: no limit).
func watchCT(ctx context.Context, c daemonv1.DaemonServiceClient, st *feeds.Store, profileList string, minAge time.Duration, maxURLs int) error {
	profs, parallel, err := liveProfiles(ctx, c, profileList)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctErr := make(chan error, 1)
	go func() {
		_, err := followCT(cctx, nil, func(it *feeds.Item) {
			mu.Lock()
			defer mu.Unlock()
			if st.AddCandidate(it) {
				fmt.Printf("%s  queued  %2d  %s  %s\n", time.Now().Format(time.TimeOnly), it.Score, it.URL, strings.Join(it.Reasons, " "))
				_ = st.Save()
			}
		})
		ctErr <- err
	}()
	limits := feeds.DefaultLimits
	limits.MinAge, limits.MaxAge, limits.Feed = minAge, 6*time.Hour, "ct"
	ran := 0
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for maxURLs == 0 || ran < maxURLs {
		select {
		case <-ctx.Done():
			return nil
		case err := <-ctErr:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ct: %w", err)
		case <-tick.C:
		}
		if st.IsPaused() {
			continue
		}
		mu.Lock()
		next := st.Next(1, time.Now().UTC(), limits)
		mu.Unlock()
		if len(next) == 0 {
			continue
		}
		fmt.Println()
		if err := runItem(ctx, c, st, &mu, next[0], profs, parallel); err != nil {
			return err
		}
		ran++
	}
	return nil
}

// pickProfiles resolves -profiles against what the daemon has.
func pickProfiles(list string, have []string) ([]string, error) {
	if list == "all" {
		if len(have) == 0 {
			return []string{""}, nil // older daemon: its default profile only
		}
		return have, nil
	}
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !slices.Contains(have, p) {
			return nil, fmt.Errorf("the daemon has no profile %q (have: %s)", p, strings.Join(have, ", "))
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("no profiles given")
	}
	return out, nil
}

type profileResult struct {
	profile string
	runDir  string
	err     error
}

// detonateProfiles runs url under each profile, at most parallel at a time, so every
// condition sees the page within seconds of the others (kits rotate and die fast).
func detonateProfiles(ctx context.Context, c daemonv1.DaemonServiceClient, url string, profs []string, parallel int) []profileResult {
	results := make([]profileResult, len(profs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, p := range profs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dir, err := detonateQuiet(ctx, c, url, p)
			results[i] = profileResult{profile: p, runDir: dir, err: err}
		}()
	}
	wg.Wait()
	return results
}

func printProfileTable(results []profileResult) {
	for _, res := range results {
		name := res.profile
		if name == "" {
			name = "default"
		}
		if res.runDir == "" {
			fmt.Printf("  %-22s REFUSED %v\n", name, res.err)
			continue
		}
		fmt.Printf("  %-22s %s\n", name, oneLine(res.runDir, res.err))
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// detonateQuiet runs one URL and returns its run directory (empty if the daemon refused it).
func detonateQuiet(ctx context.Context, c daemonv1.DaemonServiceClient, url, profile string) (string, error) {
	stream, err := c.Detonate(ctx, &daemonv1.DetonateRequest{Url: url, Profile: profile})
	if err != nil {
		return "", err
	}
	runDir := ""
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return runDir, errors.New("stream ended without a final state")
		}
		if err != nil {
			return runDir, err
		}
		if m.GetRunDir() != "" {
			runDir = m.GetRunDir()
		}
		switch m.GetState() {
		case daemonv1.RunState_RUN_STATE_DONE:
			return runDir, nil
		case daemonv1.RunState_RUN_STATE_FAILED:
			return runDir, errors.New(m.GetError())
		}
	}
}

// ctOperators are the CT log operators followed: Let's Encrypt issues most phishing
// certificates, and logs them only to its own static-ct-api logs plus one other.
var ctOperators = []string{"Let's Encrypt"}

// followCT follows the current CT logs until ctx ends, calling found for each name that scores
// as a candidate (once per name). It returns how many names it scanned.
func followCT(ctx context.Context, dump io.Writer, found func(*feeds.Item)) (int, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	logs, err := ctlog.CurrentLogs(ctx, client, ctOperators, time.Now())
	if err != nil {
		return 0, err
	}
	entries := make(chan ctlog.Entry, 4096)
	for _, l := range logs {
		fmt.Fprintf(os.Stderr, "following %s\n", l.Name)
		f := &ctlog.Follower{Client: client, Log: l, Poll: 5 * time.Second, MaxLag: 20,
			Skipped: func(n uint64) { fmt.Fprintf(os.Stderr, "%s: behind, skipped %d entries\n", l.Name, n) }}
		go f.Run(ctx, entries)
	}
	seen := map[string]bool{}
	scanned := 0
	for {
		select {
		case <-ctx.Done():
			return scanned, ctx.Err()
		case e := <-entries:
			for _, name := range e.Names {
				scanned++
				name = strings.TrimPrefix(name, "*.")
				if seen[name] {
					continue
				}
				seen[name] = true
				if dump != nil {
					fmt.Fprintln(dump, name)
				}
				if len(seen) > 1_000_000 {
					clear(seen)
				}
				score, why := feeds.Score(name)
				if score < feeds.CandidateScore {
					continue
				}
				u, err := feeds.Normalize("https://" + name + "/")
				if err != nil {
					continue
				}
				found(&feeds.Item{URL: u, Feed: "ct", FirstSeen: e.Timestamp, Score: score, Reasons: why})
			}
		}
	}
}
