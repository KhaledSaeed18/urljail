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
	case "pause", "resume":
		st.Paused = args[0] == "pause"
		fmt.Printf("submissions %sd\n", args[0])
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
	if st.Paused {
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

func runFeeds(ctx context.Context, c daemonv1.DaemonServiceClient, st *feeds.Store, n int, profileList string) error {
	if st.Paused {
		return errors.New("submissions are paused (urljail feeds resume)")
	}
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	v, err := c.Version(vctx, &daemonv1.VersionRequest{})
	cancel()
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if v.GetEgressMode() != "live" {
		return fmt.Errorf("the daemon is in %q mode: feed URLs are only detonated in live mode", v.GetEgressMode())
	}
	profs, err := pickProfiles(profileList, v.GetProfiles())
	if err != nil {
		return err
	}
	parallel := max(1, min(int(v.GetMaxVms()), len(profs)))
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
	for i, it := range batch {
		if ctx.Err() != nil {
			break
		}
		fmt.Printf("\n[%d/%d] %s (%s, first seen %s ago)\n", i+1, len(batch), it.URL, it.Feed, time.Since(it.FirstSeen).Round(time.Minute))
		it.Status, it.RunAt = "running", time.Now().UTC()
		if err := st.Save(); err != nil {
			return err
		}
		results := detonateProfiles(ctx, c, it.URL, profs, parallel)
		it.Runs = map[string]string{}
		ran, errs := 0, []string{}
		for _, res := range results {
			if res.runDir == "" {
				errs = append(errs, res.profile+": "+errString(res.err))
				continue
			}
			ran++
			it.Runs[res.profile] = filepath.Base(res.runDir)
			if werr := report.WriteFeed(res.runDir, report.FeedMeta{Name: it.Feed, FirstSeen: it.FirstSeen}); werr == nil {
				report.Write(res.runDir) // rebuild with run.feed
			}
		}
		switch {
		case ran == 0:
			it.Status, it.Error = "refused", strings.Join(errs, "; ")
		case ran < len(profs):
			it.Status, it.Error = "done", strings.Join(errs, "; ")
		default:
			it.Status, it.Error = "done", ""
		}
		printProfileTable(results)
		if err := st.Save(); err != nil {
			return err
		}
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
