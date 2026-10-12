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
	"sort"
	"time"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/feeds"
	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/report"
)

const feedsUsage = `usage: urljail feeds <command>

  fetch          fetch due feeds into the queue (no detonation)
  status         queue and source summary
  run [-n N]     fetch, then detonate up to N queued URLs, one at a time (default 3; live mode only)
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
		if err := fs.Parse(args[1:]); err != nil || *n < 1 {
			return exitError(2)
		}
		return runFeeds(ctx, c, st, *n)
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

func runFeeds(ctx context.Context, c daemonv1.DaemonServiceClient, st *feeds.Store, n int) error {
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
		runDir, err := detonateQuiet(ctx, c, it.URL)
		it.RunID = filepath.Base(runDir)
		switch {
		case runDir == "":
			it.Status, it.Error = "refused", errString(err)
		case err != nil:
			it.Status, it.Error = "failed", errString(err)
		default:
			it.Status = "done"
		}
		if runDir != "" {
			if werr := report.WriteFeed(runDir, report.FeedMeta{Name: it.Feed, FirstSeen: it.FirstSeen}); werr == nil {
				report.Write(runDir) // rebuild with run.feed
			}
		}
		if err != nil {
			fmt.Printf("  %s: %v\n", it.Status, err)
		}
		if runDir != "" {
			printSummary(runDir)
		}
		if err := st.Save(); err != nil {
			return err
		}
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// detonateQuiet runs one URL and returns its run directory (empty if the daemon refused it).
func detonateQuiet(ctx context.Context, c daemonv1.DaemonServiceClient, url string) (string, error) {
	stream, err := c.Detonate(ctx, &daemonv1.DetonateRequest{Url: url})
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
