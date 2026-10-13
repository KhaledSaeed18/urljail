package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/visual"
)

// cmdBrands manages the brand reference screenshots (internal/brands/refs.json).
func cmdBrands(ctx context.Context, c daemonv1.DaemonServiceClient, args []string) error {
	if len(args) == 0 || args[0] != "refs" {
		return errors.New("usage: urljail brands refs [-profiles p1,p2] [-only id,id] > internal/brands/refs.json")
	}
	fs := flag.NewFlagSet("brands refs", flag.ContinueOnError)
	profiles := fs.String("profiles", "stealth,baseline", "profiles to take each reference under (comma-separated)")
	only := fs.String("only", "", "brand IDs to take (default: all with a sign-in page)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitError(2)
	}
	want := map[string]bool{}
	for _, id := range strings.Split(*only, ",") {
		if id != "" {
			want[id] = true
		}
	}
	var refs []brands.Ref
	for _, b := range brands.All {
		if b.Login == "" || (len(want) > 0 && !want[b.ID]) {
			continue
		}
		for _, p := range strings.Split(*profiles, ",") {
			ref, err := takeRef(ctx, c, b, p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%-14s %-9s skipped: %v\n", b.ID, p, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "%-14s %-9s %s  %s\n", b.ID, p, ref.Phash, ref.Final)
			refs = append(refs, ref)
		}
	}
	out, err := json.MarshalIndent(refs, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(out, '\n'))
	return err
}

// takeRef detonates a brand's sign-in page and hashes the screenshot. A reference only counts
// when the page stayed on the brand's own domains and has a hashable screenshot.
func takeRef(ctx context.Context, c daemonv1.DaemonServiceClient, b brands.Brand, profile string) (brands.Ref, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stream, err := c.Detonate(ctx, &daemonv1.DetonateRequest{Url: b.Login, Profile: profile})
	if err != nil {
		return brands.Ref{}, err
	}
	var runDir string
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return brands.Ref{}, errors.New("stream ended without a final state")
		}
		if err != nil {
			return brands.Ref{}, err
		}
		if m.GetState() == daemonv1.RunState_RUN_STATE_FAILED {
			return brands.Ref{}, fmt.Errorf("run failed: %s", m.GetError())
		}
		if m.GetState() == daemonv1.RunState_RUN_STATE_DONE {
			runDir = m.GetRunDir()
			break
		}
	}
	var rep struct {
		Navigation struct {
			FinalURL string `json:"final_url"`
		} `json:"navigation"`
	}
	f, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return brands.Ref{}, err
	}
	if err := json.Unmarshal(f, &rep); err != nil {
		return brands.Ref{}, err
	}
	final := rep.Navigation.FinalURL
	if reg := brands.DomainOf(final); !b.Owns(reg) {
		return brands.Ref{}, fmt.Errorf("ended on %s, not %s's", reg, b.Name)
	}
	h, err := visual.HashFile(filepath.Join(runDir, "guest", "screenshot.png"))
	if err != nil {
		return brands.Ref{}, err
	}
	// Only scheme, host and path: sign-in redirects carry nonces and session state.
	if u, err := url.Parse(final); err == nil {
		u.RawQuery, u.Fragment = "", ""
		final = u.String()
	}
	return brands.Ref{Brand: b.ID, URL: b.Login, Final: final, Profile: profile, Phash: h.String(),
		Taken: time.Now().UTC().Format("2006-01-02"), Run: filepath.Base(runDir)}, nil
}
