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
	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/report"
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
	rep, err := report.Build(runDir)
	if err != nil {
		return brands.Ref{}, err
	}
	final := rep.GetNavigation().GetFinalUrl()
	if reg := brands.DomainOf(final); !b.Owns(reg) {
		return brands.Ref{}, fmt.Errorf("ended on %s, not %s's", reg, b.Name)
	}
	var favs []string
	for _, f := range rep.GetPage().GetFavicons() {
		favs = append(favs, f.GetSha256())
	}
	// Only scheme, host and path: sign-in redirects carry nonces and session state.
	if u, err := url.Parse(final); err == nil {
		u.RawQuery, u.Fragment = "", ""
		final = u.String()
	}
	ref := brands.Ref{Brand: b.ID, URL: b.Login, Final: final, Profile: profile,
		Taken: time.Now().UTC().Format("2006-01-02"), Run: filepath.Base(runDir), Favicons: favs}
	// The screenshot is a reference only for a sign-in page: one with somewhere to type.
	// Without that, bot walls (Cloudflare, DataDome), error pages and pages caught mid-render
	// became references (found in P7: 14 of 53). The favicon is the brand's either way, so
	// such a page is kept for its favicons alone.
	if hasSignInInput(rep) && rep.GetPage().GetScreenshotPhash() != "" {
		ref.Phash = rep.GetPage().GetScreenshotPhash()
	}
	if ref.Phash == "" && len(favs) == 0 {
		return brands.Ref{}, fmt.Errorf("neither a sign-in page nor a favicon (title %q)", clip(rep.GetNavigation().GetTitle(), 60))
	}
	return ref, nil
}

// hasSignInInput: a password field anywhere, or a form with a text, email or tel field.
func hasSignInInput(r *reportv0.Report) bool {
	if r.GetPage().GetPasswordFields() > 0 {
		return true
	}
	for _, f := range r.GetPage().GetForms() {
		for _, x := range f.GetFields() {
			switch x.GetType() {
			case "text", "email", "tel":
				return true
			}
		}
	}
	return false
}
