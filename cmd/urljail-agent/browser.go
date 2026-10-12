package main

import (
	"context"
	"time"

	cdpbrowser "github.com/chromedp/cdproto/browser"
	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/cdp"
)

// browserSession is a running Chrome, attached to its startup tab, with the domains enabled.
type browserSession struct {
	ch       *chrome
	targetID target.ID
	browser  cdp.Session
	page     cdp.Session
}

// startBrowser launches Chrome and sets it up for a detonation.
func startBrowser(ctx context.Context) (*browserSession, error) {
	ch, err := launchChrome()
	if err != nil {
		return nil, err
	}
	b := &browserSession{ch: ch, browser: ch.conn.Browser()}
	ok := false
	defer func() {
		if !ok {
			ch.close()
		}
	}()
	bctx := cdpctx.WithExecutor(ctx, b.browser)
	// Drive the tab Chrome opened at startup: it is the foreground tab. A tab created with
	// Target.createTarget is a background tab, which reports visibilityState "hidden",
	// throttles timers and doesn't paint (found in P2 M4).
	if b.targetID, err = initialTab(bctx); err != nil {
		return nil, err
	}
	sessionID, err := target.AttachToTarget(b.targetID).WithFlatten(true).Do(bctx)
	if err != nil {
		return nil, err
	}
	b.page = ch.conn.Session(sessionID)
	pctx := cdpctx.WithExecutor(ctx, b.page)

	// The only domains enabled (ADR 0013). No Runtime.enable: it is a well-known way for
	// pages to detect automation, and nothing here needs it.
	for _, step := range []func() error{
		func() error { return network.Enable().Do(pctx) },
		func() error { return page.Enable().Do(pctx) },
		func() error { return page.SetLifecycleEventsEnabled(true).Do(pctx) },
		func() error {
			return cdpbrowser.SetDownloadBehavior(cdpbrowser.SetDownloadBehaviorBehaviorAllowAndName).
				WithDownloadPath(downloadDir).WithEventsEnabled(true).Do(bctx)
		},
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	ok = true
	return b, nil
}

// discardQueued drops CDP events that arrived before this detonation started.
func (b *browserSession) discardQueued() {
	for {
		select {
		case _, ok := <-b.ch.conn.Events():
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// Prepare implements GuestAgentService.Prepare.
func (a *agent) Prepare(ctx context.Context, _ *guestv1.PrepareRequest) (*guestv1.PrepareResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.prepared != nil {
		return nil, status.Error(codes.FailedPrecondition, "a browser is already prepared")
	}
	start := time.Now()
	b, err := startBrowser(ctx)
	if err != nil {
		return nil, err
	}
	a.prepared = b
	a.log.Info("browser prepared", "took", time.Since(start))
	return &guestv1.PrepareResponse{Took: durationpb.New(time.Since(start))}, nil
}

func (a *agent) takePrepared() *browserSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.prepared
	a.prepared = nil
	return b
}
