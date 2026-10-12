package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto"
	cdpbrowser "github.com/chromedp/cdproto/browser"
	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

const (
	downloadDir = runDir + "/downloads"
	chunkSize   = 1 << 20 // gRPC's default message limit is 4 MiB (ADR 0007)
	quietPeriod = 500 * time.Millisecond
)

// sender serializes stream.Send, which isn't safe for concurrent use.
type sender struct {
	mu     sync.Mutex
	stream guestv1.GuestAgentService_DetonateServer
}

func (s *sender) send(m *guestv1.DetonateResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(m)
}

func (s *sender) progress(stage guestv1.Stage, msg string) error {
	return s.send(&guestv1.DetonateResponse{Msg: &guestv1.DetonateResponse_Progress{
		Progress: &guestv1.Progress{Stage: stage, Message: msg}}})
}

func (a *agent) Detonate(req *guestv1.DetonateRequest, stream guestv1.GuestAgentService_DetonateServer) error {
	if !a.busy.CompareAndSwap(false, true) {
		return status.Error(codes.FailedPrecondition, "a detonation is already running")
	}
	defer a.busy.Store(false)

	out := &sender{stream: stream}
	done, err := a.detonate(stream.Context(), req, out)
	if err != nil {
		done.Error = err.Error()
		a.log.Warn("detonation failed", "err", err)
	}
	return out.send(&guestv1.DetonateResponse{Msg: &guestv1.DetonateResponse_Done{Done: done}})
}

func (a *agent) detonate(ctx context.Context, req *guestv1.DetonateRequest, out *sender) (*guestv1.Done, error) {
	done := &guestv1.Done{}
	ch, err := launchChrome()
	if err != nil {
		return done, err
	}
	defer func() {
		ch.close()
		// Ship the key log and Chrome's own log even when the run failed: they're evidence.
		for _, f := range []struct{ path, name string }{{keyLogPath, "sslkeys.log"}, {chromeLog, "chrome.log"}} {
			if err := sendFile(out, f.path, f.name); err != nil && !errors.Is(err, os.ErrNotExist) {
				a.log.Warn("sending artifact", "name", f.name, "err", err)
			}
		}
	}()

	bctx := cdpctx.WithExecutor(ctx, ch.conn.Browser())
	// Drive the tab Chrome opened at startup: it is the foreground tab. A tab created with
	// Target.createTarget is a background tab, which reports visibilityState "hidden",
	// throttles timers and doesn't paint (found in M4: first paint only came when the
	// screenshot forced it).
	targetID, err := initialTab(bctx)
	if err != nil {
		return done, err
	}
	sessionID, err := target.AttachToTarget(targetID).WithFlatten(true).Do(bctx)
	if err != nil {
		return done, err
	}
	pctx := cdpctx.WithExecutor(ctx, ch.conn.Session(sessionID))

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
			return done, err
		}
	}

	act := newActivity()
	fwdCtx, stopFwd := context.WithCancel(ctx)
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		a.forward(fwdCtx, ch.conn.Events(), out, act, pctx)
	}()

	if err := out.progress(guestv1.Stage_STAGE_NAVIGATING, req.GetUrl()); err != nil {
		stopFwd()
		return done, err
	}
	start := time.Now()
	_, _, navErr, _, err := page.Navigate(req.GetUrl()).Do(pctx)
	if err != nil {
		stopFwd()
		return done, err
	}
	done.NavigationError = navErr

	if err := out.progress(guestv1.Stage_STAGE_OBSERVING, "waiting for network idle"); err != nil {
		stopFwd()
		return done, err
	}
	reason := observe(ctx, act, start, req)
	done.Dwell = durationpb.New(time.Since(start))
	done.DwellReason = reason

	if err := out.progress(guestv1.Stage_STAGE_COLLECTING, "screenshot, DOM, final URL"); err != nil {
		stopFwd()
		return done, err
	}
	collectErr := a.collect(pctx, bctx, targetID, out, done)
	stopFwd()
	<-fwdDone
	done.DroppedEvents = ch.conn.Dropped()
	if reason == "cancelled" {
		return done, ctx.Err()
	}
	return done, collectErr
}

// initialTab waits for the page target Chrome opens from its command line.
func initialTab(bctx context.Context) (target.ID, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		infos, err := target.GetTargets().Do(bctx)
		if err != nil {
			return "", err
		}
		for _, t := range infos {
			if t.Type == "page" {
				return t.TargetID, nil
			}
		}
		if time.Now().After(deadline) {
			return "", errors.New("chrome opened no page target")
		}
		select {
		case <-bctx.Done():
			return "", bctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// observe waits for at least min_dwell plus jitter, then until the network has been quiet
// (or Chrome reports networkIdle), or max_dwell at the latest.
func observe(ctx context.Context, act *activity, start time.Time, req *guestv1.DetonateRequest) string {
	minDwell := req.GetMinDwell().AsDuration()
	if j := req.GetJitter().AsDuration(); j > 0 {
		minDwell += rand.N(j)
	}
	maxDwell := req.GetMaxDwell().AsDuration()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return "cancelled"
		case <-t.C:
		}
		elapsed := time.Since(start)
		if elapsed >= maxDwell {
			return "max dwell"
		}
		if elapsed >= minDwell && act.idle() {
			return "network idle"
		}
	}
}

func (a *agent) collect(pctx, bctx context.Context, targetID target.ID, out *sender, done *guestv1.Done) error {
	var errs []error
	if png, err := page.CaptureScreenshot().Do(pctx); err != nil {
		errs = append(errs, fmt.Errorf("screenshot: %w", err))
	} else if err := sendBytes(out, "screenshot.png", png); err != nil {
		return err
	}
	// Read the DOM through the protocol, without running script in the page.
	if root, err := dom.GetDocument().Do(pctx); err != nil {
		errs = append(errs, fmt.Errorf("dom: %w", err))
	} else if html, err := dom.GetOuterHTML().WithNodeID(root.NodeID).Do(pctx); err != nil {
		errs = append(errs, fmt.Errorf("dom: %w", err))
	} else if err := sendBytes(out, "dom.html", []byte(html)); err != nil {
		return err
	}
	if info, err := target.GetTargetInfo().WithTargetID(targetID).Do(bctx); err != nil {
		errs = append(errs, fmt.Errorf("target info: %w", err))
	} else {
		done.FinalUrl, done.Title = info.URL, info.Title
	}
	return errors.Join(errs...)
}

// forward streams every CDP event to the host, feeds the network-idle tracker, and
// dismisses JavaScript dialogs so they can't stall the page.
func (a *agent) forward(ctx context.Context, events <-chan *cdproto.Message, out *sender, act *activity, pctx context.Context) {
	for {
		var msg *cdproto.Message
		select {
		case <-ctx.Done():
			// Drain what's already queued, so events from the last moments aren't lost.
			for {
				select {
				case m, ok := <-events:
					if !ok {
						return
					}
					a.forwardOne(m, out, act, pctx)
				default:
					return
				}
			}
		case m, ok := <-events:
			if !ok {
				return
			}
			msg = m
		}
		a.forwardOne(msg, out, act, pctx)
	}
}

func (a *agent) forwardOne(msg *cdproto.Message, out *sender, act *activity, pctx context.Context) {
	_ = out.send(&guestv1.DetonateResponse{Msg: &guestv1.DetonateResponse_Event{Event: &guestv1.Event{
		Time:      timestamppb.Now(),
		SessionId: string(msg.SessionID),
		Method:    string(msg.Method),
		Params:    msg.Params,
	}}})
	ev, err := cdproto.UnmarshalMessage(msg)
	if err != nil {
		return // events from domains we don't track
	}
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		act.start(string(e.RequestID))
	case *network.EventLoadingFinished:
		act.finish(string(e.RequestID))
	case *network.EventLoadingFailed:
		act.finish(string(e.RequestID))
	case *page.EventLifecycleEvent:
		if e.Name == "networkIdle" {
			act.networkIdle()
		}
	case *page.EventJavascriptDialogOpening:
		go func() {
			ctx, cancel := context.WithTimeout(pctx, 2*time.Second)
			defer cancel()
			_ = page.HandleJavaScriptDialog(false).Do(ctx)
		}()
	}
}

// activity tracks in-flight requests for the dwell rule.
type activity struct {
	mu       sync.Mutex
	inflight map[string]bool
	last     time.Time
	idleSeen bool
}

func newActivity() *activity { return &activity{inflight: map[string]bool{}, last: time.Now()} }

func (a *activity) start(id string) {
	a.mu.Lock()
	a.inflight[id] = true
	a.last = time.Now()
	a.idleSeen = false
	a.mu.Unlock()
}

func (a *activity) finish(id string) {
	a.mu.Lock()
	delete(a.inflight, id)
	a.last = time.Now()
	a.mu.Unlock()
}

func (a *activity) networkIdle() {
	a.mu.Lock()
	a.idleSeen = true
	a.mu.Unlock()
}

func (a *activity) idle() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.idleSeen || (len(a.inflight) == 0 && time.Since(a.last) >= quietPeriod)
}

func sendFile(out *sender, path, name string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return sendBytes(out, filepath.Base(name), b)
}

func sendBytes(out *sender, name string, b []byte) error {
	for {
		n := min(len(b), chunkSize)
		last := n == len(b)
		if err := out.send(&guestv1.DetonateResponse{Msg: &guestv1.DetonateResponse_Artifact{
			Artifact: &guestv1.Artifact{Name: name, Data: b[:n], Last: last}}}); err != nil {
			return err
		}
		if last {
			return nil
		}
		b = b[n:]
	}
}
