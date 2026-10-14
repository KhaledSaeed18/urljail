package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto"
	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/cdp"
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
	b := a.takePrepared()
	if b == nil {
		var err error
		if b, err = startBrowser(ctx, req.GetProfile(), a.browser); err != nil {
			return done, err
		}
	} else {
		b.discardQueued() // events from about:blank before the snapshot aren't this run's
	}
	ch, targetID := b.ch, b.targetID
	bctx := cdpctx.WithExecutor(ctx, b.browser)
	pctx := cdpctx.WithExecutor(ctx, b.page)
	defer func() {
		ch.close()
		// Ship the key log and Chrome's own log even when the run failed: they're evidence.
		for _, f := range []struct{ path, name string }{{keyLogPath, "sslkeys.log"}, {chromeLog, "chrome.log"}} {
			if err := sendFile(out, f.path, f.name); err != nil && !errors.Is(err, os.ErrNotExist) {
				a.log.Warn("sending artifact", "name", f.name, "err", err)
			}
		}
	}()

	act := newActivity()
	fwdCtx, stopFwd := context.WithCancel(ctx)
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		a.forward(fwdCtx, ch.conn.Events(), out, act, pctx, ch.conn)
	}()

	if err := out.progress(guestv1.Stage_STAGE_NAVIGATING, req.GetUrl()); err != nil {
		stopFwd()
		return done, err
	}
	start := time.Now()
	// Page.navigate returns once the server answers. A server that accepts the connection and
	// never answers (found in P6) would hold it until the run's deadline and lose every
	// artifact, so it's bounded by the longest observation.
	// 12 s at most: with stopping (2 s) and collection (12 s) it stays inside the daemon's
	// default 30 s run limit.
	navLimit := min(req.GetMaxDwell().AsDuration(), 12*time.Second)
	if navLimit <= 0 {
		navLimit = 12 * time.Second
	}
	nctx, ncancel := context.WithTimeout(pctx, navLimit)
	_, _, navErr, _, err := page.Navigate(req.GetUrl()).Do(nctx)
	ncancel()
	reason := ""
	switch {
	case err != nil && nctx.Err() == context.DeadlineExceeded && ctx.Err() == nil:
		done.NavigationError = fmt.Sprintf("navigation timed out after %s (no response)", navLimit)
		sctx, scancel := context.WithTimeout(pctx, 2*time.Second)
		_ = page.StopLoading().Do(sctx)
		scancel()
		reason = "navigation timeout"
	case err != nil:
		stopFwd()
		return done, err
	default:
		done.NavigationError = navErr
		if err := out.progress(guestv1.Stage_STAGE_OBSERVING, "waiting for network idle"); err != nil {
			stopFwd()
			return done, err
		}
		reason = observe(ctx, act, start, req)
	}
	done.Dwell = durationpb.New(time.Since(start))
	done.DwellReason = reason

	if err := out.progress(guestv1.Stage_STAGE_COLLECTING, "screenshot, DOM, final URL"); err != nil {
		stopFwd()
		return done, err
	}
	collectErr := a.collect(pctx, bctx, targetID, out, done)
	if err := a.collectFavicons(ctx, ch.conn, act, out); err != nil && collectErr == nil {
		collectErr = err
	}
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
	// Each step has its own limit: a page that keeps its renderer busy (found in P6 on a
	// phishing page) blocks the screenshot and the DOM forever, and the run's deadline would
	// then lose every artifact. Final URL and title come from the browser process, so first.
	step := func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(parent, d)
	}
	ctx, cancel := step(bctx, 2*time.Second)
	if info, err := target.GetTargetInfo().WithTargetID(targetID).Do(ctx); err != nil {
		errs = append(errs, fmt.Errorf("target info: %w", err))
	} else {
		done.FinalUrl, done.Title = info.URL, info.Title
	}
	cancel()
	// Read the DOM through the protocol, without running script in the page.
	ctx, cancel = step(pctx, 5*time.Second)
	if html, err := outerHTML(ctx); err != nil {
		errs = append(errs, fmt.Errorf("dom: %w", err))
	} else if err := sendBytes(out, "dom.html", []byte(html)); err != nil {
		cancel()
		return err
	}
	cancel()
	ctx, cancel = step(pctx, 5*time.Second)
	defer cancel()
	if png, err := page.CaptureScreenshot().Do(ctx); err != nil {
		errs = append(errs, fmt.Errorf("screenshot: %w", err))
	} else if err := sendBytes(out, "screenshot.png", png); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// maxFaviconBytes caps one favicon (a real one is a few KiB).
const maxFaviconBytes = 256 << 10

// collectFavicons sends the bodies of the favicons Chrome loaded (favicon-0..3) and a manifest
// (favicons.json) naming each one's URL and type. Unreadable ones are left out.
func (a *agent) collectFavicons(ctx context.Context, conn *cdp.Conn, act *activity, out *sender) error {
	act.mu.Lock()
	refs := append([]faviconRef(nil), act.favicons...)
	act.mu.Unlock()
	var sent []faviconRef
	for _, f := range refs {
		fctx, cancel := context.WithTimeout(cdpctx.WithExecutor(ctx, conn.Session(f.session)), 2*time.Second)
		body, err := network.GetResponseBody(f.requestID).Do(fctx)
		cancel()
		if err != nil || len(body) == 0 || len(body) > maxFaviconBytes {
			continue
		}
		f.File = fmt.Sprintf("favicon-%d", len(sent))
		if err := sendBytes(out, f.File, body); err != nil {
			return err
		}
		sent = append(sent, f)
	}
	if len(sent) == 0 {
		return nil
	}
	b, err := json.Marshal(sent)
	if err != nil {
		return err
	}
	return sendBytes(out, "favicons.json", b)
}

// outerHTML serializes the document. A page that replaces its document between the two calls
// (a script redirect or document.write during collection; found in P7 on 4 of 40 feed URLs)
// invalidates the node ID: the read is retried once against the new document.
func outerHTML(ctx context.Context) (string, error) {
	var err error
	for range 2 {
		var root *cdpctx.Node
		if root, err = dom.GetDocument().Do(ctx); err != nil {
			return "", err
		}
		var html string
		if html, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx); err == nil {
			return html, nil
		}
		if !strings.Contains(err.Error(), "Could not find node") {
			return "", err
		}
	}
	return "", err
}

// forward streams every CDP event to the host, feeds the network-idle tracker, and
// dismisses JavaScript dialogs so they can't stall the page.
func (a *agent) forward(ctx context.Context, events <-chan *cdproto.Message, out *sender, act *activity, pctx context.Context, conn *cdp.Conn) {
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
					a.forwardOne(m, out, act, pctx, conn)
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
		a.forwardOne(msg, out, act, pctx, conn)
	}
}

func (a *agent) forwardOne(msg *cdproto.Message, out *sender, act *activity, pctx context.Context, conn *cdp.Conn) {
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
	case *network.EventResponseReceived:
		// Chrome loads favicons itself: type Other, an image. Bodies are read at collection
		// from the browser's memory (no network request, nothing the page can see).
		if e.Type == network.ResourceTypeOther && e.Response != nil && e.Response.Status == 200 &&
			strings.HasPrefix(e.Response.MimeType, "image/") {
			act.addFavicon(faviconRef{session: msg.SessionID, requestID: e.RequestID, URL: e.Response.URL, MimeType: e.Response.MimeType})
		}
	case *network.EventLoadingFinished:
		act.finish(string(e.RequestID))
	case *network.EventLoadingFailed:
		act.finish(string(e.RequestID))
	case *page.EventLifecycleEvent:
		if e.Name == "networkIdle" {
			act.networkIdle()
		}
	case *target.EventAttachedToTarget:
		go attachChild(pctx, conn, e.SessionID, string(e.TargetInfo.Type))
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
	favicons []faviconRef // browser-initiated image loads: the page's favicons
}

// faviconRef is a favicon response, kept so its body can be read at collection.
type faviconRef struct {
	session   target.SessionID
	requestID network.RequestID
	URL       string `json:"url"`
	MimeType  string `json:"mime"`
	File      string `json:"file,omitempty"`
}

const maxFavicons = 4

func (a *activity) addFavicon(f faviconRef) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, g := range a.favicons {
		if g.URL == f.URL {
			return
		}
	}
	if len(a.favicons) < maxFavicons {
		a.favicons = append(a.favicons, f)
	}
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

// attachChild sets up a worker or out-of-process iframe the page auto-attached to: its
// Network domain (its requests aren't the page session's), auto-attach for what it starts in
// turn, then lets it run. It was paused at start so no request is missed, and is always
// released, even if setting up failed. Found in P7: a worker's request (logx.optimizely.com on
// www.bbc.com) seen by the host and missing from the guest's report.
func attachChild(parent context.Context, conn *cdp.Conn, id target.SessionID, kind string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	sctx := cdpctx.WithExecutor(ctx, conn.Session(id))
	defer func() { _ = runtime.RunIfWaitingForDebugger().Do(sctx) }()
	switch kind {
	case "worker", "shared_worker", "service_worker", "iframe":
		_ = network.Enable().Do(sctx)
		_ = target.SetAutoAttach(true, true).WithFlatten(true).Do(sctx)
	}
}
