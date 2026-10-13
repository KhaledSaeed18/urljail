package report

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/visual"
)

// Schema identifies the report format.
const Schema = "urljail.report/v0"

const guestCDP = "guest.cdp"

// Write builds the report for runDir and writes runDir/report.json.
func Write(runDir string) (*reportv0.Report, error) {
	r, err := Build(runDir)
	if err != nil {
		return nil, err
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}.Marshal(r)
	if err != nil {
		return nil, err
	}
	return r, os.WriteFile(filepath.Join(runDir, "report.json"), append(b, '\n'), 0o600)
}

// Build derives a report from runDir. Missing guest files are reported as gaps, not errors:
// a failed run still gets a report that says what is and isn't known.
func Build(runDir string) (*reportv0.Report, error) {
	meta, err := ReadMeta(runDir)
	if err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	r := &reportv0.Report{
		Schema: Schema,
		Run: &reportv0.Run{
			Id:           meta.RunID,
			SubmittedUrl: meta.URL,
			Profile:      meta.Profile,
			Egress:       &reportv0.Egress{Mode: meta.Egress},
			StartedAt:    ts(meta.StartedAt),
			EndedAt:      ts(meta.EndedAt),
			Status:       meta.Status,
			Error:        meta.Error,
			Versions:     meta.Versions,
			Feed:         readFeed(runDir),
		},
		Navigation: &reportv0.Navigation{},
		Network:    &reportv0.Network{},
		Page:       &reportv0.Page{},
		Artifacts:  artifacts(runDir),
	}

	r.Gaps = append(r.Gaps,
		"No interaction simulated: content behind clicks, CAPTCHAs or other gates was not reached",
		"QUIC, Encrypted Client Hello and DNS-over-HTTPS are disabled by browser policy",
	)
	if c := meta.Clone; c != nil {
		r.Run.Clone = &reportv0.Clone{Snapshot: c.Snapshot, GuestClockSkewMs: int32(c.GuestClockSkewMs), VmgenidReseed: c.VMGenIDReseed}
		r.Gaps = append(r.Gaps, "Restored from snapshot "+c.Snapshot+": the guest kernel's RNG is reseeded on restore (VMGenID), but Chrome's userspace RNG state is copied from the snapshot (research R2)")
		if !c.VMGenIDReseed {
			r.Gaps = append(r.Gaps, "The guest kernel didn't log a VMGenID reseed: this clone may share kernel RNG state with others from the same snapshot")
		}
	}
	r.Gaps = append(r.Gaps, meta.HostGaps...)
	if g := retentionGap(runDir); g != "" {
		r.Gaps = append(r.Gaps, g)
	}
	if meta.Status != "completed" {
		r.Gaps = append(r.Gaps, fmt.Sprintf("Run ended with status %q: observations may be incomplete", meta.Status))
	}

	if d, err := readDone(runDir); err == nil {
		n := r.Navigation
		n.FinalUrl, n.Title, n.Error, n.DwellReason = d.FinalURL, d.Title, d.NavigationError, d.DwellReason
		if dur, err := time.ParseDuration(d.Dwell); err == nil {
			n.DwellMs = clampU32(float64(dur.Milliseconds()))
		}
		if d.Error != "" {
			// Guest-controlled text: valid UTF-8, bounded.
			msg := strings.ToValidUTF8(d.Error, "?")
			if len(msg) > 300 {
				msg = msg[:300] + "…"
			}
			r.Gaps = append(r.Gaps, "The guest agent reported an error (guest-attested): "+msg)
		}
		if d.DroppedEvents > 0 {
			r.Gaps = append(r.Gaps, fmt.Sprintf("%d CDP events were dropped and are missing from this report", d.DroppedEvents))
		}
	} else {
		r.Gaps = append(r.Gaps, "The guest agent sent no result (guest/done.json missing)")
	}

	evs, err := readEvents(filepath.Join(runDir, "guest", "events.jsonl"))
	if err != nil {
		r.Gaps = append(r.Gaps, "No guest events (guest/events.jsonl missing or unreadable)")
		evs = nil // host records are still worth reporting, especially when the guest failed
	}
	b := newBuilder()
	for _, e := range evs {
		b.add(e)
	}
	b.finish(r)
	if r.Artifacts.GetScreenshot() != "" {
		switch h, err := visual.HashFile(filepath.Join(runDir, "guest", "screenshot.png")); {
		case errors.Is(err, visual.ErrBlank):
			r.Page.ScreenshotBlank = true
		case err != nil:
			r.Gaps = append(r.Gaps, "The screenshot couldn't be decoded for its perceptual hash")
		default:
			r.Page.ScreenshotPhash = h.String()
		}
	}
	if !addHost(r, runDir, b.reportHosts, b.headerHints) {
		r.Gaps = append(r.Gaps, "No host-side records (run from before P3): every network observation is guest-attested (source guest.cdp)")
	}
	return r, nil
}

// event is one line of guest/events.jsonl.
type event struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func readEvents(path string) ([]event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var evs []event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			evs = append(evs, e)
		}
	}
	return evs, sc.Err()
}

// done is guest/done.json (the guest's Done message in protojson).
type done struct {
	FinalURL, Title, NavigationError, Dwell, DwellReason, Error string
	DroppedEvents                                               int64
}

func readDone(runDir string) (done, error) {
	var d done
	b, err := os.ReadFile(filepath.Join(runDir, "guest", "done.json"))
	if err != nil {
		return d, err
	}
	// protojson writes int64 as a string and Duration as "1.5s"; tolerate both shapes.
	var loose map[string]any
	if err := json.Unmarshal(b, &loose); err != nil {
		return d, err
	}
	str := func(k string) string { s, _ := loose[k].(string); return s }
	d.FinalURL, d.Title, d.NavigationError, d.Dwell, d.DwellReason =
		str("final_url"), str("title"), str("navigation_error"), str("dwell"), str("dwell_reason")
	d.Error = str("error")
	switch v := loose["dropped_events"].(type) {
	case string:
		fmt.Sscan(v, &d.DroppedEvents)
	case float64:
		d.DroppedEvents = int64(v)
	}
	return d, nil
}

func artifacts(runDir string) *reportv0.Artifacts {
	rel := func(p string) string {
		if _, err := os.Stat(filepath.Join(runDir, p)); err != nil {
			return ""
		}
		return p
	}
	return &reportv0.Artifacts{
		Screenshot:     rel("guest/screenshot.png"),
		Dom:            rel("guest/dom.html"),
		Sslkeylog:      rel("guest/sslkeys.log"),
		Events:         rel("guest/events.jsonl"),
		ChromeLog:      rel("guest/chrome.log"),
		SerialLog:      rel("host/serial.log"),
		FirecrackerLog: rel("host/firecracker.log"),
		Pcap:           rel("host/capture.pcap"),
	}
}

// CDP params, only the fields the report uses. Everything here is guest-supplied.
type (
	cdpResponse struct {
		URL             string         `json:"url"`
		Status          float64        `json:"status"`
		RemoteIPAddress string         `json:"remoteIPAddress"`
		Protocol        string         `json:"protocol"`
		FromDiskCache   bool           `json:"fromDiskCache"`
		Headers         map[string]any `json:"headers"`
		SecurityDetails *struct {
			Protocol    string   `json:"protocol"`
			SubjectName string   `json:"subjectName"`
			Issuer      string   `json:"issuer"`
			ValidFrom   float64  `json:"validFrom"`
			ValidTo     float64  `json:"validTo"`
			SanList     []string `json:"sanList"`
		} `json:"securityDetails"`
	}
	requestWillBeSent struct {
		RequestID string `json:"requestId"`
		FrameID   string `json:"frameId"`
		Type      string `json:"type"`
		Request   struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		} `json:"request"`
		Initiator struct {
			Type string `json:"type"`
		} `json:"initiator"`
		RedirectResponse *cdpResponse `json:"redirectResponse"`
	}
	responseReceived struct {
		RequestID string      `json:"requestId"`
		FrameID   string      `json:"frameId"`
		Type      string      `json:"type"`
		Response  cdpResponse `json:"response"`
	}
	loadingFinished struct {
		RequestID         string  `json:"requestId"`
		EncodedDataLength float64 `json:"encodedDataLength"`
	}
	loadingFailed struct {
		RequestID     string `json:"requestId"`
		ErrorText     string `json:"errorText"`
		BlockedReason string `json:"blockedReason"`
	}
	frameNavigated struct {
		Frame struct {
			ID       string `json:"id"`
			ParentID string `json:"parentId"`
		} `json:"frame"`
	}
	frameRequestedNavigation struct {
		FrameID string `json:"frameId"`
		Reason  string `json:"reason"`
	}
	dialogOpening struct {
		URL     string `json:"url"`
		Message string `json:"message"`
		Type    string `json:"type"`
	}
	downloadWillBegin struct {
		GUID              string `json:"guid"`
		URL               string `json:"url"`
		SuggestedFilename string `json:"suggestedFilename"`
	}
	downloadProgress struct {
		GUID          string  `json:"guid"`
		ReceivedBytes float64 `json:"receivedBytes"`
		State         string  `json:"state"`
	}
)

type builder struct {
	mainFrame   string
	pendingKind string
	hops        []*reportv0.Hop
	requests    []*reportv0.Request
	byID        map[string]*reportv0.Request
	tls         map[string]*reportv0.Tls
	hosts       map[string]bool
	reportHosts map[string]bool // Reporting API / NEL endpoints named in response headers
	headerHints map[string]bool // preconnect and other hints named in Link response headers
	dataURLs    int
	dialogs     []*reportv0.Dialog
	downloads   map[string]*reportv0.Download
	dlOrder     []string
}

func newBuilder() *builder {
	return &builder{
		pendingKind: "initial",
		byID:        map[string]*reportv0.Request{},
		tls:         map[string]*reportv0.Tls{},
		hosts:       map[string]bool{},
		reportHosts: map[string]bool{},
		headerHints: map[string]bool{},
		downloads:   map[string]*reportv0.Download{},
	}
}

func (b *builder) add(e event) {
	switch e.Method {
	case "Page.frameNavigated":
		var p frameNavigated
		if json.Unmarshal(e.Params, &p) == nil && p.Frame.ParentID == "" && b.mainFrame == "" {
			b.mainFrame = p.Frame.ID
		}
	case "Page.frameRequestedNavigation":
		var p frameRequestedNavigation
		if json.Unmarshal(e.Params, &p) == nil && (b.mainFrame == "" || p.FrameID == b.mainFrame) {
			b.pendingKind = navKind(p.Reason)
		}
	case "Network.requestWillBeSent":
		var p requestWillBeSent
		if json.Unmarshal(e.Params, &p) != nil {
			return
		}
		b.request(p)
	case "Network.responseReceived":
		var p responseReceived
		if json.Unmarshal(e.Params, &p) != nil {
			return
		}
		if req := b.byID[p.RequestID]; req != nil {
			fillResponse(req, &p.Response)
		}
		b.addTLS(&p.Response)
		for _, h := range reportEndpointHosts(p.Response.Headers) {
			if len(b.reportHosts) < maxReportHosts {
				b.reportHosts[h] = true
			}
		}
		for _, h := range linkHeaderHosts(p.Response.Headers, p.Response.URL) {
			if len(b.headerHints) < maxHeaderHints {
				b.headerHints[h] = true
			}
		}
		if p.Type == "Document" && b.isMain(p.FrameID) {
			for i := len(b.hops) - 1; i >= 0; i-- {
				if b.hops[i].Url == p.Response.URL && b.hops[i].Status == 0 {
					b.hops[i].Status = int32(p.Response.Status)
					break
				}
			}
		}
	case "Network.webSocketCreated":
		// WebSockets don't go through requestWillBeSent (found in P7: pusher.com connections the
		// host saw were "unexplained").
		var p struct {
			RequestID string `json:"requestId"`
			URL       string `json:"url"`
			Initiator struct {
				Type string `json:"type"`
			} `json:"initiator"`
		}
		if json.Unmarshal(e.Params, &p) != nil {
			return
		}
		ws := requestWillBeSent{RequestID: p.RequestID, Type: "WebSocket"}
		ws.Request.URL, ws.Request.Method, ws.Initiator.Type = p.URL, "GET", p.Initiator.Type
		b.request(ws)
	case "Network.webSocketHandshakeResponseReceived":
		var p struct {
			RequestID string `json:"requestId"`
			Response  struct {
				Status float64 `json:"status"`
			} `json:"response"`
		}
		if json.Unmarshal(e.Params, &p) == nil && b.byID[p.RequestID] != nil {
			b.byID[p.RequestID].Status = int32(p.Response.Status)
		}
	case "Network.requestServedFromCache":
		var p struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(e.Params, &p) == nil && b.byID[p.RequestID] != nil {
			b.byID[p.RequestID].FromCache = true
		}
	case "Network.loadingFinished":
		var p loadingFinished
		if json.Unmarshal(e.Params, &p) == nil && b.byID[p.RequestID] != nil {
			b.byID[p.RequestID].Bytes = clampU32(p.EncodedDataLength)
		}
	case "Network.loadingFailed":
		var p loadingFailed
		if json.Unmarshal(e.Params, &p) == nil && b.byID[p.RequestID] != nil {
			msg := p.ErrorText
			if p.BlockedReason != "" {
				msg += " (blocked: " + p.BlockedReason + ")"
			}
			b.byID[p.RequestID].Error = msg
		}
	case "Page.javascriptDialogOpening":
		var p dialogOpening
		if json.Unmarshal(e.Params, &p) == nil {
			b.dialogs = append(b.dialogs, &reportv0.Dialog{Type: p.Type, Message: p.Message, Url: p.URL, Source: guestCDP})
		}
	case "Browser.downloadWillBegin", "Page.downloadWillBegin":
		var p downloadWillBegin
		if json.Unmarshal(e.Params, &p) == nil && b.downloads[p.GUID] == nil {
			b.downloads[p.GUID] = &reportv0.Download{Url: p.URL, Filename: p.SuggestedFilename, State: "inProgress", Source: guestCDP}
			b.dlOrder = append(b.dlOrder, p.GUID)
		}
	case "Browser.downloadProgress", "Page.downloadProgress":
		var p downloadProgress
		if json.Unmarshal(e.Params, &p) == nil && b.downloads[p.GUID] != nil {
			b.downloads[p.GUID].State = p.State
			b.downloads[p.GUID].Bytes = clampU32(p.ReceivedBytes)
		}
	}
}

func (b *builder) isMain(frame string) bool { return b.mainFrame == "" || frame == b.mainFrame }

func (b *builder) request(p requestWillBeSent) {
	if strings.HasPrefix(p.Request.URL, "data:") {
		b.dataURLs++
		return
	}
	// A redirect reuses the request ID: close the previous hop of this request first.
	if prev := b.byID[p.RequestID]; prev != nil && p.RedirectResponse != nil {
		fillResponse(prev, p.RedirectResponse)
		b.addTLS(p.RedirectResponse)
	}
	req := &reportv0.Request{
		Url:       p.Request.URL,
		Method:    p.Request.Method,
		Type:      p.Type,
		Initiator: p.Initiator.Type,
		Source:    guestCDP,
	}
	b.requests = append(b.requests, req)
	b.byID[p.RequestID] = req
	if u, err := url.Parse(p.Request.URL); err == nil && u.Hostname() != "" {
		b.hosts[strings.ToLower(u.Hostname())] = true
	}

	if p.Type == "Document" && b.isMain(p.FrameID) {
		if b.mainFrame == "" {
			b.mainFrame = p.FrameID
		}
		kind := b.pendingKind
		if p.RedirectResponse != nil {
			kind = "http"
			if n := len(b.hops); n > 0 && b.hops[n-1].Url == p.RedirectResponse.URL {
				b.hops[n-1].Status = int32(p.RedirectResponse.Status)
			}
		}
		b.pendingKind = "other" // a later navigation with no recorded reason
		b.hops = append(b.hops, &reportv0.Hop{Url: p.Request.URL, Kind: kind, Source: guestCDP})
	}
}

func fillResponse(req *reportv0.Request, r *cdpResponse) {
	req.Status = int32(r.Status)
	req.RemoteIp = r.RemoteIPAddress
	req.Protocol = r.Protocol
	if r.FromDiskCache {
		req.FromCache = true
	}
}

func (b *builder) addTLS(r *cdpResponse) {
	sd := r.SecurityDetails
	if sd == nil {
		return
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := strings.ToLower(u.Hostname())
	if b.tls[host] != nil {
		return
	}
	b.tls[host] = &reportv0.Tls{
		Host:      host,
		Protocol:  sd.Protocol,
		Subject:   sd.SubjectName,
		Issuer:    sd.Issuer,
		NotBefore: epoch(sd.ValidFrom),
		NotAfter:  epoch(sd.ValidTo),
		San:       sd.SanList,
		Source:    guestCDP,
	}
}

func (b *builder) finish(r *reportv0.Report) {
	r.Navigation.RedirectChain = b.hops
	r.Network.Requests = b.requests

	hosts := make([]string, 0, len(b.tls))
	for h := range b.tls {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		r.Network.Tls = append(r.Network.Tls, b.tls[h])
	}

	groups := map[string][]string{}
	for h := range b.hosts {
		reg := h
		if net.ParseIP(h) == nil {
			if e, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
				reg = e
			}
		}
		groups[reg] = append(groups[reg], h)
	}
	regs := make([]string, 0, len(groups))
	for reg := range groups {
		regs = append(regs, reg)
	}
	sort.Strings(regs)
	for _, reg := range regs {
		sort.Strings(groups[reg])
		r.Network.Domains = append(r.Network.Domains, &reportv0.Domain{Registrable: reg, Hosts: groups[reg]})
	}

	r.Page.Dialogs = b.dialogs
	for _, g := range b.dlOrder {
		r.Page.Downloads = append(r.Page.Downloads, b.downloads[g])
	}
	if len(b.dlOrder) > 0 {
		r.Gaps = append(r.Gaps, "Downloads are recorded from CDP, but their files are not collected from the guest yet")
	}
	if b.dataURLs > 0 {
		r.Gaps = append(r.Gaps, fmt.Sprintf("%d data: URLs omitted from network.requests", b.dataURLs))
	}
}

// navKind maps Chrome's Page.frameRequestedNavigation reasons to hop kinds.
func navKind(reason string) string {
	switch reason {
	case "scriptInitiated":
		return "js"
	case "metaTagRefresh":
		return "meta"
	case "httpHeaderRefresh":
		return "header"
	default:
		return "other"
	}
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func epoch(sec float64) *timestamppb.Timestamp {
	if sec <= 0 || math.IsNaN(sec) || math.IsInf(sec, 0) {
		return nil
	}
	return timestamppb.New(time.Unix(int64(sec), 0).UTC())
}

func clampU32(v float64) uint32 {
	switch {
	case math.IsNaN(v) || v <= 0:
		return 0
	case v >= math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(v)
}
