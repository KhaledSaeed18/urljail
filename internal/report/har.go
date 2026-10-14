package report

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HAR 1.2 (http://www.softwareishard.com/blog/har-12-spec/), built from the guest's CDP events
// so a run opens in browser devtools and HAR tools. Guest-attested, like the requests in the
// report; response bodies aren't captured, so content carries sizes and types only.
type (
	harLog struct {
		Log harBody `json:"log"`
	}
	harBody struct {
		Version string     `json:"version"`
		Creator harNameVer `json:"creator"`
		Pages   []harPage  `json:"pages"`
		Entries []harEntry `json:"entries"`
		Comment string     `json:"comment"`
	}
	harNameVer struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	harPage struct {
		StartedDateTime string         `json:"startedDateTime"`
		ID              string         `json:"id"`
		Title           string         `json:"title"`
		PageTimings     map[string]int `json:"pageTimings"`
	}
	harEntry struct {
		PageRef         string         `json:"pageref"`
		StartedDateTime string         `json:"startedDateTime"`
		Time            float64        `json:"time"`
		Request         harRequest     `json:"request"`
		Response        harResponse    `json:"response"`
		Cache           struct{}       `json:"cache"`
		Timings         harTimings     `json:"timings"`
		ServerIPAddress string         `json:"serverIPAddress,omitempty"`
		ResourceType    string         `json:"_resourceType,omitempty"`
		Initiator       map[string]any `json:"_initiator,omitempty"`
		TransferSize    int64          `json:"_transferSize"`
		Error           string         `json:"_error,omitempty"`
		Comment         string         `json:"comment,omitempty"`
	}
	harRequest struct {
		Method      string   `json:"method"`
		URL         string   `json:"url"`
		HTTPVersion string   `json:"httpVersion"`
		Cookies     []harNV  `json:"cookies"`
		Headers     []harNV  `json:"headers"`
		QueryString []harNV  `json:"queryString"`
		PostData    *harPost `json:"postData,omitempty"`
		HeadersSize int      `json:"headersSize"`
		BodySize    int      `json:"bodySize"`
	}
	harResponse struct {
		Status      int        `json:"status"`
		StatusText  string     `json:"statusText"`
		HTTPVersion string     `json:"httpVersion"`
		Cookies     []harNV    `json:"cookies"`
		Headers     []harNV    `json:"headers"`
		Content     harContent `json:"content"`
		RedirectURL string     `json:"redirectURL"`
		HeadersSize int        `json:"headersSize"`
		BodySize    int        `json:"bodySize"`
	}
	harContent struct {
		Size     int64  `json:"size"`
		MimeType string `json:"mimeType"`
		Comment  string `json:"comment,omitempty"`
	}
	harPost struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
	}
	harNV struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	harTimings struct {
		Blocked float64 `json:"blocked"`
		DNS     float64 `json:"dns"`
		Connect float64 `json:"connect"`
		SSL     float64 `json:"ssl"`
		Send    float64 `json:"send"`
		Wait    float64 `json:"wait"`
		Receive float64 `json:"receive"`
	}
)

// CDP params the HAR reads (guest-supplied).
type (
	harReqEvent struct {
		RequestID string  `json:"requestId"`
		Timestamp float64 `json:"timestamp"`
		WallTime  float64 `json:"wallTime"`
		Type      string  `json:"type"`
		Request   struct {
			URL      string            `json:"url"`
			Method   string            `json:"method"`
			Headers  map[string]string `json:"headers"`
			PostData string            `json:"postData"`
		} `json:"request"`
		Initiator        map[string]any `json:"initiator"`
		RedirectResponse *harCDPResp    `json:"redirectResponse"`
	}
	harCDPResp struct {
		URL             string            `json:"url"`
		Status          float64           `json:"status"`
		StatusText      string            `json:"statusText"`
		Headers         map[string]string `json:"headers"`
		MimeType        string            `json:"mimeType"`
		Protocol        string            `json:"protocol"`
		RemoteIPAddress string            `json:"remoteIPAddress"`
		FromDiskCache   bool              `json:"fromDiskCache"`
		EncodedLength   float64           `json:"encodedDataLength"`
		Timing          *struct {
			RequestTime       float64 `json:"requestTime"`
			DNSStart          float64 `json:"dnsStart"`
			DNSEnd            float64 `json:"dnsEnd"`
			ConnectStart      float64 `json:"connectStart"`
			ConnectEnd        float64 `json:"connectEnd"`
			SSLStart          float64 `json:"sslStart"`
			SSLEnd            float64 `json:"sslEnd"`
			SendStart         float64 `json:"sendStart"`
			SendEnd           float64 `json:"sendEnd"`
			ReceiveHeadersEnd float64 `json:"receiveHeadersEnd"`
		} `json:"timing"`
	}
)

// maxHAREntries caps the entries (a page can make any number of requests).
const maxHAREntries = 20000

type harPending struct {
	e        *harEntry
	start    float64 // CDP monotonic seconds
	wall     time.Time
	respAt   float64
	resp     *harCDPResp
	finished bool
}

// BuildHAR builds the HAR for a run directory from guest/events.jsonl.
func BuildHAR(runDir string) ([]byte, error) {
	evs, err := readEvents(filepath.Join(runDir, "guest", "events.jsonl"))
	if err != nil {
		return nil, err
	}
	title := ""
	if d, err := readDone(runDir); err == nil {
		title = strings.ToValidUTF8(d.Title, "?")
	}
	var order []*harPending
	live := map[string]*harPending{} // session + requestId
	var pageStart time.Time

	finish := func(p *harPending, at float64) {
		if p.finished {
			return
		}
		p.finished = true
		fillHARResponse(p)
		if at > 0 && at >= p.start {
			p.e.Time = ms(at - p.start)
		}
		p.e.Timings = harTimingsOf(p, at)
	}
	for _, ev := range evs {
		key := ev.Session + "/"
		switch ev.Method {
		case "Network.requestWillBeSent":
			var q harReqEvent
			if json.Unmarshal(ev.Params, &q) != nil || strings.HasPrefix(q.Request.URL, "data:") {
				continue
			}
			key += q.RequestID
			if prev := live[key]; prev != nil && q.RedirectResponse != nil {
				prev.resp = q.RedirectResponse
				prev.e.Response.RedirectURL = q.Request.URL
				finish(prev, q.Timestamp)
			}
			if len(order) >= maxHAREntries {
				continue
			}
			wall := time.Unix(0, int64(q.WallTime*1e9)).UTC()
			if pageStart.IsZero() || wall.Before(pageStart) {
				pageStart = wall
			}
			p := &harPending{start: q.Timestamp, wall: wall, e: &harEntry{
				PageRef: "page_1", StartedDateTime: wall.Format(time.RFC3339Nano),
				Request: harRequest{
					Method: q.Request.Method, URL: q.Request.URL, HTTPVersion: "",
					Cookies: []harNV{}, Headers: harHeaders(q.Request.Headers), QueryString: harQuery(q.Request.URL),
					HeadersSize: -1, BodySize: len(q.Request.PostData),
				},
				Response:     harResponse{Cookies: []harNV{}, Headers: []harNV{}, HeadersSize: -1, BodySize: -1},
				ResourceType: q.Type, Initiator: q.Initiator, TransferSize: 0,
			}}
			if q.Request.PostData != "" {
				p.e.Request.PostData = &harPost{MimeType: headerValue(q.Request.Headers, "content-type"), Text: q.Request.PostData}
			}
			live[key] = p
			order = append(order, p)
		case "Network.responseReceived":
			var r struct {
				RequestID string     `json:"requestId"`
				Timestamp float64    `json:"timestamp"`
				Response  harCDPResp `json:"response"`
			}
			if json.Unmarshal(ev.Params, &r) == nil && live[key+r.RequestID] != nil {
				p := live[key+r.RequestID]
				p.resp, p.respAt = &r.Response, r.Timestamp
			}
		case "Network.loadingFinished":
			var f struct {
				RequestID     string  `json:"requestId"`
				Timestamp     float64 `json:"timestamp"`
				EncodedLength float64 `json:"encodedDataLength"`
			}
			if json.Unmarshal(ev.Params, &f) == nil && live[key+f.RequestID] != nil {
				p := live[key+f.RequestID]
				p.e.TransferSize = int64(f.EncodedLength)
				finish(p, f.Timestamp)
			}
		case "Network.loadingFailed":
			var f struct {
				RequestID string  `json:"requestId"`
				Timestamp float64 `json:"timestamp"`
				ErrorText string  `json:"errorText"`
			}
			if json.Unmarshal(ev.Params, &f) == nil && live[key+f.RequestID] != nil {
				p := live[key+f.RequestID]
				p.e.Error = clipString(f.ErrorText, 200)
				finish(p, f.Timestamp)
			}
		}
	}
	h := harLog{Log: harBody{
		Version: "1.2", Creator: harNameVer{Name: "urljail", Version: Schema},
		Comment: "Built from the guest browser's CDP events (guest-attested). Response bodies are not captured: content has sizes and types only.",
		Entries: []harEntry{},
	}}
	if !pageStart.IsZero() {
		h.Log.Pages = []harPage{{StartedDateTime: pageStart.Format(time.RFC3339Nano), ID: "page_1", Title: title,
			PageTimings: map[string]int{"onContentLoad": -1, "onLoad": -1}}}
	} else {
		h.Log.Pages = []harPage{}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].wall.Before(order[j].wall) })
	for _, p := range order {
		if !p.finished {
			fillHARResponse(p)
			p.e.Timings = harTimingsOf(p, 0)
			p.e.Comment = "no loadingFinished or loadingFailed event: still in flight when the page was collected"
		}
		h.Log.Entries = append(h.Log.Entries, *p.e)
	}
	return json.MarshalIndent(h, "", " ")
}

func fillHARResponse(p *harPending) {
	r := p.resp
	if r == nil {
		return
	}
	p.e.Response.Status = int(clampU32(r.Status))
	p.e.Response.StatusText = r.StatusText
	p.e.Response.HTTPVersion = harHTTPVersion(r.Protocol)
	p.e.Request.HTTPVersion = p.e.Response.HTTPVersion
	p.e.Response.Headers = harHeaders(r.Headers)
	p.e.Response.Content = harContent{Size: -1, MimeType: r.MimeType}
	if loc := headerValue(r.Headers, "location"); loc != "" && p.e.Response.RedirectURL == "" {
		p.e.Response.RedirectURL = loc
	}
	p.e.ServerIPAddress = strings.Trim(r.RemoteIPAddress, "[]")
	if r.FromDiskCache {
		p.e.Comment = "served from the browser's disk cache"
	}
}

// harTimingsOf splits the entry's time as Chrome's ResourceTiming allows; -1 where unknown.
func harTimingsOf(p *harPending, end float64) harTimings {
	t := harTimings{Blocked: -1, DNS: -1, Connect: -1, SSL: -1}
	if p.resp != nil && p.resp.Timing != nil && p.resp.Timing.RequestTime > 0 {
		rt := p.resp.Timing
		span := func(a, b float64) float64 {
			if a < 0 || b < 0 || b < a {
				return -1
			}
			return round3(b - a)
		}
		t.DNS, t.Connect, t.SSL = span(rt.DNSStart, rt.DNSEnd), span(rt.ConnectStart, rt.ConnectEnd), span(rt.SSLStart, rt.SSLEnd)
		t.Send = max(0, span(rt.SendStart, rt.SendEnd))
		t.Wait = max(0, span(rt.SendEnd, rt.ReceiveHeadersEnd))
		if end > 0 {
			headersAt := rt.RequestTime + rt.ReceiveHeadersEnd/1000
			t.Receive = max(0, ms(end-headersAt))
		}
		if blocked := span(0, rt.DNSStart); blocked > 0 {
			t.Blocked = blocked
		}
		return t
	}
	if p.respAt > 0 && p.respAt >= p.start {
		t.Wait = ms(p.respAt - p.start)
		if end >= p.respAt {
			t.Receive = ms(end - p.respAt)
		}
	} else if end > 0 && end >= p.start {
		t.Wait = ms(end - p.start)
	}
	return t
}

func ms(sec float64) float64 { return round3(sec * 1000) }

func round3(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*1000) / 1000
}

func harHTTPVersion(p string) string {
	switch strings.ToLower(p) {
	case "h2":
		return "HTTP/2.0"
	case "h3":
		return "HTTP/3"
	case "http/1.0":
		return "HTTP/1.0"
	case "http/1.1":
		return "HTTP/1.1"
	}
	return p
}

// harHeaders turns CDP's header object (duplicates joined with "\n") into HAR's list, sorted.
func harHeaders(h map[string]string) []harNV {
	out := []harNV{}
	for k, v := range h {
		for _, line := range strings.Split(v, "\n") {
			out = append(out, harNV{Name: k, Value: line})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func harQuery(raw string) []harNV {
	out := []harNV{}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, harNV{Name: k, Value: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// WriteHAR builds the HAR for runDir and writes runDir/har.json.
func WriteHAR(runDir string) error {
	b, err := BuildHAR(runDir)
	if err != nil {
		return fmt.Errorf("har: %w", err)
	}
	return os.WriteFile(filepath.Join(runDir, "har.json"), append(b, '\n'), 0o600)
}
