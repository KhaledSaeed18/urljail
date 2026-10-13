// Package outcome labels what a detonation showed and compares the same URL across browser
// profiles (P6: is the page cloaking, and on which signal?). It reads run directories only:
// reports, the captured DOM and the screenshot, all guest-attested except the report's host
// sections, and all treated as untrusted bytes.
package outcome

import (
	"image"
	"image/png"
	"io"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
	"google.golang.org/protobuf/encoding/protojson"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

// Labels, roughly from "nothing there" to "a page".
const (
	Failed       = "failed"        // no usable report
	Dead         = "dead"          // the name doesn't resolve
	NoResponse   = "no-response"   // connection refused, reset, or no answer
	OriginDown   = "origin-down"   // CDN up, site behind it not (Cloudflare 52x)
	Blocked      = "blocked"       // a provider's phishing interstitial
	Gate         = "gate"          // CAPTCHA / "verify you are human" / browser check
	Login        = "login"         // a password field
	ErrorPage    = "error-page"    // HTTP 4xx/5xx document
	RedirectAway = "redirect-away" // ended on another registrable domain
	Content      = "content"       // anything else
)

// Outcome is one run's result, reduced for comparison.
type Outcome struct {
	Profile     string `json:"profile"`
	RunID       string `json:"run_id"`
	Label       string `json:"label"`
	FinalDomain string `json:"final_domain,omitempty"`
	Title       string `json:"title,omitempty"`
	Password    bool   `json:"password,omitempty"`
	DOMBytes    int    `json:"dom_bytes,omitempty"`
	Screen      uint64 `json:"screen_hash,omitempty"` // 8x8 average hash; 0: no screenshot
}

var (
	passwordInput = regexp.MustCompile(`(?i)<input[^>]+type=["']?password`)
	gateMarkers   = regexp.MustCompile(`(?i)verify you are human|just a moment\.\.\.|challenges\.cloudflare\.com|cf-turnstile|hcaptcha\.com|www\.google\.com/recaptcha|g-recaptcha|are you a robot|checking your browser|ddos-guard`)
	blockedTitle  = regexp.MustCompile(`(?i)^suspected phishing|deceptive site ahead|this site has been (blocked|suspended)|phishing warning`)
	originDown    = regexp.MustCompile(`\| 52[0-9]: `)
)

const maxDOM = 32 << 20

// Classify labels the run in runDir. submitted is the URL that was opened.
func Classify(runDir, submitted string) Outcome {
	o := Outcome{RunID: filepath.Base(runDir), Label: Failed}
	b, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return o
	}
	var r reportv0.Report
	if (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, &r) != nil {
		return o
	}
	o.Profile = r.GetRun().GetProfile()
	n := r.GetNavigation()
	o.Title = n.GetTitle()
	o.FinalDomain = domainOf(n.GetFinalUrl())
	var dom []byte
	if f, err := os.Open(filepath.Join(runDir, "guest", "dom.html")); err == nil {
		dom, _ = io.ReadAll(io.LimitReader(f, maxDOM))
		f.Close()
	}
	o.DOMBytes = len(dom)
	o.Password = passwordInput.Match(dom)
	o.Screen = screenHash(filepath.Join(runDir, "guest", "screenshot.png"))

	e := n.GetError()
	lastStatus := int32(0)
	if hops := n.GetRedirectChain(); len(hops) > 0 {
		lastStatus = hops[len(hops)-1].GetStatus()
	}
	switch {
	case strings.Contains(e, "ERR_NAME_NOT_RESOLVED"):
		o.Label = Dead
	case strings.Contains(e, "timed out"), strings.Contains(e, "ERR_CONNECTION"), strings.Contains(e, "ERR_TIMED_OUT"),
		strings.Contains(e, "ERR_EMPTY_RESPONSE"), strings.Contains(e, "ERR_SSL"), strings.Contains(e, "ERR_ADDRESS_UNREACHABLE"):
		o.Label = NoResponse
	case originDown.MatchString(o.Title):
		o.Label = OriginDown
	case blockedTitle.MatchString(o.Title):
		o.Label = Blocked
	case gateMarkers.MatchString(o.Title) || !o.Password && gateMarkers.Match(dom):
		o.Label = Gate
	case o.Password:
		o.Label = Login
	case lastStatus >= 400:
		o.Label = ErrorPage
	case e != "":
		o.Label = NoResponse
	case o.FinalDomain != "" && o.FinalDomain != domainOf(submitted):
		o.Label = RedirectAway
	default:
		o.Label = Content
	}
	return o
}

func domainOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(u.Hostname())); err == nil {
		return d
	}
	return strings.ToLower(u.Hostname())
}

// screenHash is an 8x8 average hash of a PNG screenshot (0 when missing or unusable).
func screenHash(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	cfg, err := png.DecodeConfig(f)
	if err != nil || cfg.Width < 8 || cfg.Height < 8 || cfg.Width > 4096 || cfg.Height > 4096 {
		return 0
	}
	if _, err := f.Seek(0, 0); err != nil {
		return 0
	}
	img, err := png.Decode(f)
	if err != nil {
		return 0
	}
	return averageHash(img)
}

func averageHash(img image.Image) uint64 {
	b := img.Bounds()
	var cells [64]float64
	for y := b.Min.Y; y < b.Max.Y; y += 2 { // every other pixel is plenty for an 8x8 grid
		cy := (y - b.Min.Y) * 8 / b.Dy()
		for x := b.Min.X; x < b.Max.X; x += 2 {
			r, g, bl, _ := img.At(x, y).RGBA()
			cx := (x - b.Min.X) * 8 / b.Dx()
			cells[cy*8+cx] += 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)
		}
	}
	var mean float64
	for _, c := range cells {
		mean += c / 64
	}
	var h uint64
	for i, c := range cells {
		if c > mean {
			h |= 1 << i
		}
	}
	return h | 1<<63 // never 0, so 0 can mean "no screenshot"
}

// ScreenDistance is the number of differing hash bits (0..63), or -1 if either is missing.
func ScreenDistance(a, b uint64) int {
	if a == 0 || b == 0 {
		return -1
	}
	return bits.OnesCount64((a ^ b) &^ (1 << 63))
}
