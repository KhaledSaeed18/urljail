package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/net/html"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/visual"
)

const guestScreenshot = "guest.screenshot"

// brandRefs are the brand reference screenshots (replaced in tests).
var brandRefs = brands.Refs

// indicators derives the phishing signals from what the report already holds. Each is a fact
// with its reason; the brand ones only fire off the brand's own domains.
func indicators(r *reportv0.Report, domPath string) []*reportv0.Indicator {
	var out []*reportv0.Indicator
	page := r.GetPage()
	domain := brands.DomainOf(r.GetNavigation().GetFinalUrl())

	for _, f := range page.GetForms() {
		if f.GetHasPassword() && f.GetCrossOriginAction() {
			out = append(out, &reportv0.Indicator{
				Id: "password-form-cross-origin", Severity: "medium", Source: guestDOM,
				Detail: fmt.Sprintf("A form with a password field sends to %s, not to the page's domain %s", brands.DomainOf(f.GetAction()), domain),
			})
			break
		}
	}
	if domain == "" {
		return out
	}

	// A brand named in the title or headings, a password asked for, and the domain belongs to
	// none of the brands named ("Amazon Web Services" names Amazon and AWS; the AWS sign-in
	// on an AWS domain is neither's impersonation).
	if page.GetPasswordFields() > 0 {
		named := brands.Named(r.GetNavigation().GetTitle() + " \n " + headings(domPath))
		owned := false
		for _, b := range named {
			owned = owned || b.Owns(domain)
		}
		if len(named) > 0 && !owned {
			b := named[0]
			out = append(out, &reportv0.Indicator{
				Id: "brand-name-off-domain", Severity: "high", Brand: b.ID, Source: guestDOM,
				Detail: fmt.Sprintf("The page names %s in its title or headings and asks for a password, on %s", b.Name, domain),
			})
		}
	}

	if h, err := visual.Parse(page.GetScreenshotPhash()); err == nil {
		if b, d, ok := brands.LooksLikeIn(brandRefs(), h, visual.DefaultMaxDistance); ok && !b.Owns(domain) {
			out = append(out, &reportv0.Indicator{
				Id: "brand-look-off-domain", Severity: "high", Brand: b.ID, Source: guestScreenshot,
				Detail: fmt.Sprintf("The screenshot looks like %s's sign-in page (%d of 64 bits apart), on %s", b.Name, d, domain),
			})
		}
	}
	return out
}

// maxHeadingText caps the heading text read from the DOM.
const maxHeadingText = 4 << 10

// headings returns the text of the top document's h1 and h2 elements, up to maxHeadingText.
func headings(domPath string) string {
	f, err := os.Open(domPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	var b strings.Builder
	depth := 0
	z := html.NewTokenizer(io.LimitReader(f, maxDOMScanned))
	for b.Len() < maxHeadingText {
		switch z.Next() {
		case html.ErrorToken:
			return b.String()
		case html.StartTagToken:
			if n, _ := z.TagName(); string(n) == "h1" || string(n) == "h2" {
				depth++
			}
		case html.EndTagToken:
			if n, _ := z.TagName(); (string(n) == "h1" || string(n) == "h2") && depth > 0 {
				depth--
				b.WriteString(" \n ")
			}
		case html.TextToken:
			if depth > 0 {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
	return clipString(b.String(), maxHeadingText)
}
