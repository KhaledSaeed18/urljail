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
	// A top-level page from a blob: URL was built in script by the page itself: the URL a
	// scanner or a mail filter checked never served it (found in P7: a Google sign-in clone at
	// blob:https://notaria11medellin.com/...).
	if strings.HasPrefix(strings.ToLower(r.GetNavigation().GetFinalUrl()), "blob:") {
		out = append(out, &reportv0.Indicator{
			Id: "blob-document", Severity: "medium", Source: guestCDP,
			Detail: fmt.Sprintf("The final page is a blob: URL of %s: built in script, not served from a URL", domain),
		})
	}
	if domain == "" {
		return out
	}

	// A brand named in the title or headings, on a domain that belongs to none of the brands
	// named ("Amazon Web Services" names Amazon and AWS; the AWS sign-in on an AWS domain is
	// neither's impersonation). High with a password field; medium with only sign-in wording,
	// which catches device-code phishing ("use the code below to sign in": no password asked,
	// found in P7 on a DocuSign look-alike).
	heads, classHeads := headings(domPath)
	title := titleWithoutHost(r.GetNavigation().GetTitle(), r.GetNavigation().GetFinalUrl())
	text := title + " \n " + strings.Join(heads, " \n ") + " \n " + strings.Join(classHeads, " \n ")
	if named := brands.Named(text); len(named) > 0 {
		owned := false
		for _, b := range named {
			owned = owned || b.Owns(domain)
		}
		b := named[0]
		switch {
		case owned:
		case page.GetPasswordFields() > 0:
			out = append(out, &reportv0.Indicator{
				Id: "brand-name-off-domain", Severity: "high", Brand: b.ID, Source: guestDOM,
				Detail: fmt.Sprintf("The page names %s in its title or headings and asks for a password, on %s", b.Name, domain),
			})
		case asksForDetails(page.GetForms()) && len(brands.PresentedAs(title, heads)) > 0:
			out = append(out, &reportv0.Indicator{
				Id: "brand-name-off-domain", Severity: "medium", Brand: b.ID, Source: guestDOM,
				Detail: fmt.Sprintf("The page names %s in its title or headings and has a form asking for details, on %s (no password field)", b.Name, domain),
			})
		case brands.SignInWording(text):
			out = append(out, &reportv0.Indicator{
				Id: "brand-name-off-domain", Severity: "medium", Brand: b.ID, Source: guestDOM,
				Detail: fmt.Sprintf("The page names %s in its title or headings with sign-in wording, on %s (no password field)", b.Name, domain),
			})
		}
	}

	// A password field or a details form on free hosting (found in P7: brandless webmail kits,
	// loan forms for a bank not on the brand list, all on replit.app, vercel.app, 4everland.app,
	// duckdns.org and the like).
	if u, err := brands.ParseOrigin(r.GetNavigation().GetFinalUrl()); err == nil {
		if svc := freeHost(u.Hostname()); svc != "" {
			switch {
			case page.GetPasswordFields() > 0:
				out = append(out, &reportv0.Indicator{
					Id: "form-on-free-hosting", Severity: "medium", Source: guestDOM,
					Detail: fmt.Sprintf("A password field on %s, a free hosting service anyone can publish to (%s)", u.Hostname(), svc),
				})
			case asksForDetails(page.GetForms()):
				out = append(out, &reportv0.Indicator{
					Id: "form-on-free-hosting", Severity: "medium", Source: guestDOM,
					Detail: fmt.Sprintf("A form asking for details on %s, a free hosting service anyone can publish to (%s)", u.Hostname(), svc),
				})
			}
		}
	}

	// The domain imitates a brand's own: what a "verify you are human" gate in front of a kit
	// still gives away (found in P7: american-expiess.vip, ameriean-expiess.vip).
	if b, d, ok := brands.LookalikeDomain(domain); ok {
		out = append(out, &reportv0.Indicator{
			Id: "brand-lookalike-domain", Severity: "medium", Brand: b.ID, Source: "host.url",
			Detail: fmt.Sprintf("%s is %d letter(s) from a domain of %s", domain, d, b.Name),
		})
	}

	// Presenting itself as a brand off its domains, without asking for anything yet: the first
	// page of a lure ("delivery failed", a loan offer, a wallet setup) whose form comes next.
	// Info, not a flag: on held-out live feed pages it fired on 3 phishing pages and on 6 that
	// weren't (tutorial clones, empty blogs, an official preview deployment; journal P7).
	if presented := brands.PresentedAs(title, heads); len(presented) > 0 && !hasBrandIndicator(out) {
		owned := false
		for _, b := range presented {
			owned = owned || b.Owns(domain)
		}
		if !owned {
			b := presented[0]
			out = append(out, &reportv0.Indicator{
				Id: "brand-presented-off-domain", Severity: "info", Brand: b.ID, Source: guestDOM,
				Detail: fmt.Sprintf("The page presents itself as %s (title or a short heading), on %s", b.Name, domain),
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

// titleWithoutHost drops the final URL's host from the title: a page without a <title> is
// titled with its URL, and a Cloudflare error page with its host, so "free-5-paypal.pages.dev
// | 522" names the host, not a brand the page presents.
func titleWithoutHost(title, finalURL string) string {
	u, err := brands.ParseOrigin(finalURL)
	if err != nil || u.Hostname() == "" {
		return title
	}
	return strings.ReplaceAll(strings.ToLower(title), strings.ToLower(u.Hostname()), " ")
}

func hasBrandIndicator(in []*reportv0.Indicator) bool {
	for _, i := range in {
		if i.GetId() == "brand-name-off-domain" {
			return true
		}
	}
	return false
}

// asksForDetails: a form with at least two fields a person types into (text, email, tel,
// number, date): billing details, an email-first sign-in. One field is a search box or a
// newsletter sign-up. Found in P7: a DHL "billing information" page and a Coinbase "receive
// payment" page asked for names, addresses and account numbers, never a password.
func asksForDetails(forms []*reportv0.Form) bool {
	for _, f := range forms {
		n := 0
		for _, x := range f.GetFields() {
			switch x.GetType() {
			case "text", "email", "tel", "number", "date", "textarea":
				n++
			}
		}
		if n >= 2 {
			return true
		}
	}
	return false
}

// maxHeadingText caps the heading text read from the DOM.
const maxHeadingText = 4 << 10

// headings returns the text of the top document's h1 and h2 elements, and separately of short
// elements whose class names them a title or heading (kits build headings from divs: "<div
// class=title>Log in to Spotify", found in P7), up to maxHeadingText in all. Class-named ones
// are noisier (Wikipedia's "Meta" project link, a "Google Chrome" requirement on chase.com):
// they count only next to a password field, a details form or sign-in wording.
func headings(domPath string) (heads, classHeads []string) {
	f, err := os.Open(domPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	var b strings.Builder
	total := 0
	headTag, nest, byClass := "", 0, false // the element being read, and how deep in same-named elements
	z := html.NewTokenizer(io.LimitReader(f, maxDOMScanned))
	for total < maxHeadingText {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return heads, classHeads
		case html.StartTagToken:
			n, hasAttr := z.TagName()
			name := string(n)
			if headTag != "" {
				if name == headTag {
					nest++
				}
				continue
			}
			isHead := name == "h1" || name == "h2"
			for hasAttr && !isHead {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				if string(k) == "class" {
					c := strings.ToLower(string(v))
					isHead = strings.Contains(c, "title") || strings.Contains(c, "heading")
				}
			}
			if isHead && !voidElement[name] {
				headTag, nest, byClass = name, 1, name != "h1" && name != "h2"
			}
		case html.EndTagToken:
			if n, _ := z.TagName(); headTag != "" && string(n) == headTag {
				if nest--; nest == 0 {
					// Only short ones: a "title" class on a whole section isn't a heading.
					if h := strings.Join(strings.Fields(b.String()), " "); h != "" && (!byClass || len(strings.Fields(h)) <= 12) {
						if byClass {
							classHeads = append(classHeads, h)
						} else {
							heads = append(heads, h)
						}
						total += len(h)
					}
					b.Reset()
					headTag = ""
				}
			}
		case html.TextToken:
			if headTag != "" && b.Len() < maxHeadingText {
				b.Write(z.Text())
				b.WriteByte(' ')
			}
		}
	}
	return heads, classHeads
}

var voidElement = map[string]bool{"img": true, "input": true, "br": true, "hr": true, "meta": true, "link": true, "source": true, "area": true, "col": true, "embed": true, "wbr": true}
