package report

import (
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// hintHosts returns the hosts a page told the browser to connect to or resolve ahead of time:
// <link rel=preconnect|dns-prefetch|prefetch|preload|prerender href=...>. Chrome acts on these
// without a request the Network domain reports, so the host sees connections and lookups the
// guest's request list doesn't explain (found in live mode on www.wikipedia.org). The DOM is
// guest-attested, like the CDP requests these complement.
func hintHosts(domPath string, page *url.URL) map[string]bool {
	hosts := map[string]bool{}
	f, err := os.Open(domPath)
	if err != nil {
		return hosts
	}
	defer f.Close()
	z := html.NewTokenizer(io.LimitReader(f, 32<<20))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return hosts
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "link" || !hasAttr {
				continue
			}
			var rel, href string
			for {
				k, v, more := z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "rel":
					rel = strings.ToLower(string(v))
				case "href":
					href = string(v)
				}
				if !more {
					break
				}
			}
			if !isHint(rel) || href == "" {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(href))
			if err != nil {
				continue
			}
			if page != nil {
				u = page.ResolveReference(u) // "//upload.wikimedia.org" is scheme-relative
			}
			if h := strings.ToLower(u.Hostname()); h != "" {
				hosts[h] = true
			}
		}
	}
}

func isHint(rel string) bool {
	for _, r := range strings.Fields(rel) {
		switch r {
		case "preconnect", "dns-prefetch", "prefetch", "preload", "prerender", "modulepreload":
			return true
		}
	}
	return false
}

// maxHeaderHints caps the hint hosts one run's response headers can name (server-controlled).
const maxHeaderHints = 64

var linkValue = regexp.MustCompile(`<([^>]*)>([^,<]*)`)

// linkHeaderHosts returns the hosts a response's Link header tells the browser to connect to
// ahead of time, the header form of <link rel=preconnect>. Google Fonts stylesheets send
// "<https://fonts.gstatic.com>; rel=preconnect" (found in P7: Chrome connected to
// fonts.gstatic.com and the page never requested it).
func linkHeaderHosts(headers map[string]any, base string) []string {
	var hosts []string
	b, _ := url.Parse(base)
	for name, v := range headers {
		val, ok := v.(string)
		if !ok || len(val) > 16<<10 || !strings.EqualFold(name, "link") {
			continue
		}
		for _, m := range linkValue.FindAllStringSubmatch(val, maxHeaderHints) {
			rel := ""
			for _, param := range strings.Split(m[2], ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "rel") {
					rel = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
				}
			}
			if !isHint(rel) {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(m[1]))
			if err != nil {
				continue
			}
			if b != nil {
				u = b.ResolveReference(u)
			}
			if h := strings.ToLower(u.Hostname()); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}
