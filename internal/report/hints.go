package report

import (
	"io"
	"net/url"
	"os"
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
