package report

import (
	"io"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

// guestDOM marks what was read from the final DOM the guest serialized (guest/dom.html).
const guestDOM = "guest.dom"

const (
	maxForms      = 32
	maxFields     = 64
	maxFieldName  = 100
	maxActionLen  = 2048
	maxDOMScanned = 32 << 20
)

// forms reads the forms and password inputs of the top document. The DOM is page-controlled:
// everything is capped, and nothing in it is followed or run.
func forms(domPath string, final *url.URL) (out []*reportv0.Form, passwords uint32) {
	f, err := os.Open(domPath)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	base := final
	var cur *reportv0.Form
	z := html.NewTokenizer(io.LimitReader(f, maxDOMScanned))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out, passwords
		}
		if tt == html.EndTagToken {
			if name, _ := z.TagName(); string(name) == "form" {
				cur = nil
			}
			continue
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		attrs := map[string]string{}
		for hasAttr {
			var k, v []byte
			k, v, hasAttr = z.TagAttr()
			key := strings.ToLower(string(k))
			if _, seen := attrs[key]; !seen { // the first of a repeated attribute wins, as in browsers
				attrs[key] = string(v)
			}
		}
		switch string(name) {
		case "base":
			if href, ok := attrs["href"]; ok && base == final && final != nil {
				if u, err := final.Parse(strings.TrimSpace(href)); err == nil {
					base = u
				}
			}
		case "form":
			if cur != nil || len(out) >= maxForms {
				continue // forms don't nest; a nested <form> is ignored by browsers too
			}
			cur = &reportv0.Form{Method: "get", Source: guestDOM}
			if m := strings.ToLower(strings.TrimSpace(attrs["method"])); m == "post" || m == "dialog" {
				cur.Method = m
			}
			cur.Action = resolveAction(base, attrs["action"])
			cur.CrossOriginAction = crossSite(final, cur.Action)
			out = append(out, cur)
		case "input", "select", "textarea":
			typ := string(name)
			if typ == "input" {
				typ = strings.ToLower(strings.TrimSpace(attrs["type"]))
				if typ == "" {
					typ = "text"
				}
			}
			if typ == "password" {
				passwords++
			}
			if cur == nil || len(cur.Fields) >= maxFields {
				continue
			}
			cur.Fields = append(cur.Fields, &reportv0.Field{Name: clipString(attrs["name"], maxFieldName), Type: clipString(typ, 32)})
			if typ == "password" {
				cur.HasPassword = true
			}
		}
	}
}

func resolveAction(base *url.URL, action string) string {
	action = strings.TrimSpace(action)
	if base == nil {
		return clipString(action, maxActionLen)
	}
	if action == "" {
		return clipString(base.String(), maxActionLen)
	}
	u, err := base.Parse(action)
	if err != nil {
		return clipString(action, maxActionLen)
	}
	return clipString(u.String(), maxActionLen)
}

// crossSite: the action goes to another registrable domain than the page (javascript: and
// other non-network schemes don't count).
func crossSite(page *url.URL, action string) bool {
	if page == nil {
		return false
	}
	u, err := url.Parse(action)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	return registrable(u.Hostname()) != registrable(page.Hostname())
}

func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if r, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return r
	}
	return host
}

func clipString(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
