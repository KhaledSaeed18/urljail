package report

import (
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

// Gates are the pages kits put in front of themselves: a "verify you are human" check, or a
// block page for visitors from VPNs and data centres (which a detonation is). They ask for
// nothing, so the form and password rules never see them (journal P7, S9: 28 of the labelled
// phishing pages, none flagged).

// maxGateWords is the most visible words a gate has: the check and little else. Gates in P7
// had 3 to 43; a real sign-in page that mentions its CAPTCHA has more (Netflix's: 69).
const maxGateWords = 60

// humanCheck is "prove you're human" wording. "captcha" counts as a word only, so "protected by
// reCAPTCHA" on a sign-in page doesn't; Cyrillic has no \b in Go's regexp, so it's matched as text.
var humanCheck = regexp.MustCompile(`(?i)verify(ing)? (that )?you are (a )?human|are you (a )?human|i'?m not a robot|i am not a robot|\bnot a robot\b|human verification|\bsecurity check\b|\bcaptcha\b|confirming it'?s you|complete the check|checking your browser|` +
	`v[ée]rification de s[ée]curit[ée]|v[ée]rification de votre navigateur|v[ée]rification anti-?bot|je ne suis pas un robot|no soy un robot|verificaci[óo]n de seguridad|n[ãa]o sou um rob[ôo]|verifica[çc][ãa]o de seguran[çc]a|ich bin kein roboter|sicherheits[üu]berpr[üu]fung|non sono un robot|verifica di sicurezza|` +
	`капч|не робот`)

// blocksProxies is a page turning visitors away for their VPN or proxy.
var (
	proxyWords = regexp.MustCompile(`(?i)\b(vpns?|prox(y|ies))\b`)
	blockWords = regexp.MustCompile(`(?i)\b(restricted|blocked|blocks|denied|forbidden|not allowed)\b`)
)

// challengeHosts serve real human checks: a page that shows one loads one of these.
var challengeHosts = []string{"challenges.cloudflare.com", "hcaptcha.com", "recaptcha.net", "arkoselabs.com", "funcaptcha.com",
	"geetest.com", "friendlycaptcha.com", "friendlycaptcha.eu", "mtcaptcha.com"}

const maxPageText = 16 << 10

// pageText is the top document's visible text (no script, style or template content), capped,
// with the script and frame sources.
type pageText struct {
	text  string
	words int
	srcs  []string
	alts  []string // images' alt text, which names a logo's brand when the page's text doesn't
}

func readPageText(domPath string) (pageText, bool) {
	f, err := os.Open(domPath)
	if err != nil {
		return pageText{}, false
	}
	defer f.Close()
	var p pageText
	var b strings.Builder
	hidden := 0
	z := html.NewTokenizer(io.LimitReader(f, maxDOMScanned))
	for {
		switch z.Next() {
		case html.ErrorToken:
			p.text = b.String()
			return p, true
		case html.StartTagToken, html.SelfClosingTagToken:
			n, hasAttr := z.TagName()
			name := string(n)
			if name == "img" {
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "alt" && len(v) > 0 && len(v) <= 80 && len(p.alts) < 32 {
						p.alts = append(p.alts, string(v))
					}
				}
			}
			if name == "script" || name == "iframe" {
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "src" && len(p.srcs) < 64 {
						p.srcs = append(p.srcs, string(v))
					}
				}
			}
			switch name {
			case "script", "style", "noscript", "template", "textarea":
				hidden++
			}
		case html.EndTagToken:
			switch n, _ := z.TagName(); string(n) {
			case "script", "style", "noscript", "template", "textarea":
				if hidden > 0 {
					hidden--
				}
			}
		case html.TextToken:
			if hidden == 0 && b.Len() < maxPageText {
				if w := strings.Fields(string(z.Text())); len(w) > 0 {
					p.words += len(w)
					b.WriteString(strings.Join(w, " "))
					b.WriteByte(' ')
				}
			}
		}
	}
}

// challengeLoaded returns the human-check service the page contacted or embeds, or "".
func challengeLoaded(r *reportv0.Report, srcs []string) string {
	hosts := []string{}
	for _, fl := range r.GetNetwork().GetFlows() {
		hosts = append(hosts, fl.GetSni(), fl.GetHttpHost())
	}
	for _, s := range srcs {
		if u, err := url.Parse(strings.TrimSpace(s)); err == nil {
			if strings.Contains(u.Path, "/recaptcha/") {
				return u.Hostname() + "/recaptcha"
			}
			hosts = append(hosts, u.Hostname())
		}
	}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		for _, c := range challengeHosts {
			if h != "" && (h == c || strings.HasSuffix(h, "."+c)) {
				return c
			}
		}
	}
	return ""
}

// isGate: a short page whose text asks the visitor to prove they're human.
func isGate(p pageText, title string) (phrase string, ok bool) {
	if p.words > maxGateWords {
		return "", false
	}
	m := humanCheck.FindString(title + " \n " + p.text)
	return strings.ToLower(m), m != ""
}

// blocksProxies: a short page turning the visitor away for a VPN or proxy.
func blocksProxies(p pageText) bool {
	return p.words <= maxGateWords && proxyWords.MatchString(p.text) && blockWords.MatchString(p.text)
}
