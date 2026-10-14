// Package brands knows the brands phishing kits impersonate most: their names, the domains
// that really are theirs, and what their sign-in pages look like. Reports use it to say "this
// page presents itself as <brand> but isn't on <brand>'s domains".
package brands

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"

	"github.com/KhaledSaeed18/urljail/internal/visual"
)

// Brand is one impersonated brand.
type Brand struct {
	ID   string
	Name string
	// Words name the brand in a title or heading: lowercase, matched as whole words. Names
	// that are ordinary words ("wise", "steam", "kraken", "orange") are left out: they'd match
	// unrelated pages.
	Words []string
	// Domains are registrable domains that are the brand (a page there is the brand itself).
	Domains []string
	// Login is the brand's real sign-in page, detonated for the reference screenshots.
	Login string
}

// All is the brand list. Kept to brands with a recognisable sign-in page.
var All = []Brand{
	{"paypal", "PayPal", []string{"paypal"}, []string{"paypal.com", "paypal.me", "paypalobjects.com"}, "https://www.paypal.com/signin"},
	{"microsoft", "Microsoft", []string{"microsoft", "office 365", "microsoft 365", "outlook", "onedrive", "sharepoint"},
		[]string{"microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "office365.com", "sharepoint.com", "onedrive.com", "microsoft365.com", "msauth.net", "msftauth.net"},
		"https://login.microsoftonline.com/"},
	{"apple", "Apple", []string{"apple id", "apple account", "icloud"}, []string{"apple.com", "icloud.com"}, "https://account.apple.com/sign-in"},
	{"google", "Google", []string{"google", "gmail"}, []string{"google.com", "gmail.com", "youtube.com", "googleusercontent.com"}, "https://accounts.google.com/"},
	{"amazon", "Amazon", []string{"amazon"}, []string{"amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.fr", "amazon.ca", "amazon.in", "amazon.es", "amazon.it", "amazon.com.au", "amazon.dev"},
		"https://www.amazon.com/gp/sign-in.html"},
	{"aws", "Amazon Web Services", []string{"amazon web services", "aws"}, []string{"amazon.com", "amazonaws.com", "amazonaws-us-gov.com", "amazonaws.cn", "aws.dev"}, "https://signin.aws.amazon.com/"},
	{"netflix", "Netflix", []string{"netflix"}, []string{"netflix.com"}, "https://www.netflix.com/login"},
	{"facebook", "Facebook", []string{"facebook"}, []string{"facebook.com", "fb.com", "meta.com"}, "https://www.facebook.com/login"},
	{"instagram", "Instagram", []string{"instagram"}, []string{"instagram.com"}, "https://www.instagram.com/accounts/login/"},
	{"dropbox", "Dropbox", []string{"dropbox"}, []string{"dropbox.com"}, "https://www.dropbox.com/login"},
	{"docusign", "DocuSign", []string{"docusign"}, []string{"docusign.com", "docusign.net"}, "https://account.docusign.com/"},
	{"adobe", "Adobe", []string{"adobe"}, []string{"adobe.com"}, "https://account.adobe.com/"},
	{"linkedin", "LinkedIn", []string{"linkedin"}, []string{"linkedin.com"}, "https://www.linkedin.com/login"},
	{"coinbase", "Coinbase", []string{"coinbase"}, []string{"coinbase.com"}, "https://login.coinbase.com/signin"},
	{"binance", "Binance", []string{"binance"}, []string{"binance.com"}, "https://accounts.binance.com/en/login"},
	{"chase", "Chase", []string{"chase bank", "chase online"}, []string{"chase.com"}, "https://secure.chase.com/web/auth/"},
	{"wellsfargo", "Wells Fargo", []string{"wells fargo"}, []string{"wellsfargo.com"}, "https://connect.secure.wellsfargo.com/auth/login/present"},
	{"bankofamerica", "Bank of America", []string{"bank of america"}, []string{"bankofamerica.com"}, "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go"},
	{"bbva", "BBVA", []string{"bbva"}, []string{"bbva.com", "bbva.es", "bbva.mx", "bbva.com.ar", "bbva.pe", "bbva.com.co"}, ""},
	{"revolut", "Revolut", []string{"revolut"}, []string{"revolut.com"}, "https://app.revolut.com/start"},
	{"usps", "USPS", []string{"usps"}, []string{"usps.com"}, "https://reg.usps.com/entreg/LoginAction_input"},
	{"fedex", "FedEx", []string{"fedex"}, []string{"fedex.com"}, "https://www.fedex.com/secure-login/"},
	{"dhl", "DHL", []string{"dhl"}, []string{"dhl.com", "dhl.de"}, ""},
	{"ebay", "eBay", []string{"ebay"}, []string{"ebay.com", "ebay.co.uk", "ebay.de"}, "https://signin.ebay.com/"},
	{"roblox", "Roblox", []string{"roblox"}, []string{"roblox.com"}, "https://www.roblox.com/login"},
	{"spotify", "Spotify", []string{"spotify"}, []string{"spotify.com"}, "https://accounts.spotify.com/login"},
	{"discord", "Discord", []string{"discord"}, []string{"discord.com", "discord.gg"}, "https://discord.com/login"},
	{"stripe", "Stripe", []string{"stripe"}, []string{"stripe.com"}, "https://dashboard.stripe.com/login"},
	{"amex", "American Express", []string{"american express", "amex"}, []string{"americanexpress.com"}, "https://www.americanexpress.com/en-us/account/login"},
	{"capitalone", "Capital One", []string{"capital one"}, []string{"capitalone.com"}, "https://verified.capitalone.com/auth/signin"},
	{"steam", "Steam", []string{"steam community", "steampowered"}, []string{"steampowered.com", "steamcommunity.com"}, "https://store.steampowered.com/login/"},
}

// ByID returns the brand with this ID.
func ByID(id string) (Brand, bool) {
	for _, b := range All {
		if b.ID == id {
			return b, true
		}
	}
	return Brand{}, false
}

// Owns reports whether a registrable domain belongs to the brand.
func (b Brand) Owns(registrable string) bool {
	for _, d := range b.Domains {
		if strings.EqualFold(d, registrable) {
			return true
		}
	}
	return false
}

// Named returns the brands named in text (whole words, case-insensitive), in list order.
func Named(text string) []Brand {
	norm := " " + normalize(text) + " "
	var out []Brand
	for _, b := range All {
		for _, w := range b.Words {
			if strings.Contains(norm, " "+w+" ") {
				out = append(out, b)
				break
			}
		}
	}
	return out
}

// signIn are phrases of a sign-in page, matched as whole words.
var signIn = []string{"log in", "login", "sign in", "signin", "sign on", "logon", "log on", "verify", "verification", "sign in code", "authenticate"}

// SignInWording reports whether text uses sign-in phrases.
func SignInWording(text string) bool {
	norm := " " + normalize(text) + " "
	for _, w := range signIn {
		if strings.Contains(norm, " "+w+" ") {
			return true
		}
	}
	return false
}

// normalize lowercases and turns every run of non-letters/digits into one space, so "PayPal:
// Log in" and "paypal-login" both contain " paypal ".
func normalize(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

// Ref is a reference screenshot hash of a brand's real sign-in page.
type Ref struct {
	Brand   string `json:"brand"`
	URL     string `json:"url"`     // the page detonated
	Final   string `json:"final"`   // where it ended up
	Profile string `json:"profile"` // browser profile used
	Phash   string `json:"phash"`   // visual.Hash
	Taken   string `json:"taken"`   // date, YYYY-MM-DD
	Run     string `json:"run"`     // run ID, for the screenshot
}

//go:embed refs.json
var refsJSON []byte

// Refs returns the reference hashes (refs.json, made by `urljail brands refs`).
func Refs() []Ref {
	var r []Ref
	_ = json.Unmarshal(refsJSON, &r)
	return r
}

// LooksLike returns the brand whose reference screenshot is closest to h, if any is within
// maxDist, and the distance.
func LooksLike(h visual.Hash, maxDist int) (Brand, int, bool) {
	return LooksLikeIn(Refs(), h, maxDist)
}

// LooksLikeIn is LooksLike against a given set of references.
func LooksLikeIn(refs []Ref, h visual.Hash, maxDist int) (Brand, int, bool) {
	best, bestD := "", maxDist+1
	for _, r := range refs {
		rh, err := visual.Parse(r.Phash)
		if err != nil {
			continue
		}
		if d := visual.Distance(h, rh); d < bestD {
			best, bestD = r.Brand, d
		}
	}
	b, ok := ByID(best)
	return b, bestD, ok
}

// ParseOrigin parses a URL; for a blob: URL ("blob:https://host/uuid") it parses the URL
// inside, whose origin the blob belongs to.
func ParseOrigin(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err == nil && strings.EqualFold(u.Scheme, "blob") && u.Opaque != "" {
		return url.Parse(u.Opaque)
	}
	return u, err
}

// DomainOf is the registrable domain of a URL, or of the origin of a blob: URL ("" when it
// has no host).
func DomainOf(rawURL string) string {
	u, err := ParseOrigin(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return reg
	}
	return host
}
