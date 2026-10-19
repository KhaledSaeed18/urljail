package report

import (
	"regexp"

	"github.com/KhaledSaeed18/urljail/internal/brands"
)

// copyrightLine is a visible copyright notice and what follows it: "© 2023 Microsoft",
// "Copyright © 2026 PayPal, Inc.".
var copyrightLine = regexp.MustCompile(`(?i)(?:©|\(c\)|copyright)\s*(?:©\s*)?(?:\d{4}\s*(?:[-–]\s*\d{4}\s*)?)?([^.|©•\n]{1,40})`)

// footerBrands returns the brands named in the first of the page's visible copyright notices
// that names any: kits copy the brand's footer with its logo, and often nothing else names the
// brand (found in P7, S20: Outlook kits titled "Sign In", the brand only in "© 2023
// Microsoft" and the logo).
func footerBrands(text string) []brands.Brand {
	for _, m := range copyrightLine.FindAllStringSubmatch(text, 8) {
		if named := brands.Named(m[1]); len(named) > 0 {
			return named
		}
	}
	return nil
}

// logoBrands returns the brands named in the first of the page's images' alt texts that names
// any, unless the page offers to sign in with another service ("Sign in with Google"), whose
// buttons carry that brand's logo on any site.
func logoBrands(alts []string, text string) []brands.Brand {
	if signInWith.MatchString(text) {
		return nil
	}
	for _, a := range alts {
		if named := brands.Named(a); len(named) > 0 {
			return named
		}
	}
	return nil
}

var signInWith = regexp.MustCompile(`(?i)\b(sign|log)\s?(in|on|up) (with|via|using)\b|\bcontinue with\b`)

// pageBrand is the brand the page names outside its title and headings, in its copyright
// notice or a logo, and where; ok is false when none is named or one of those named owns
// domain ("© Amazon Web Services" names Amazon and AWS on AWS's GovCloud sign-in).
func pageBrand(pt pageText, domain string) (b brands.Brand, where string, ok bool) {
	for _, c := range []struct {
		named []brands.Brand
		where string
	}{{footerBrands(pt.text), "its copyright notice"}, {logoBrands(pt.alts, pt.text), "an image's alt text"}} {
		if len(c.named) == 0 {
			continue
		}
		for _, n := range c.named {
			if n.Owns(domain) {
				return brands.Brand{}, "", false
			}
		}
		return c.named[0], c.where, true
	}
	return brands.Brand{}, "", false
}
