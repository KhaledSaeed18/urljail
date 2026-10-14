package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/brands"
)

func TestIndicators(t *testing.T) {
	brandRefs = func() []brands.Ref {
		return []brands.Ref{{Brand: "paypal", Phash: "ffff0000ffff0000"}}
	}
	defer func() { brandRefs = brands.Refs }()

	dom := filepath.Join(t.TempDir(), "dom.html")
	os.WriteFile(dom, []byte(`<h1>Log in to <b>PayPal</b></h1><p>paypal</p>`), 0o600)
	noDOM := filepath.Join(t.TempDir(), "none.html")

	type tc struct {
		name, final, title, phash, dom string
		passwords                      uint32
		forms                          []*reportv0.Form
		want                           string
	}
	for _, c := range []tc{
		{name: "kit: heading names PayPal, password, look-alike screenshot", final: "https://secure-paypa1.top/x",
			title: "Log in", phash: "ffff0000ffff0001", dom: dom, passwords: 1,
			want: "brand-name-off-domain:paypal brand-look-off-domain:paypal"},
		{name: "the real PayPal", final: "https://www.paypal.com/signin", title: "PayPal: Log in", phash: "ffff0000ffff0000",
			dom: dom, passwords: 1, want: ""},
		{name: "names PayPal but no password (a blog post)", final: "https://news.example/", title: "PayPal earnings", dom: noDOM, want: ""},
		{name: "device-code phishing: names DocuSign, sign-in wording, no password", final: "https://loginservice.cloud/",
			title: "DocuSign Login - Choose a login method to sign in", dom: noDOM, want: "brand-name-off-domain:docusign"},
		{name: "AWS sign-in on an AWS domain names Amazon too", final: "https://signin.amazonaws-us-gov.com/", title: "Amazon Web Services Sign-In",
			dom: noDOM, passwords: 1, want: ""},
		{name: "screenshot far from every reference", final: "https://other.example/", title: "Login", phash: "0000ffff0000ffff",
			dom: noDOM, passwords: 1, want: ""},
		{name: "password posted elsewhere", final: "https://shop.example/", dom: noDOM, passwords: 1,
			forms: []*reportv0.Form{{HasPassword: true, CrossOriginAction: true, Action: "https://collect.evil.test/p"}},
			want:  "password-form-cross-origin:"},
	} {
		r := &reportv0.Report{
			Navigation: &reportv0.Navigation{FinalUrl: c.final, Title: c.title},
			Page:       &reportv0.Page{ScreenshotPhash: c.phash, PasswordFields: c.passwords, Forms: c.forms},
		}
		var got []string
		for _, i := range indicators(r, c.dom) {
			got = append(got, i.GetId()+":"+i.GetBrand())
			if i.GetDetail() == "" || i.GetSeverity() == "" || i.GetSource() == "" {
				t.Errorf("%s: incomplete indicator %v", c.name, i)
			}
		}
		if s := strings.Join(got, " "); s != c.want {
			t.Errorf("%s: got %q, want %q", c.name, s, c.want)
		}
	}
}

func TestHeadings(t *testing.T) {
	dom := filepath.Join(t.TempDir(), "dom.html")
	os.WriteFile(dom, []byte(`<title>x</title><h1>Sign in</h1><p>not this</p><h2>to <span>Netflix</span></h2><h3>nor this</h3>`), 0o600)
	got := strings.Join(strings.Fields(headings(dom)), " ")
	if got != "Sign in to Netflix" {
		t.Errorf("headings = %q", got)
	}
}
