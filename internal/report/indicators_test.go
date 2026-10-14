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
		// A headline that leads with a brand reads as presenting it: low, the price of catching
		// lures that ask for nothing on their first page.
		{name: "names PayPal but no password (a blog post)", final: "https://news.example/", title: "PayPal earnings", dom: noDOM,
			want: "brand-presented-off-domain:paypal"},
		{name: "a page titled with its own host isn't presenting a brand", final: "https://free-5-paypal.pages.dev/", title: "free-5-paypal.pages.dev | 522: Connection timed out",
			dom: noDOM, want: ""},
		{name: "typo-squat behind a captcha", final: "https://american-expiess.vip/", title: "Verify you are human", dom: noDOM,
			want: "brand-lookalike-domain:amex"},
		{name: "device-code phishing: names DocuSign, sign-in wording, no password", final: "https://loginservice.cloud/",
			title: "DocuSign Login - Choose a login method to sign in", dom: noDOM, want: "brand-name-off-domain:docusign"},
		{name: "AWS sign-in on an AWS domain names Amazon too", final: "https://signin.amazonaws-us-gov.com/", title: "Amazon Web Services Sign-In",
			dom: noDOM, passwords: 1, want: ""},
		{name: "screenshot far from every reference", final: "https://other.example/", title: "Login", phash: "0000ffff0000ffff",
			dom: noDOM, passwords: 1, want: ""},
		{name: "blob: page with a Google sign-in title", final: "blob:https://notaria11medellin.com/3f42-89#", title: "Sign in - Google Accounts",
			dom: noDOM, want: "blob-document: brand-name-off-domain:google"},
		{name: "details harvest: DHL billing form, no password", final: "https://www.chemclean.example/x", title: "DHL", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "text"}, {Type: "text"}, {Type: "tel"}}}},
			want:  "brand-name-off-domain:dhl"},
		{name: "a blog that mentions a brand, with a contact form", final: "https://rossmanpartners.com/", title: "Rossman Partners - Blog on Amazon, Leadership", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "text"}, {Type: "email"}, {Type: "textarea"}}}}, want: ""},
		{name: "a search box isn't asking for details", final: "https://blog.example/", title: "DHL strike news", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "text", Name: "q"}}}}, want: "brand-presented-off-domain:dhl"},
		{name: "Spanish sign-in wording", final: "https://accountsecurity.dothome.co.kr/", title: "Verificacion Microsoft", dom: noDOM,
			want: "brand-name-off-domain:microsoft"},
		{name: "brandless webmail kit on free hosting", final: "https://musical-potato-x.4everland.app/", title: "musical-potato-x.4everland.app", dom: noDOM, passwords: 1,
			want: "form-on-free-hosting:"},
		{name: "a loan form on replit for a bank not on the list", final: "https://crediplus--credi0.replit.app/", title: "Crédito en Línea - Banco Pichincha", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "text"}, {Type: "tel"}, {Type: "text"}}}}, want: "form-on-free-hosting:"},
		{name: "a static page on free hosting asks for nothing", final: "https://someone.github.io/", title: "My portfolio", dom: noDOM, want: ""},
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
	os.WriteFile(dom, []byte(`<title>x</title><h1>Sign in</h1><p>not this</p><h2>to <span>Netflix</span></h2><h3>nor this</h3>`+
		`<div class="card-title">Log in to <div>Spotify</div></div><img class="title"><section class="title">`+strings.Repeat("long section text ", 10)+`</section>`), 0o600)
	heads, classHeads := headings(dom)
	got := strings.Join(heads, "|") + " / " + strings.Join(classHeads, "|")
	if got != "Sign in|to Netflix / Log in to Spotify" {
		t.Errorf("headings = %q", got)
	}
}
