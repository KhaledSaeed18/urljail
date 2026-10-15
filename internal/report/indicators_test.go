package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/brands"
	"github.com/KhaledSaeed18/urljail/internal/kits"
)

func TestIndicators(t *testing.T) {
	brandRefs = func() []brands.Ref {
		return []brands.Ref{{Brand: "paypal", Phash: "ffff0000ffff0000", Favicons: []string{"aa11"}}}
	}
	defer func() { brandRefs = brands.Refs }()

	dom := filepath.Join(t.TempDir(), "dom.html")
	os.WriteFile(dom, []byte(`<h1>Log in to <b>PayPal</b></h1><p>paypal</p>`), 0o600)
	noDOM := filepath.Join(t.TempDir(), "none.html")

	type tc struct {
		name, final, title, phash, dom string
		passwords                      uint32
		forms                          []*reportv0.Form
		favicons                       []*reportv0.Favicon
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
		{name: "a WordPress comment form on wordpress.com isn't asking for details", final: "https://winecoach.wordpress.com/2026/10/x/", title: "Vinhos do Douro", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "textarea", Name: "comment"}, {Type: "text", Name: "email"}, {Type: "text", Name: "author"},
				{Type: "text", Name: "url"}, {Type: "submit", Name: "submit"}}}}, want: ""},
		{name: "a message with a phone number and a second email is an appeal kit, not a comment", final: "https://meta-appeal.vercel.app/", title: "Appeal", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "text", Name: "name"}, {Type: "email", Name: "personal_email"}, {Type: "email", Name: "business_email"},
				{Type: "tel", Name: "mobile_phone_number"}, {Type: "textarea", Name: "message"}}}}, want: "form-on-free-hosting:"},
		{name: "a recovery-phrase box on free hosting", final: "https://wallet-sync.netlify.app/", title: "Restore", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "textarea", Name: "phrase"}, {Type: "text", Name: "name"}}}}, want: "form-on-free-hosting:"},
		{name: "reCAPTCHA's hidden textarea isn't a field a person fills", final: "https://someone.github.io/", title: "My portfolio", dom: noDOM,
			forms: []*reportv0.Form{{Fields: []*reportv0.Field{{Type: "email", Name: "email"}, {Type: "textarea", Name: "g-recaptcha-response"}}}}, want: ""},
		{name: "a static page on free hosting asks for nothing", final: "https://someone.github.io/", title: "My portfolio", dom: noDOM, want: ""},
		{name: "PayPal's favicon off PayPal", final: "https://secure-acct.example/", title: "Account", dom: noDOM,
			favicons: []*reportv0.Favicon{{Sha256: "bb22"}, {Sha256: "aa11", Url: "https://www.paypalobjects.com/favicon.ico"}},
			want:     "brand-favicon-off-domain:paypal"},
		{name: "PayPal's favicon on PayPal", final: "https://www.paypal.com/", title: "Account", dom: noDOM,
			favicons: []*reportv0.Favicon{{Sha256: "aa11"}}, want: ""},
		{name: "password posted elsewhere", final: "https://shop.example/", dom: noDOM, passwords: 1,
			forms: []*reportv0.Form{{HasPassword: true, CrossOriginAction: true, Action: "https://collect.evil.test/p"}},
			want:  "password-form-cross-origin:"},
	} {
		r := &reportv0.Report{
			Navigation: &reportv0.Navigation{FinalUrl: c.final, Title: c.title},
			Page:       &reportv0.Page{ScreenshotPhash: c.phash, PasswordFields: c.passwords, Forms: c.forms, Favicons: c.favicons},
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

func TestKitMatch(t *testing.T) {
	page := `<html><body><div><div><img><h1>Sign in</h1><form><input type="email" name="ai"><input type="password" name="pr">` +
		`<label><input type="checkbox" name="r">r</label><button type="submit">Go</button></form><a>f</a></div>` +
		`<footer><p>c</p><p>p</p></footer></div><div><div><p>x</p><span>y</span><ul><li>a</li><li>b</li></ul></div></div>` +
		`<nav><a>1</a><a>2</a><span><b>3</b><i>4</i></span></nav><section><article><h2>t</h2><p>u</p></article></section></body></html>`
	dir := t.TempDir()
	dom := filepath.Join(dir, "dom.html")
	os.WriteFile(dom, []byte(page), 0o600)
	fp, ok := kits.Of(strings.NewReader(page))
	if !ok {
		t.Fatal("fixture too small for a fingerprint")
	}
	kitRefs = func() []kits.Ref {
		return []kits.Ref{{Run: "r1", Host: "loan.replit.app", Kind: "payment", Labelled: "2026-10-14", Fingerprint: fp}}
	}
	defer func() { kitRefs = kits.Refs }()
	for final, want := range map[string]bool{"https://other.vercel.app/": true, "https://again.replit.app/": false, "https://accounts.google.com/": false} {
		r := &reportv0.Report{Navigation: &reportv0.Navigation{FinalUrl: final}, Page: &reportv0.Page{}}
		got := false
		for _, i := range indicators(r, dom) {
			got = got || i.GetId() == "kit-match"
		}
		if got != want {
			t.Errorf("%s: kit-match %v, want %v", final, got, want)
		}
	}
}

func TestGates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	turnstile := []*reportv0.Flow{{Sni: "challenges.cloudflare.com"}}
	fakeCF := write("fakecf.html", `<div class="box"><input type="checkbox"><span>Verify you are human</span><div>CLOUDFLARE</div><a>Privacy</a> · <a>Help</a></div>`)
	orange := write("orange.html", `<img alt=""><h2>Vérification de sécurité</h2><p>Veuillez saisir le code de sécurité affiché ci-dessous.</p><canvas></canvas><input type="text"><button>Valider</button>`)
	outlook := write("outlook.html", `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script><h1>Outlook</h1><p>One moment — confirming it's you</p><p>Complete the check below to continue</p><div id="ts"></div><p>Microsoft</p>`)
	blocked := write("blocked.html", `<div class="card"><h1>Access Restricted</h1><p>We could not verify your connection. This site only allows traffic from legitimate internet service providers and blocks anonymous proxies, VPNs, and automated clients.</p><a href="/">Go back</a></div>`)
	netflix := write("netflix.html", `<h1>Enter your info to sign in</h1><p>Or get started with a new account.</p><input type="email"><input type="password"><button>Continue</button><p>Get Help</p><p>This page is protected by Google reCAPTCHA to ensure you're not a bot.</p>`)
	ruCaptcha := write("ru.html", `<p>Введите капчу</p><input type="text"><button>Войти</button>`)
	long := write("long.html", `<h1>Security check</h1><p>`+strings.Repeat("our community guidelines explain how moderation works here. ", 12)+`</p>`)

	type tc struct {
		name, final, title, dom string
		flows                   []*reportv0.Flow
		passwords               uint32
		want                    string
	}
	for _, c := range []tc{
		{name: "Cloudflare box drawn in HTML, no Cloudflare", final: "https://professionellerkurier-paketservicex.ink/", title: "Verify you are human", dom: fakeCF,
			want: "fake-human-check:"},
		{name: "the same box with the real Turnstile loaded", final: "https://shop.example/", title: "Just a moment...", dom: fakeCF, flows: turnstile, want: ""},
		{name: "Orange digit CAPTCHA drawn by the page", final: "https://connexion-auth.toclw.xyz/", title: "Vérification CAPTCHA", dom: orange,
			want: "fake-human-check:"},
		{name: "Outlook behind a real Turnstile, off Microsoft", final: "https://check.checkandbalancefirm.top/", title: "Outlook", dom: outlook, flows: turnstile,
			want: "brand-name-off-domain:microsoft"},
		{name: "Revolut's own Cloudflare check", final: "https://app.revolut.com/", title: "Revolut", dom: fakeCF, want: ""},
		{name: "VPN block page on netlify", final: "https://statuesque-dragon-151da0.netlify.app/", title: "Access Restricted", dom: blocked,
			want: "block-page-on-free-hosting:"},
		{name: "VPN block page on a company's own domain", final: "https://portal.example.com/", title: "Access Forbidden", dom: blocked, want: ""},
		{name: "sign-in page that mentions reCAPTCHA", final: "https://login.example.com/", title: "Sign in", dom: netflix, passwords: 1, want: ""},
		{name: "Russian captcha wording", final: "https://captcha-shrew.sion10.to/", title: "Captcha", dom: ruCaptcha, want: "fake-human-check:"},
		{name: "a long page that mentions a security check", final: "https://forum.example/", title: "Rules", dom: long, want: ""},
	} {
		r := &reportv0.Report{
			Navigation: &reportv0.Navigation{FinalUrl: c.final, Title: c.title},
			Page:       &reportv0.Page{PasswordFields: c.passwords},
			Network:    &reportv0.Network{Flows: c.flows},
		}
		var got []string
		for _, i := range indicators(r, c.dom) {
			if i.GetId() == "brand-presented-off-domain" {
				continue
			}
			got = append(got, i.GetId()+":"+i.GetBrand())
		}
		if s := strings.Join(got, " "); s != c.want {
			t.Errorf("%s: got %q, want %q", c.name, s, c.want)
		}
	}
}
