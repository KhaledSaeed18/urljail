package kits

import (
	"strings"
	"testing"
)

const loginKit = `<html><body><div class="wrap"><div class="card"><img src="logo.png"><h1>Sign in</h1>
<form action="post.php" method="post"><input type="email" name="ai"><input type="password" name="pr">
<label><input type="checkbox" name="remember">Remember</label><button type="submit">Login</button></form>
<a href="#">Forgot password?</a></div><footer><p>Copyright</p><p>Privacy</p></footer></div>
<div class="modal"><div class="modal-body"><p>x</p><span>y</span><ul><li>a</li><li>b</li></ul></div></div>
<nav><a>1</a><a>2</a><span><b>3</b><i>4</i></span></nav><section><article><h2>t</h2><p>u</p></article></section>
<script>var lots = "of script text that is not structure";</script></body></html>`

func TestSameKitDifferentText(t *testing.T) {
	a, ok := Of(strings.NewReader(loginKit))
	if !ok {
		t.Fatalf("no fingerprint (%d shingles)", a.Shingles)
	}
	// Same kit: other words, other brand, other script; same structure and field names.
	other := strings.NewReplacer("Sign in", "Connexion", "Copyright", "Droits", "of script text", "entirely different code").Replace(loginKit)
	b, _ := Of(strings.NewReader(other))
	if s := Similarity(a, b); s != 1 {
		t.Errorf("same structure, different text: similarity %.2f", s)
	}
	// A different page: a blog.
	blog := `<html><body><header><nav><ul><li><a>Home</a></li><li><a>About</a></li></ul></nav></header><main>` +
		strings.Repeat(`<article><h2>Post</h2><p>Text <em>em</em></p><figure><img><figcaption>c</figcaption></figure></article>`, 5) +
		`<aside><h3>Tags</h3><ul><li>x</li></ul></aside></main><footer><p>c</p></footer></body></html>`
	c, ok := Of(strings.NewReader(blog))
	if !ok {
		t.Fatalf("blog: no fingerprint (%d)", c.Shingles)
	}
	if s := Similarity(a, c); s > 0.3 {
		t.Errorf("login kit vs blog: similarity %.2f", s)
	}
	if _, ok := Of(strings.NewReader(`<html><body><p>hi</p></body></html>`)); ok {
		t.Error("a tiny page should have no fingerprint")
	}
}

func TestSamePlace(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"x.github.io", "y.github.io", true},             // same platform
		{"a.gitbook.io", "b.gitbook.io", true},           // same platform
		{"login.evil.com", "www.evil.com", true},         // same site
		{"x.replit.app", "y.vercel.app", false},          // different platforms
		{"bagidimofu.duckdns.org", "kit.example", false}, // different sites
		{"", "x.example", true},
	} {
		if got := SamePlace(c.a, c.b); got != c.want {
			t.Errorf("SamePlace(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestMatch(t *testing.T) {
	a, _ := Of(strings.NewReader(loginKit))
	refs := []Ref{{Run: "r1", Host: "kit.replit.app", Fingerprint: a}}
	if _, s, ok := Match(refs, a, "other.vercel.app"); !ok || s != 1 {
		t.Errorf("same kit elsewhere: %v %.2f", ok, s)
	}
	if _, _, ok := Match(refs, a, "kit2.replit.app"); ok {
		t.Error("a match on the same platform must not count")
	}
}

func FuzzOf(f *testing.F) {
	f.Add([]byte(loginKit))
	f.Fuzz(func(t *testing.T, b []byte) { Of(strings.NewReader(string(b))) })
}
