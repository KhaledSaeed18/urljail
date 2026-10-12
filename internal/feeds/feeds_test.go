package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"HTTPS://Login.Example.COM:443/a?b=1#frag": "https://login.example.com/a?b=1",
		"http://user:pw@x.test:80/":                "http://x.test/",
		"  https://x.test/path  ":                  "https://x.test/path",
	}
	for in, want := range ok {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x.test/", "javascript:alert(1)", "https://x.test:22/", "https://x.test/a b", "https://x.test/\x00", "/relative", strings.Repeat("a", 3000)} {
		if got, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", bad, got)
		}
	}
	if d := Domain("https://a.b.example.co.uk/x"); d != "example.co.uk" {
		t.Errorf("Domain = %q", d)
	}
}

func TestNextLimits(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	s := &Store{Items: map[string]*Item{}}
	s.Add("f", []string{"https://a.evil.test/1", "https://b.evil.test/2", "https://other.test/x"}, now.Add(-time.Hour))
	s.Add("f", []string{"https://old.test/x"}, now.Add(-48*time.Hour))
	s.Items["https://ran.test/x"] = &Item{URL: "https://ran.test/x", Domain: "ran.test", Status: "done", RunAt: now.Add(-time.Minute)}
	s.Add("f", []string{"https://ran.test/y"}, now)

	got := s.Next(10, now, DefaultLimits)
	var urls []string
	for _, it := range got {
		urls = append(urls, it.URL)
	}
	// one per registrable domain per batch (evil.test), ran.test inside its 10-minute gap, old expired
	if len(got) != 2 || s.Items["https://old.test/x"].Status != "expired" {
		t.Fatalf("Next = %v, old status %q", urls, s.Items["https://old.test/x"].Status)
	}
	for _, u := range urls {
		if strings.Contains(u, "ran.test") || strings.Contains(u, "old.test") {
			t.Errorf("picked %s", u)
		}
	}
}

func TestFetchConditional(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("https://x.test/a\nnot a url\n\nhttps://y.test/b\n"))
	}))
	defer srv.Close()
	src := Source{Name: "t", URL: srv.URL, MinInterval: time.Hour}
	st := &FetchState{}
	now := time.Now()
	urls, skipped, err := Fetch(context.Background(), srv.Client(), src, st, now)
	if err != nil || len(urls) != 2 || skipped != 1 {
		t.Fatalf("first fetch: %v %d %v", urls, skipped, err)
	}
	if urls, _, _ := Fetch(context.Background(), srv.Client(), src, st, now.Add(time.Minute)); urls != nil || hits != 1 {
		t.Fatalf("fetched again inside MinInterval (hits %d)", hits)
	}
	if urls, _, err := Fetch(context.Background(), srv.Client(), src, st, now.Add(2*time.Hour)); urls != nil || err != nil || hits != 2 {
		t.Fatalf("conditional fetch: %v %v hits %d", urls, err, hits)
	}
}

func FuzzNormalize(f *testing.F) {
	f.Add("https://x.test/a?b#c")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Normalize(s)
		if err != nil {
			return
		}
		again, err := Normalize(got) // normalized output must be stable and still valid
		if err != nil || again != got {
			t.Fatalf("Normalize(%q) = %q, then %q, %v", s, got, again, err)
		}
	})
}
