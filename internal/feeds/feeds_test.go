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

func TestScore(t *testing.T) {
	for name, want := range map[string]bool{
		"paypal-account-verify.com":       true,
		"login.micros0ft-support.top":     true,
		"secure-auspost-parcel.info":      true,
		"www.paypal.com":                  false, // the brand itself
		"paypal-shop.myshopify.com":       false, // platform subdomain
		"myupsidedown.com":                false, // "ups" only as a token
		"secure-login-portal.example.com": false, // no brand
		"applesauce-recipes.com":          false, // apple is token-only
		"ups-tracking-delivery.xyz":       true,
		// Found live in P6 (CT watch): false positives and real candidates.
		"auto-s1285612mzi2-pbi-kv-httpszonede.zde.w.api.fabric.microsoft-int.com": false,
		"fihcbalkjidde0604d0-f14d-49fa-848a-d1acc7altlinkedin123.t.jfdir.com":     false,
		"m.whm.whm.teprwuqv.forticloud.online":                                    false, // icloud inside a word
		"bitsagawallet.com":                                                       false,
		"onlinemedical.cz":                                                        false,
		"tomato-shop.top":                                                         false, // "ato" inside a word
		"bahmanaccounting.com":                                                    false, // not account+ING
		"hightopaccounting.com":                                                   false,
		"bookingsupport.example.com":                                              false,
		"tdkonline.com":                                                           false, // "td" + not an action word
		"verify-r1.americanexpress.com":                                           false, // the brand's own domain
		"api.prod.lws.kuiper.amazon.dev":                                          false,
		"schemas.cn-north-1.api.amazonwebservices.com.cn":                         false,
		"instagram.co":                                                            false,
		"accounts.tdaccounts.online":                                              true,
		"dhldelivery-status.com":                                                  true,
		"facebookabc.cc":                                                          true, // Cloudflare-flagged 5 min after its certificate
		"www.microsoftonline3.com":                                                true,
		"canadapost-delivery.top":                                                 true,
		"secure-account-verify.top":                                               true, // words only, on a cheap TLD
		"paypal.secure-login.top":                                                 true, // brand in a subdomain
		"track.hibuzdrinks.com":                                                   false,
	} {
		s, why := Score(name)
		if (s >= CandidateScore) != want {
			t.Errorf("Score(%q) = %d %v, candidate want %v", name, s, why, want)
		}
	}
}

func TestMinAgeFeedPauseLock(t *testing.T) {
	now := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.AddCandidate(&Item{URL: "https://young.test/", Feed: "ct", FirstSeen: now.Add(-time.Minute)})
	s.AddCandidate(&Item{URL: "https://ready.test/", Feed: "ct", FirstSeen: now.Add(-10 * time.Minute)})
	s.Add("openphish-community", []string{"https://other.test/"}, now.Add(-time.Minute))
	l := DefaultLimits
	l.MinAge, l.Feed = 5*time.Minute, "ct"
	got := s.Next(5, now, l)
	if len(got) != 1 || got[0].URL != "https://ready.test/" {
		t.Fatalf("Next = %v", got)
	}
	if s.Items["https://young.test/"].Status != "queued" {
		t.Error("a young candidate must wait, not expire")
	}

	s.Items["https://ready.test/"].NotBefore = now.Add(time.Minute)
	if got := s.Next(5, now, l); len(got) != 0 {
		t.Errorf("retry before NotBefore: %v", got)
	}
	if got := s.Next(5, now.Add(2*time.Minute), l); len(got) == 0 {
		t.Error("no retry after NotBefore")
	}

	if s.IsPaused() {
		t.Fatal("paused at start")
	}
	if s.SetPaused(true) != nil || !s.IsPaused() || s.SetPaused(false) != nil || s.IsPaused() || s.SetPaused(false) != nil {
		t.Error("pause/resume")
	}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil { // flock is per open file: a second open conflicts
		t.Error("second lock succeeded")
	}
	unlock()
	if u, err := s.Lock(); err != nil {
		t.Errorf("lock after unlock: %v", err)
	} else {
		u()
	}
}

func TestRescore(t *testing.T) {
	s := &Store{Items: map[string]*Item{}}
	s.AddCandidate(&Item{URL: "https://schemas.cn-north-1.api.amazonwebservices.com.cn/", Feed: "ct", Score: 4})
	s.AddCandidate(&Item{URL: "https://paypal-account-verify.com/", Feed: "ct", Score: 4})
	s.AddCandidate(&Item{URL: "https://other.test/", Feed: "openphish-community"})
	if n := s.Rescore("ct", CandidateScore, Score); n != 1 {
		t.Fatalf("dropped %d", n)
	}
	if s.Items["https://paypal-account-verify.com/"].Status != "queued" || s.Items["https://other.test/"].Status != "queued" {
		t.Error("rescored the wrong items")
	}
}
