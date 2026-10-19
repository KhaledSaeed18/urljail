package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

func TestRendererPIDs(t *testing.T) {
	proc := t.TempDir()
	add := func(pid int, stat, cmdline string) {
		d := filepath.Join(proc, strconv.Itoa(pid))
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline), 0o644)
	}
	add(100, "100 (chrome) S 1 100 100 0", "/opt/google/chrome/chrome\x00--headless=new\x00")
	add(101, "101 (chrome) S 100 100 100 0", "/opt/google/chrome/chrome\x00--type=zygote\x00")
	add(102, "102 (chrome (render)) S 101 100 100 0", "/opt/google/chrome/chrome\x00--type=renderer\x00--lang=en\x00")
	add(103, "103 (chrome) S 101 100 100 0", "/opt/google/chrome/chrome --type=renderer --lang=en") // title rewritten by the zygote
	add(200, "200 (chrome) S 1 200 200 0", "/opt/google/chrome/chrome\x00--type=renderer\x00")      // another Chrome
	add(300, "300 (sh) S 1 100 100 0", "sh\x00-c\x00echo --type=renderer\x00")                      // not a flag
	got := rendererPIDs(proc, 100)
	slices.Sort(got)
	if !slices.Equal(got, []int{102, 103}) {
		t.Errorf("rendererPIDs = %v, want [102 103]", got)
	}
}

// TestFreshRendererChrome runs the real Chrome: URLJAIL_TEST_CHROME=/path/to/chrome. It checks
// that the renderers from before are gone and a page still loads, in new ones.
func TestFreshRendererChrome(t *testing.T) {
	bin := os.Getenv("URLJAIL_TEST_CHROME")
	if bin == "" {
		t.Skip("URLJAIL_TEST_CHROME not set")
	}
	dir := t.TempDir()
	chromeBin, keyLogPath, chromeLog = bin, filepath.Join(dir, "keys.log"), filepath.Join(dir, "chrome.log")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	b, err := startBrowser(ctx, &guestv1.BrowserProfile{}, "155.0.8059.39-1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.ch.close()
	var before []int
	for range 50 { // the about:blank renderer starts a moment after the browser
		if before = rendererPIDs("/proc", b.ch.cmd.Process.Pid); len(before) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(before) == 0 {
		t.Fatal("no renderer before")
	}
	start := time.Now()
	if err := b.freshRenderer(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("replaced %d renderer(s) in %s", len(before), time.Since(start))
	b.discardQueued()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>loading</title></head><body><script>document.title = "r=" + Math.random()</script></body></html>`)
	}))
	defer srv.Close()
	pctx := cdpctx.WithExecutor(ctx, b.page)
	if _, _, navErr, _, err := page.Navigate(srv.URL).Do(pctx); err != nil || navErr != "" {
		t.Fatalf("navigate after the renderer was replaced: %v %q", err, navErr)
	}
	bctx := cdpctx.WithExecutor(ctx, b.browser)
	title := ""
	for range 50 {
		info, err := target.GetTargetInfo().WithTargetID(b.targetID).Do(bctx)
		if err == nil && len(info.Title) > 2 && info.Title[:2] == "r=" {
			title = info.Title
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if title == "" {
		t.Fatal("the page's script never ran")
	}
	after := rendererPIDs("/proc", b.ch.cmd.Process.Pid)
	if len(after) == 0 {
		t.Fatal("no renderer after")
	}
	for _, p := range after {
		if slices.Contains(before, p) {
			t.Errorf("renderer %d from before is still there (before %v, after %v)", p, before, after)
		}
	}
	t.Logf("before %v, after %v, %s", before, after, title)
}
