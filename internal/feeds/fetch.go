package feeds

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Source is a feed urljail fetches.
type Source struct {
	Name        string
	URL         string
	MinInterval time.Duration // never fetch more often (provider terms and courtesy)
	Attribution string
}

// OpenPhishCommunity is OpenPhish's free feed: plain text, one URL per line, updated every
// 12 hours; independent research use is allowed by its terms (docs/research/feeds.md).
var OpenPhishCommunity = Source{
	Name:        "openphish-community",
	URL:         "https://openphish.com/feed.txt",
	MinInterval: time.Hour,
	Attribution: "OpenPhish (https://openphish.com)",
}

const maxFeedBytes = 8 << 20

// Fetch downloads src if it's due and changed (conditional GET), and returns its usable URLs
// normalized. not-due and not-modified return no URLs and no error.
func Fetch(ctx context.Context, c *http.Client, src Source, st *FetchState, now time.Time) (urls []string, skipped int, err error) {
	if !st.LastFetch.IsZero() && now.Sub(st.LastFetch) < src.MinInterval {
		return nil, 0, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "urljail-feeds (research; https://github.com/KhaledSaeed18/urljail)")
	if st.ETag != "" {
		req.Header.Set("If-None-Match", st.ETag)
	}
	if st.LastModified != "" {
		req.Header.Set("If-Modified-Since", st.LastModified)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	st.LastFetch = now
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, 0, nil
	case http.StatusOK:
	default:
		return nil, 0, fmt.Errorf("%s: HTTP %d", src.Name, resp.StatusCode)
	}
	st.ETag, st.LastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	urls, skipped, err = ParseLines(io.LimitReader(resp.Body, maxFeedBytes))
	st.LastCount, st.LastSkipped = len(urls), skipped
	return urls, skipped, err
}

// ParseLines reads one URL per line, skipping (and counting) anything unusable.
func ParseLines(r io.Reader) (urls []string, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		if u, err := Normalize(sc.Text()); err == nil {
			urls = append(urls, u)
		} else if sc.Text() != "" {
			skipped++
		}
	}
	return urls, skipped, sc.Err()
}
