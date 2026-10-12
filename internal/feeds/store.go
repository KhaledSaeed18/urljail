package feeds

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Item is one URL from a feed and what became of it.
type Item struct {
	URL       string    `json:"url"`
	Domain    string    `json:"domain"`
	Feed      string    `json:"feed"`
	FirstSeen time.Time `json:"first_seen"` // when urljail first saw it in the feed
	Status    string    `json:"status"`     // queued, running, done, failed, refused, expired
	RunID     string    `json:"run_id,omitempty"`
	RunAt     time.Time `json:"run_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// FetchState is what urljail remembers about a source between fetches.
type FetchState struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastFetch    time.Time `json:"last_fetch,omitzero"`
	LastCount    int       `json:"last_count"`
	LastSkipped  int       `json:"last_skipped"`
}

// Store is ~/.local/share/urljail/feeds/state.json.
type Store struct {
	path    string
	Items   map[string]*Item       `json:"items"`
	Sources map[string]*FetchState `json:"sources"`
	Paused  bool                   `json:"paused"`
}

// Open loads the store in dir, or starts an empty one.
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "state.json"), Items: map[string]*Item{}, Sources: map[string]*FetchState{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Items == nil {
		s.Items = map[string]*Item{}
	}
	if s.Sources == nil {
		s.Sources = map[string]*FetchState{}
	}
	return s, nil
}

// Save writes the store atomically, private to the operator.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Source returns the fetch state of a source, creating it.
func (s *Store) Source(name string) *FetchState {
	if s.Sources[name] == nil {
		s.Sources[name] = &FetchState{}
	}
	return s.Sources[name]
}

// Add queues new URLs from a feed; URLs already known keep their first-seen time and status.
func (s *Store) Add(feed string, urls []string, now time.Time) (added int) {
	for _, u := range urls {
		if s.Items[u] != nil {
			continue
		}
		s.Items[u] = &Item{URL: u, Domain: Domain(u), Feed: feed, FirstSeen: now, Status: "queued"}
		added++
	}
	return added
}

// Limits are the scheduling rules (docs/feed-ingestion.md#queue-and-scheduling).
type Limits struct {
	MaxAge      time.Duration // older than this (since first seen) expires: stale phishing is mostly dead
	DomainGap   time.Duration // at most one run per registrable domain within this
	DomainDaily int           // and at most this many per domain per 24 h
}

// DefaultLimits are gentle on the (often compromised) sites behind phishing URLs.
var DefaultLimits = Limits{MaxAge: 24 * time.Hour, DomainGap: 10 * time.Minute, DomainDaily: 5}

// Next picks up to n queued URLs to run now: newest first, within the per-domain limits.
// Queued URLs past MaxAge are marked expired.
func (s *Store) Next(n int, now time.Time, l Limits) []*Item {
	lastRun := map[string]time.Time{}
	daily := map[string]int{}
	var queued []*Item
	for _, it := range s.Items {
		if !it.RunAt.IsZero() {
			if it.RunAt.After(lastRun[it.Domain]) {
				lastRun[it.Domain] = it.RunAt
			}
			if now.Sub(it.RunAt) < 24*time.Hour {
				daily[it.Domain]++
			}
		}
		if it.Status == "queued" {
			if now.Sub(it.FirstSeen) > l.MaxAge {
				it.Status = "expired"
				continue
			}
			queued = append(queued, it)
		}
	}
	sort.Slice(queued, func(i, j int) bool {
		if !queued[i].FirstSeen.Equal(queued[j].FirstSeen) {
			return queued[i].FirstSeen.After(queued[j].FirstSeen)
		}
		return queued[i].URL < queued[j].URL
	})
	var out []*Item
	for _, it := range queued {
		if len(out) == n {
			break
		}
		if t, ok := lastRun[it.Domain]; ok && now.Sub(t) < l.DomainGap || daily[it.Domain] >= l.DomainDaily {
			continue
		}
		out = append(out, it)
		lastRun[it.Domain] = now // one per domain per batch
		daily[it.Domain]++
	}
	return out
}

// Counts tallies items by status.
func (s *Store) Counts() map[string]int {
	c := map[string]int{}
	for _, it := range s.Items {
		c[it.Status]++
	}
	return c
}
