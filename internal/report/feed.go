package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

// FeedFile is written into a run directory by `urljail feeds` (the operator's process, not the
// daemon or the guest) when the URL came from a feed.
const FeedFile = "feed.json"

// FeedMeta is the content of FeedFile.
type FeedMeta struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
	FeedTime  time.Time `json:"feed_time,omitzero"`
}

// WriteFeed records feed provenance in a run directory.
func WriteFeed(runDir string, m FeedMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, FeedFile), append(b, '\n'), 0o600)
}

func readFeed(runDir string) *reportv0.Feed {
	b, err := os.ReadFile(filepath.Join(runDir, FeedFile))
	if err != nil || len(b) > 64<<10 {
		return nil
	}
	var m FeedMeta
	if json.Unmarshal(b, &m) != nil || m.Name == "" {
		return nil
	}
	f := &reportv0.Feed{Name: m.Name, FirstSeen: ts(m.FirstSeen)}
	if !m.FeedTime.IsZero() {
		f.FeedTime = ts(m.FeedTime)
	}
	return f
}
