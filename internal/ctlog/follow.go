package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// LogListURL is Chrome's list of CT logs.
const LogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Log is a static-ct-api log to follow.
type Log struct {
	Name   string // description from the log list
	Prefix string // monitoring prefix, ending in "/"
}

const userAgent = "urljail-ct (research; https://github.com/KhaledSaeed18/urljail)"

func get(ctx context.Context, c *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s: larger than %d bytes", url, max)
	}
	return b, err
}

// CurrentLogs returns the usable static-ct-api logs of the given operators whose certificate
// window contains now (log shards rotate every six months).
func CurrentLogs(ctx context.Context, c *http.Client, operators []string, now time.Time) ([]Log, error) {
	b, err := get(ctx, c, LogListURL, 8<<20)
	if err != nil {
		return nil, err
	}
	var list struct {
		Operators []struct {
			Name      string `json:"name"`
			TiledLogs []struct {
				Description   string                     `json:"description"`
				MonitoringURL string                     `json:"monitoring_url"`
				State         map[string]json.RawMessage `json:"state"`
				Interval      struct {
					Start time.Time `json:"start_inclusive"`
					End   time.Time `json:"end_exclusive"`
				} `json:"temporal_interval"`
			} `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	var out []Log
	for _, op := range list.Operators {
		if !slices.Contains(operators, op.Name) {
			continue
		}
		for _, l := range op.TiledLogs {
			_, usable := l.State["usable"]
			_, qualified := l.State["qualified"]
			if !(usable || qualified) || now.Before(l.Interval.Start) || !now.Before(l.Interval.End) ||
				!strings.HasPrefix(l.MonitoringURL, "https://") {
				continue
			}
			p := l.MonitoringURL
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			out = append(out, Log{Name: l.Description, Prefix: p})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no current static-ct-api logs from %v", operators)
	}
	return out, nil
}

// Follower reads a log's new entries as they are appended.
type Follower struct {
	Client *http.Client
	Log    Log
	Poll   time.Duration // checkpoint interval
	MaxLag uint64        // tiles behind before skipping ahead to the newest
	// Skipped is called when entries are skipped to catch up (freshness over completeness).
	Skipped func(n uint64)
}

// Run sends every entry appended from now on (full tiles only) until ctx ends.
func (f *Follower) Run(ctx context.Context, out chan<- Entry) error {
	next, started := uint64(0), false
	for {
		b, err := get(ctx, f.Client, f.Log.Prefix+"checkpoint", 64<<10)
		if err == nil {
			var cp Checkpoint
			if cp, err = ParseCheckpoint(b); err == nil {
				full := cp.Size / TileWidth
				if !started {
					next, started = full, true // from now on: history isn't fresh
				}
				if full > next+f.MaxLag {
					if f.Skipped != nil {
						f.Skipped((full - next - 1) * TileWidth)
					}
					next = full - 1
				}
				for ; next < full; next++ {
					tile, err := get(ctx, f.Client, f.Log.Prefix+"tile/data/"+TilePath(next), 16<<20)
					if err != nil {
						break // retry this tile after the next poll
					}
					es, _ := ParseDataTile(tile, next*TileWidth) // a bad entry ends the tile; keep the rest
					for _, e := range es {
						select {
						case out <- e:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.Poll):
		}
	}
}
