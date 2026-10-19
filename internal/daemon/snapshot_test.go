package daemon

import (
	"context"
	"testing"
	"time"
)

func TestSnapshotOld(t *testing.T) {
	s := &Server{cfg: Config{SnapshotMaxAge: 24 * time.Hour}}
	for _, c := range []struct {
		age  time.Duration
		want bool
	}{{time.Hour, false}, {23 * time.Hour, false}, {25 * time.Hour, true}, {5 * 24 * time.Hour, true}} {
		if got := s.snapshotOld(snapshotManifest{Created: time.Now().Add(-c.age)}); got != c.want {
			t.Errorf("age %s: old = %v, want %v", c.age, got, c.want)
		}
	}
	never := &Server{cfg: Config{}}
	if never.snapshotOld(snapshotManifest{Created: time.Now().Add(-30 * 24 * time.Hour)}) {
		t.Error("SnapshotMaxAge 0 must never call a snapshot old")
	}
}

// Without snapshots or a maximum age, the refresher returns at once instead of polling.
func TestRefreshSnapshotsOff(t *testing.T) {
	done := make(chan struct{})
	go func() {
		(&Server{cfg: Config{SnapshotMaxAge: time.Hour}}).RefreshSnapshots(context.Background()) // cold boot: no snapshots
		(&Server{snaps: map[string]*snapshot{}}).RefreshSnapshots(context.Background())          // no maximum age
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshSnapshots kept running with nothing to refresh")
	}
}
