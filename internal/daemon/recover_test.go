package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KhaledSaeed18/urljail/internal/operator"
	"github.com/KhaledSaeed18/urljail/internal/report"
)

func TestRecoverRunsMarksInterrupted(t *testing.T) {
	dir := t.TempDir()
	op := operator.Operator{UID: os.Getuid(), GID: os.Getgid()}
	s := New(Config{RunsDir: dir, Operator: op}, nil, slog.New(slog.DiscardHandler))
	// The helper is this test binary, which isn't urljaild: only the bookkeeping is checked.
	write := func(id, status string) string {
		d := filepath.Join(dir, id)
		os.MkdirAll(d, 0o700)
		report.WriteMeta(d, report.Meta{RunID: id, URL: "https://x.test/", Status: status, StartedAt: time.Now()})
		return d
	}
	stuck := write("stuck", "")
	done := write("done", "completed")
	os.MkdirAll(filepath.Join(dir, "not-a-run"), 0o700)

	if n := s.RecoverRuns(context.Background()); n != 1 {
		t.Fatalf("recovered %d, want 1", n)
	}
	if m, _ := report.ReadMeta(stuck); m.Status != "interrupted" || m.Error == "" {
		t.Errorf("stuck run: %+v", m)
	}
	if m, _ := report.ReadMeta(done); m.Status != "completed" {
		t.Errorf("finished run changed: %+v", m)
	}
	if n := s.RecoverRuns(context.Background()); n != 0 {
		t.Errorf("second pass recovered %d", n)
	}
}
