package daemon

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/KhaledSaeed18/urljail/internal/report"
)

// RecoverRuns finishes the bookkeeping of runs a stopped daemon left behind (a crash, a
// SIGKILL): their meta.json still has no status, the directory is still root's and there is no
// report. Each gets status "interrupted", goes to the operator and gets a report built by the
// unprivileged helper. Call it at startup, before serving. It returns how many it recovered.
func (s *Server) RecoverRuns(ctx context.Context) int {
	entries, err := os.ReadDir(s.cfg.RunsDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.cfg.RunsDir, e.Name())
		m, merr := report.ReadMeta(dir)
		var st syscall.Stat_t
		notOurs := syscall.Stat(dir, &st) == nil && int(st.Uid) != s.cfg.Operator.UID
		if merr != nil || (m.Status != "" && !notOurs) {
			continue // not a run directory, or finished normally
		}
		if m.Status == "" {
			m.Status = "interrupted"
			m.Error = "the daemon stopped before the run finished"
			if err := report.WriteMeta(dir, m); err != nil {
				s.log.Warn("recovering run", "run", e.Name(), "err", err)
				continue
			}
		}
		if err := s.cfg.Operator.ChownTree(dir); err != nil {
			s.log.Warn("recovering run", "run", e.Name(), "err", err)
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "selftest.json")); err != nil { // self-tests have no report
			if err := s.buildReport(ctx, dir); err != nil {
				s.log.Warn("recovering run: report", "run", e.Name(), "err", err)
			}
		}
		n++
	}
	if n > 0 {
		s.log.Info("recovered interrupted runs", "count", n)
	}
	return n
}
