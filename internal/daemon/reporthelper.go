package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KhaledSaeed18/urljail/internal/report"
)

// ReportHelperArg is the hidden subcommand urljaild runs itself with to build a report. The
// report builder parses guest-controlled bytes (CDP events, the DOM, ClientHellos), so it
// runs as the operator, who owns the run directory, not as root (threat model: "the root
// daemon parses guest-controlled data").
const ReportHelperArg = "__build-report"

const reportTimeout = 60 * time.Second

// buildReport writes runDir/report.json in an unprivileged child process. Call it after
// the run directory belongs to the operator.
func (s *Server) buildReport(ctx context.Context, runDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	op := s.cfg.Operator
	cmd := exec.CommandContext(ctx, exe, ReportHelperArg, runDir)
	cmd.Dir, cmd.Env = "/", []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(op.UID), Gid: uint32(op.GID), Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		return fmt.Errorf("report helper: %w: %s", err, msg)
	}
	return nil
}

// RunReportHelper is the helper process: it refuses to run as root, takes no new privileges,
// caps its memory, open files and output size, then builds the report.
func RunReportHelper(runDir string) error {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("the report helper must not run as root")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	debug.SetMemoryLimit(768 << 20) // the Go heap; the hard caps below back it up
	for _, l := range []struct {
		res int
		max uint64
	}{
		{unix.RLIMIT_AS, 4 << 30},
		{unix.RLIMIT_NOFILE, 64},
		{unix.RLIMIT_FSIZE, 256 << 20}, // report.json
		// Not RLIMIT_NPROC: it counts the operator's whole session, and Go needs threads.
		{unix.RLIMIT_CORE, 0},
	} {
		if err := unix.Setrlimit(l.res, &unix.Rlimit{Cur: l.max, Max: l.max}); err != nil {
			return fmt.Errorf("rlimit %d: %w", l.res, err)
		}
	}
	_, err := report.Write(runDir)
	return err
}
