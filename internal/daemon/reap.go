package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/KhaledSaeed18/urljail/internal/hostnet"
)

// Reap removes what a crashed daemon may have left behind: Firecracker processes on our
// socket directory, urljaild TAPs, and per-run scratch directories. Call it before serving.
func Reap(ctx context.Context, cfg Config, egress *hostnet.Egress, log *slog.Logger) {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		args := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
		if len(args) < 3 || filepath.Base(string(args[0])) != "firecracker" {
			continue
		}
		for i := 1; i+1 < len(args); i++ {
			if string(args[i]) == "--api-sock" && filepath.Dir(string(args[i+1])) == filepath.Clean(cfg.SocketDir) {
				pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(p)))
				log.Warn("reaping orphaned firecracker", "pid", pid, "socket", string(args[i+1]))
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}

	if egress != nil {
		taps, err := hostnet.LeftoverTaps(ctx)
		if err != nil {
			log.Warn("listing taps", "err", err)
		}
		for _, t := range taps {
			log.Warn("reaping leftover tap", "tap", t)
			egress.RemoveTap(ctx, t)
		}
	}

	if entries, err := os.ReadDir(cfg.WorkDir); err == nil {
		for _, e := range entries {
			log.Warn("reaping leftover work dir", "dir", e.Name())
			_ = os.RemoveAll(filepath.Join(cfg.WorkDir, e.Name()))
		}
	}
	socks, _ := filepath.Glob(filepath.Join(cfg.SocketDir, "*.sock"))
	for _, s := range socks {
		_ = os.Remove(s)
	}
}
