package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/hostnet"
	"github.com/KhaledSaeed18/urljail/internal/version"
	"github.com/KhaledSaeed18/urljail/internal/vm"
)

const (
	// shutdownGrace is how long the guest gets to shut down after Ctrl-Alt-Del before the VMM
	// is killed. A guest still booting ignores Ctrl-Alt-Del, and evidence is collected before
	// teardown, so there's nothing to wait for beyond a clean exit.
	shutdownGrace = 3 * time.Second
	// cleanupStepTimeout bounds each teardown step separately, so one slow step can't use up
	// the time the others need.
	cleanupStepTimeout = 10 * time.Second
)

// meta is runs/<id>/meta.json: the inputs of a run (docs/architecture.md#storage-layout-per-run).
type meta struct {
	RunID     string            `json:"run_id"`
	URL       string            `json:"url"`
	Profile   string            `json:"profile"`
	Egress    string            `json:"egress"`
	Timeout   string            `json:"timeout"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at,omitzero"`
	Status    string            `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Versions  map[string]string `json:"versions"`
}

// detonate runs the VM part of a detonation. It always tears down what it started.
func (s *Server) detonate(ctx context.Context, r *run, u *url.URL, profile string, timeout time.Duration) (err error) {
	slot, ok := s.slots.acquire()
	if !ok {
		return fmt.Errorf("all %d VM slots are busy", s.slots.size())
	}
	defer s.slots.release(slot)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runDir := filepath.Join(s.cfg.RunsDir, r.id)
	if err := os.MkdirAll(filepath.Join(runDir, "host"), 0o700); err != nil {
		return err
	}
	m := meta{
		RunID: r.id, URL: u.String(), Profile: profile, Egress: string(s.cfg.Policy.Mode),
		Timeout: timeout.String(), StartedAt: time.Now().UTC(),
		Versions: map[string]string{
			"urljail":      version.String(),
			"firecracker":  s.cfg.FirecrackerVersion,
			"guest_kernel": s.cfg.GuestKernel,
			"rootfs":       s.cfg.RootfsName,
		},
	}
	writeMeta(runDir, m)
	defer func() {
		m.EndedAt = time.Now().UTC()
		m.Status = "completed"
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			m.Status = "timeout"
		case errors.Is(ctx.Err(), context.Canceled):
			m.Status = "cancelled" // client went away, or the daemon is shutting down
		case err != nil:
			m.Status = "error"
			m.Error = err.Error()
		}
		writeMeta(runDir, m)
	}()

	// Teardown ignores cancellation of the run: a client disconnecting or the timeout firing
	// must still leave nothing behind. Each step gets its own fresh deadline.
	var cleanups []func(context.Context)
	defer func() {
		_ = r.send(daemonv1.RunState_RUN_STATE_TEARDOWN, "stopping VM, removing tap and disk")
		base := context.WithoutCancel(ctx)
		for i := len(cleanups) - 1; i >= 0; i-- {
			sctx, scancel := context.WithTimeout(base, cleanupStepTimeout)
			cleanups[i](sctx)
			scancel()
		}
	}()

	if err := r.send(daemonv1.RunState_RUN_STATE_BOOTING, "cold boot (no snapshots before P4)"); err != nil {
		return err
	}

	workDir := filepath.Join(s.cfg.WorkDir, r.id)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}
	cleanups = append(cleanups, func(context.Context) { os.RemoveAll(workDir) })
	rootfs := filepath.Join(workDir, "rootfs.ext4")
	if err := vm.CloneFile(s.cfg.Rootfs, rootfs); err != nil {
		return fmt.Errorf("cloning rootfs: %w", err)
	}

	tap := hostnet.TapFor(slot)
	if err := s.egress.AddTap(ctx, tap); err != nil {
		return err
	}
	cleanups = append(cleanups, func(ctx context.Context) { s.egress.RemoveTap(ctx, tap.Name) })

	t0 := time.Now()
	machine, err := vm.Start(ctx, vm.Config{
		Firecracker: s.cfg.Firecracker,
		Socket:      filepath.Join(s.cfg.SocketDir, r.id+".sock"),
		LogDir:      filepath.Join(runDir, "host"),
		Kernel:      s.cfg.Kernel,
		BootArgs:    "console=ttyS0 reboot=k panic=1 " + tap.BootArgs(),
		Rootfs:      rootfs,
		TapName:     tap.Name,
		GuestMAC:    tap.GuestMAC,
		VCPUs:       s.cfg.VCPUs,
		MemMiB:      s.cfg.MemMiB,
	})
	if err != nil {
		return err
	}
	cleanups = append(cleanups, func(ctx context.Context) {
		gctx, gcancel := context.WithTimeout(ctx, shutdownGrace)
		defer gcancel()
		_ = machine.Shutdown(gctx)
	})
	r.log.Info("vm started", "pid", machine.PID(), "tap", tap.Name, "guest", tap.GuestIP)

	// Until the guest agent exists (M4), "ready" means the guest answers on TCP 22.
	if err := waitTCP(ctx, machine, net.JoinHostPort(tap.GuestIP, "22")); err != nil {
		return err
	}
	if err := r.send(daemonv1.RunState_RUN_STATE_NET_READY,
		fmt.Sprintf("guest %s reachable %d ms after start (no guest agent yet: nothing is navigated)",
			tap.GuestIP, time.Since(t0).Milliseconds())); err != nil {
		return err
	}
	return nil
}

// waitTCP polls addr until it accepts a connection, the VM exits, or ctx ends.
func waitTCP(ctx context.Context, m *vm.Machine, addr string) error {
	for {
		d := net.Dialer{Timeout: 200 * time.Millisecond}
		if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-m.Done():
			return errors.New("VM exited before the guest came up (see host/serial.log)")
		case <-ctx.Done():
			return fmt.Errorf("guest not reachable: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func writeMeta(runDir string, m meta) {
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(runDir, "meta.json"), append(b, '\n'), 0o600)
}
