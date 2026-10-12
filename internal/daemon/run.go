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

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/guestinfo"
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
	img := s.cfg.Image
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
			"image":        img.Manifest.Name,
			"guest_kernel": img.Manifest.Kernel.Name,
			"browser":      img.Manifest.Browser.Version,
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
	if err := vm.CloneFile(img.Rootfs, rootfs); err != nil {
		return fmt.Errorf("cloning rootfs: %w", err)
	}

	tap := hostnet.TapFor(slot)
	if err := s.egress.AddTap(ctx, tap); err != nil {
		return err
	}
	cleanups = append(cleanups, func(ctx context.Context) { s.egress.RemoveTap(ctx, tap.Name) })

	vsockUDS := filepath.Join(s.cfg.SocketDir, r.id+".vsock")
	t0 := time.Now()
	machine, err := vm.Start(ctx, vm.Config{
		Firecracker: s.cfg.Firecracker,
		Socket:      filepath.Join(s.cfg.SocketDir, r.id+".sock"),
		LogDir:      filepath.Join(runDir, "host"),
		Kernel:      img.Kernel,
		BootArgs:    "console=ttyS0 reboot=k panic=1 init=" + img.Manifest.Init + " " + tap.BootArgs(s.cfg.DNS),
		Rootfs:      rootfs,
		TapName:     tap.Name,
		GuestMAC:    tap.GuestMAC,
		VsockUDS:    vsockUDS,
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

	agent, err := dialAgent(vsockUDS)
	if err != nil {
		return err
	}
	cleanups = append(cleanups, func(context.Context) { agent.Close() })
	hello, err := waitAgent(ctx, machine, guestv1.NewGuestAgentServiceClient(agent))
	if err != nil {
		return err
	}
	if hello.GetBrowserVersion() != img.Manifest.Browser.Version {
		// Guest-attested, so only a warning: the host's record (the image manifest) stands.
		r.log.Warn("guest reports a different browser than the image manifest",
			"guest", hello.GetBrowserVersion(), "manifest", img.Manifest.Browser.Version)
	}
	if err := r.send(daemonv1.RunState_RUN_STATE_NET_READY,
		fmt.Sprintf("guest agent up %d ms after start (Chrome %s, kernel %s)",
			time.Since(t0).Milliseconds(), hello.GetBrowserVersion(), hello.GetKernel())); err != nil {
		return err
	}

	d, err := s.dwellFor(ctx)
	if err != nil {
		return err
	}
	done, err := s.runGuest(ctx, r, guestv1.NewGuestAgentServiceClient(agent), u.String(), d, runDir)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("final %s after %s (%s)", done.GetFinalUrl(), done.GetDwell().AsDuration().Round(time.Millisecond), done.GetDwellReason())
	if e := done.GetNavigationError(); e != "" {
		msg = "navigation error: " + e
	}
	return r.send(daemonv1.RunState_RUN_STATE_COLLECTING, msg)
}

// collectMargin is the time kept back from the run's deadline for collecting artifacts.
const collectMargin = 8 * time.Second

// dwellFor fits the configured dwell into the time the run has left.
func (s *Server) dwellFor(ctx context.Context) (dwell, error) {
	d := dwell{min: s.cfg.MinDwell, max: s.cfg.MaxDwell, jitter: s.cfg.DwellJitter}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl) - collectMargin; left < d.max {
			d.max = left
		}
	}
	if d.max < d.min {
		return d, fmt.Errorf("not enough time left to observe for %s (raise the timeout)", d.min)
	}
	return d, nil
}

// dialAgent returns a gRPC connection to the guest agent over the VM's vsock socket.
// It connects lazily, so it can be created before the guest is up.
func dialAgent(uds string) (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///guest-agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return vm.DialVsock(ctx, uds, guestinfo.AgentPort)
		}),
		// The guest is expected within seconds: retry the dial quickly instead of gRPC's
		// default backoff, which grows to tens of seconds.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 50 * time.Millisecond, Multiplier: 1.3, MaxDelay: 250 * time.Millisecond},
			MinConnectTimeout: time.Second,
		}),
	)
}

// waitAgent calls Hello until the agent answers, the VM exits, or ctx ends.
func waitAgent(ctx context.Context, m *vm.Machine, c guestv1.GuestAgentServiceClient) (*guestv1.HelloResponse, error) {
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-m.Done():
			cancel()
		case <-hctx.Done():
		}
	}()
	hello, err := c.Hello(hctx, &guestv1.HelloRequest{}, grpc.WaitForReady(true))
	if err == nil {
		return hello, nil
	}
	select {
	case <-m.Done():
		return nil, errors.New("VM exited before the guest agent answered (see host/serial.log)")
	default:
	}
	return nil, fmt.Errorf("guest agent not reachable: %w", err)
}

func writeMeta(runDir string, m meta) {
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(runDir, "meta.json"), append(b, '\n'), 0o600)
}
