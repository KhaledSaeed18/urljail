// Package daemon implements urljaild's gRPC service.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/image"
	"github.com/KhaledSaeed18/urljail/internal/netns"
	"github.com/KhaledSaeed18/urljail/internal/operator"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/report"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

// Config is the daemon's runtime configuration.
type Config struct {
	Policy         policy.Policy
	RunsDir        string
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration

	// Observation per run (open question Q11): at least MinDwell plus up to DwellJitter, then
	// until the network is idle, MaxDwell at most.
	MinDwell    time.Duration
	MaxDwell    time.Duration
	DwellJitter time.Duration

	// VM settings.
	Firecracker string            // binary path
	Image       *image.Image      // read-only base; each run gets a reflinked copy of its rootfs
	Operator    operator.Operator // owns run directories and runs the VMMs
	SocketDir   string            // Firecracker API sockets (short paths: Unix sockets are limited to 108 bytes)
	WorkDir     string            // per-run scratch (disk clones), deleted at teardown
	MaxVMs      int
	VCPUs       int
	MemMiB      int

	// Pinned component versions, reported by Version and recorded per run.
	FirecrackerVersion string
}

// Server implements daemonv1.DaemonServiceServer.
type Server struct {
	daemonv1.UnimplementedDaemonServiceServer
	cfg    Config
	log    *slog.Logger
	net    *netns.Egress // nil: no VM lifecycle (tests of the API only)
	slots  *slots
	active sync.WaitGroup // running detonations, so shutdown can wait for their teardown
}

// Wait blocks until every running detonation has finished its teardown.
func (s *Server) Wait() { s.active.Wait() }

// New returns a Server. With a nil egress, Detonate stops after preflight.
func New(cfg Config, egress *netns.Egress, log *slog.Logger) *Server {
	n := cfg.MaxVMs
	if n < 1 {
		n = 1
	}
	return &Server{cfg: cfg, log: log, net: egress, slots: newSlots(n)}
}

func (s *Server) guestKernel() string {
	if s.cfg.Image == nil {
		return ""
	}
	return s.cfg.Image.Manifest.Kernel.Name
}

// Version implements DaemonService.Version.
func (s *Server) Version(context.Context, *daemonv1.VersionRequest) (*daemonv1.VersionResponse, error) {
	return &daemonv1.VersionResponse{
		Urljail:     version.String(),
		Firecracker: s.cfg.FirecrackerVersion,
		GuestKernel: s.guestKernel(),
		EgressMode:  string(s.cfg.Policy.Mode),
	}, nil
}

// Detonate implements DaemonService.Detonate.
func (s *Server) Detonate(req *daemonv1.DetonateRequest, stream daemonv1.DaemonService_DetonateServer) error {
	s.active.Add(1)
	defer s.active.Done()

	id, err := uuid.NewV7()
	if err != nil {
		return status.Errorf(codes.Internal, "run id: %v", err)
	}
	r := &run{id: id.String(), stream: stream, log: s.log.With("run", id.String())}

	if err := r.send(daemonv1.RunState_RUN_STATE_REQUESTED, req.GetUrl()); err != nil {
		return err
	}
	if err := r.send(daemonv1.RunState_RUN_STATE_PREFLIGHT, "checking URL against egress policy"); err != nil {
		return err
	}
	u, err := s.cfg.Policy.Check(req.GetUrl())
	if err != nil {
		return r.fail(err)
	}
	timeout, err := s.timeout(req)
	if err != nil {
		return r.fail(err)
	}
	if s.net == nil {
		return r.fail(errors.New("daemon has no VM backend configured"))
	}

	runDir := filepath.Join(s.cfg.RunsDir, r.id)
	err = s.detonate(stream.Context(), r, u, req.GetProfile(), timeout)
	// Every run that got a run directory gets a report, failed ones included: its gaps
	// say what couldn't be observed.
	if _, statErr := os.Stat(filepath.Join(runDir, "meta.json")); statErr == nil {
		if _, rerr := report.Write(runDir); rerr != nil {
			r.log.Warn("writing report", "err", rerr)
		}
		if cerr := s.cfg.Operator.ChownTree(runDir); cerr != nil {
			r.log.Warn("giving the run directory to the operator", "err", cerr)
		}
	} else {
		runDir = ""
	}
	if err != nil {
		return r.failIn(runDir, err)
	}
	return r.done(runDir)
}

func (s *Server) timeout(req *daemonv1.DetonateRequest) (time.Duration, error) {
	if req.GetTimeout() == nil {
		return s.cfg.DefaultTimeout, nil
	}
	d := req.GetTimeout().AsDuration()
	if d <= 0 || d > s.cfg.MaxTimeout {
		return 0, fmt.Errorf("%w: timeout %s outside (0, %s]", policy.ErrRefused, d, s.cfg.MaxTimeout)
	}
	return d, nil
}

// run sends one detonation's progress to the client.
type run struct {
	id     string
	stream progressSender
	log    *slog.Logger
}

type progressSender interface {
	Send(*daemonv1.DetonateResponse) error
}

// noProgress is the sender for runs nobody streams (the self-test).
type noProgress struct{}

func (noProgress) Send(*daemonv1.DetonateResponse) error { return nil }

func (r *run) send(state daemonv1.RunState, msg string) error {
	r.log.Info("state", "state", state.String(), "msg", msg)
	return r.stream.Send(&daemonv1.DetonateResponse{
		RunId:   r.id,
		State:   state,
		Time:    timestamppb.Now(),
		Message: msg,
	})
}

func (r *run) done(runDir string) error {
	r.log.Info("run done", "dir", runDir)
	return r.stream.Send(&daemonv1.DetonateResponse{
		RunId:  r.id,
		State:  daemonv1.RunState_RUN_STATE_DONE,
		Time:   timestamppb.Now(),
		RunDir: runDir,
	})
}

// fail reports a terminal failure. The RPC itself succeeds: the outcome is in the stream.
func (r *run) fail(err error) error { return r.failIn("", err) }

// failIn reports a failure of a run that has a run directory with its evidence.
func (r *run) failIn(runDir string, err error) error {
	r.log.Warn("run failed", "err", err)
	return r.stream.Send(&daemonv1.DetonateResponse{
		RunId:  r.id,
		State:  daemonv1.RunState_RUN_STATE_FAILED,
		Time:   timestamppb.Now(),
		Error:  err.Error(),
		RunDir: runDir,
	})
}
