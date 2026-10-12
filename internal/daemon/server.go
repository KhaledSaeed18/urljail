// Package daemon implements urljaild's gRPC service.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/hostnet"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

// Config is the daemon's runtime configuration.
type Config struct {
	Policy         policy.Policy
	RunsDir        string
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration

	// VM settings.
	Firecracker string // binary path
	Kernel      string
	Rootfs      string // read-only base image; each run gets a reflinked copy
	SocketDir   string // Firecracker API sockets (short paths: Unix sockets are limited to 108 bytes)
	WorkDir     string // per-run scratch (disk clones), deleted at teardown
	MaxVMs      int
	VCPUs       int
	MemMiB      int

	// Pinned component versions, reported by Version and recorded per run.
	FirecrackerVersion string
	GuestKernel        string
	RootfsName         string
}

// Server implements daemonv1.DaemonServiceServer.
type Server struct {
	daemonv1.UnimplementedDaemonServiceServer
	cfg    Config
	log    *slog.Logger
	egress *hostnet.Egress // nil: no VM lifecycle (tests of the API only)
	slots  *slots
	active sync.WaitGroup // running detonations, so shutdown can wait for their teardown
}

// Wait blocks until every running detonation has finished its teardown.
func (s *Server) Wait() { s.active.Wait() }

// New returns a Server. With a nil egress, Detonate stops after preflight.
func New(cfg Config, egress *hostnet.Egress, log *slog.Logger) *Server {
	n := cfg.MaxVMs
	if n < 1 {
		n = 1
	}
	return &Server{cfg: cfg, log: log, egress: egress, slots: newSlots(n)}
}

// Version implements DaemonService.Version.
func (s *Server) Version(context.Context, *daemonv1.VersionRequest) (*daemonv1.VersionResponse, error) {
	return &daemonv1.VersionResponse{
		Urljail:     version.String(),
		Firecracker: s.cfg.FirecrackerVersion,
		GuestKernel: s.cfg.GuestKernel,
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
	if s.egress == nil {
		return r.fail(errors.New("daemon has no VM backend configured"))
	}

	if err := s.detonate(stream.Context(), r, u, req.GetProfile(), timeout); err != nil {
		return r.fail(err)
	}
	return r.done(filepath.Join(s.cfg.RunsDir, r.id))
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
	stream daemonv1.DaemonService_DetonateServer
	log    *slog.Logger
}

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
func (r *run) fail(err error) error {
	r.log.Warn("run failed", "err", err)
	return r.stream.Send(&daemonv1.DetonateResponse{
		RunId: r.id,
		State: daemonv1.RunState_RUN_STATE_FAILED,
		Time:  timestamppb.Now(),
		Error: err.Error(),
	})
}
