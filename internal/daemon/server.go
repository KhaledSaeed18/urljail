// Package daemon implements urljaild's gRPC service.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

// Config is the daemon's runtime configuration.
type Config struct {
	Policy         policy.Policy
	RunsDir        string
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration

	// Pinned component versions, reported by Version and recorded per run.
	FirecrackerVersion string
	GuestKernel        string
}

// Server implements daemonv1.DaemonServiceServer.
type Server struct {
	daemonv1.UnimplementedDaemonServiceServer
	cfg Config
	log *slog.Logger
}

// New returns a Server.
func New(cfg Config, log *slog.Logger) *Server {
	return &Server{cfg: cfg, log: log}
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
	if _, err := s.cfg.Policy.Check(req.GetUrl()); err != nil {
		return r.fail(err)
	}
	if _, err := s.timeout(req); err != nil {
		return r.fail(err)
	}

	return r.fail(errors.New("VM lifecycle not implemented yet (P2 milestone M2)"))
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
