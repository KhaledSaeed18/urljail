// Command urljail-agent is the guest agent. It runs inside the microVM as an unprivileged user,
// started by urljail-init, and serves gRPC on vsock for the host (ADR 0007).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/guestinfo"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

type agent struct {
	guestv1.UnimplementedGuestAgentServiceServer
	log     *slog.Logger
	browser string
	kernel  string
	busy    atomic.Bool

	mu       sync.Mutex
	prepared *browserSession
}

func (a *agent) Hello(context.Context, *guestv1.HelloRequest) (*guestv1.HelloResponse, error) {
	random := make([]byte, 16)
	_, _ = unix.Getrandom(random, 0)
	a.mu.Lock()
	prepared := a.prepared != nil
	a.mu.Unlock()
	return &guestv1.HelloResponse{
		AgentVersion:   version.String(),
		BrowserVersion: a.browser,
		Kernel:         a.kernel,
		Uptime:         durationpb.New(guestinfo.Uptime()),
		Time:           timestamppb.Now(),
		Random:         random,
		Prepared:       prepared,
	}, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil)).With("component", "agent")
	l, err := vsock.Listen(guestinfo.AgentPort, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "urljail-agent: vsock listen:", err)
		os.Exit(1)
	}
	a := &agent{log: log, browser: guestinfo.PackageVersion(guestinfo.ChromePackage), kernel: guestinfo.Kernel()}
	gs := grpc.NewServer()
	guestv1.RegisterGuestAgentServiceServer(gs, a)
	log.Info("listening", "vsock_port", guestinfo.AgentPort, "browser", a.browser, "uid", os.Getuid())
	if err := gs.Serve(l); err != nil {
		fmt.Fprintln(os.Stderr, "urljail-agent:", err)
		os.Exit(1)
	}
}
