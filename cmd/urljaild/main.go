// Command urljaild is urljail's host agent: it owns every privileged operation and serves the
// gRPC API on a Unix socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/daemon"
	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "urljaild:", err)
		os.Exit(1)
	}
}

func run() error {
	defSock, _ := paths.Socket()
	dataDir, err := paths.DataDir()
	if err != nil {
		return err
	}

	socket := flag.String("socket", defSock, "gRPC Unix socket path")
	egress := flag.String("egress", "dev", "egress mode: off, dev or live")
	allow := flag.String("allow", strings.Join(policy.DefaultDevAllowlist, ","), "dev mode allowlist (comma-separated domains)")
	runsDir := flag.String("runs-dir", filepath.Join(dataDir, "runs"), "where run directories are written")
	defTimeout := flag.Duration("timeout", 30*time.Second, "default wall-clock limit per run")
	maxTimeout := flag.Duration("max-timeout", 5*time.Minute, "largest timeout a client may request")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *socket == "" {
		return fmt.Errorf("no socket path: set XDG_RUNTIME_DIR or pass -socket")
	}
	mode, err := policy.ParseEgressMode(*egress)
	if err != nil {
		return err
	}
	if mode == policy.EgressLive {
		// The interlock: live egress needs the WireGuard netns and the live gate (docs/roadmap.md).
		return fmt.Errorf("egress mode live is not available before the live gate")
	}

	srv := daemon.New(daemon.Config{
		Policy:         policy.Policy{Mode: mode, Allowlist: splitList(*allow)},
		RunsDir:        *runsDir,
		DefaultTimeout: *defTimeout,
		MaxTimeout:     *maxTimeout,
	}, log)

	l, err := daemon.Listen(*socket)
	if err != nil {
		return err
	}
	defer os.Remove(*socket)

	gs := grpc.NewServer()
	daemonv1.RegisterDaemonServiceServer(gs, srv)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		done := make(chan struct{})
		go func() { gs.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			gs.Stop()
		}
	}()

	log.Info("urljaild listening", "version", version.String(), "socket", *socket, "egress", mode)
	return gs.Serve(l)
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
