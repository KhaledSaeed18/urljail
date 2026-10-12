// Command urljaild is urljail's host agent: it owns every privileged operation and serves the
// gRPC API on a Unix socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/daemon"
	"github.com/KhaledSaeed18/urljail/internal/hostnet"
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
	defFC, _ := exec.LookPath("firecracker")

	socket := flag.String("socket", defSock, "gRPC Unix socket path")
	egress := flag.String("egress", "dev", "egress mode: off, dev or live")
	allow := flag.String("allow", strings.Join(policy.DefaultDevAllowlist, ","), "dev mode allowlist (comma-separated domains)")
	runsDir := flag.String("runs-dir", filepath.Join(dataDir, "runs"), "where run directories are written")
	image := flag.String("image", filepath.Join(dataDir, "images", "default"), "guest image directory (vmlinux + rootfs.ext4)")
	firecracker := flag.String("firecracker", defFC, "firecracker binary")
	maxVMs := flag.Int("max-vms", 2, "concurrent VMs (RAM is the limit on this laptop)")
	vcpus := flag.Int("vcpus", 2, "vCPUs per VM")
	mem := flag.Int("mem", 1024, "guest memory per VM, MiB")
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

	cfg := daemon.Config{
		Policy:         policy.Policy{Mode: mode, Allowlist: splitList(*allow)},
		RunsDir:        *runsDir,
		DefaultTimeout: *defTimeout,
		MaxTimeout:     *maxTimeout,
		Firecracker:    *firecracker,
		Kernel:         filepath.Join(*image, "vmlinux"),
		Rootfs:         filepath.Join(*image, "rootfs.ext4"),
		SocketDir:      filepath.Join(filepath.Dir(*socket), "vm"),
		WorkDir:        filepath.Join(dataDir, "work"),
		MaxVMs:         *maxVMs,
		VCPUs:          *vcpus,
		MemMiB:         *mem,
	}
	if err := describe(&cfg); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var eg *hostnet.Egress
	if mode == policy.EgressDev {
		if eg, err = hostnet.Up(ctx, log); err != nil {
			return fmt.Errorf("dev egress: %w", err)
		}
		defer eg.Close(context.Background())
	}
	daemon.Reap(ctx, cfg, eg, log)

	srv := daemon.New(cfg, eg, log)
	l, err := daemon.Listen(*socket)
	if err != nil {
		return err
	}
	defer os.Remove(*socket)

	gs := grpc.NewServer()
	daemonv1.RegisterDaemonServiceServer(gs, srv)
	go func() {
		<-ctx.Done()
		// Stop cancels running detonations; each one still runs its teardown.
		log.Info("shutting down: cancelling runs")
		gs.Stop()
	}()

	log.Info("urljaild listening", "version", version.String(), "socket", *socket, "egress", mode,
		"firecracker", cfg.FirecrackerVersion, "kernel", cfg.GuestKernel, "rootfs", cfg.RootfsName)
	err = gs.Serve(l)
	srv.Wait()
	return err
}

// describe checks the VM inputs exist and fills in their versions.
func describe(cfg *daemon.Config) error {
	if cfg.Firecracker == "" {
		return fmt.Errorf("firecracker not found in PATH; pass -firecracker")
	}
	out, err := exec.Command(cfg.Firecracker, "--version").Output()
	if err != nil {
		return fmt.Errorf("%s --version: %w", cfg.Firecracker, err)
	}
	cfg.FirecrackerVersion = strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "Firecracker ")

	kernel, err := filepath.EvalSymlinks(cfg.Kernel)
	if err != nil {
		return fmt.Errorf("guest kernel: %w", err)
	}
	rootfs, err := filepath.EvalSymlinks(cfg.Rootfs)
	if err != nil {
		return fmt.Errorf("guest rootfs: %w", err)
	}
	image, err := filepath.EvalSymlinks(filepath.Dir(cfg.Rootfs))
	if err != nil {
		return err
	}
	cfg.Kernel, cfg.Rootfs = kernel, rootfs
	cfg.GuestKernel = filepath.Base(kernel)
	cfg.RootfsName = filepath.Base(image)
	return nil
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
