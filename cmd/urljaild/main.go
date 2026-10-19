// Command urljaild is urljail's host agent: the only privileged component (ADR 0005, ADR 0014).
// It runs as root, builds the network namespaces, and starts each Firecracker VMM inside its
// VM's namespace as the operator. The gRPC socket belongs to the operator, so the CLI needs no
// privileges.
package main

import (
	"context"
	"errors"
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
	"github.com/KhaledSaeed18/urljail/internal/image"
	"github.com/KhaledSaeed18/urljail/internal/netns"
	"github.com/KhaledSaeed18/urljail/internal/operator"
	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

// exitInterlock is the exit status when the live interlock refuses to serve. The systemd unit
// doesn't restart on it: retrying a failed safety check every few seconds helps nobody.
const exitInterlock = 3

type interlockError struct{ error }

func main() {
	// The unprivileged report builder (internal/daemon/reporthelper.go), before anything else.
	if len(os.Args) == 3 && os.Args[1] == daemon.ReportHelperArg {
		if err := daemon.RunReportHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "urljaild report helper:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "urljaild:", err)
		var ie interlockError
		if errors.As(err, &ie) {
			os.Exit(exitInterlock)
		}
		os.Exit(1)
	}
}

func run() error {
	opName := flag.String("operator", "", "user to work for (default: the user who ran sudo)")
	socket := flag.String("socket", paths.Socket(), "gRPC Unix socket path")
	egress := flag.String("egress", "dev", "egress mode: off, dev or live")
	allow := flag.String("allow", strings.Join(policy.DefaultDevAllowlist, ","), "dev mode allowlist (comma-separated domains)")
	upstreams := flag.String("dns-upstream", "1.1.1.1,9.9.9.9", "DNS servers the resolver forwards to, through the exit (dev mode; live uses the VPN's DNS)")
	wgConfig := flag.String("wg-config", "", "WireGuard config (wg-quick format) for live mode, readable by root only")
	runsDir := flag.String("runs-dir", "", "where run directories are written (default ~operator/.local/share/urljail/runs)")
	imageDir := flag.String("image", "", "guest image directory (default ~operator/.local/share/urljail/images/default)")
	firecracker := flag.String("firecracker", "", "firecracker binary (default ~operator/.local/bin/firecracker)")
	jailer := flag.String("jailer", "", "jailer binary (default ~operator/.local/bin/jailer)")
	selinuxModule := flag.String("selinux-module", "", "SELinux policy module (default: selinux/urljail.pp next to bin/)")
	maxVMs := flag.Int("max-vms", 3, "concurrent VMs (snapshot clones share memory: ~125 MiB each here)")
	confineResolver := flag.Bool("confine-resolver", true, "run unbound in SELinux's named_t when started by systemd (threat model)")
	exitTZ := flag.String("exit-timezone", "", "IANA time zone of the VPN exit (e.g. America/Chicago), used by the stealth profiles")
	vcpus := flag.Int("vcpus", 2, "vCPUs per VM")
	mem := flag.Int("mem", 1024, "guest memory per VM, MiB")
	defTimeout := flag.Duration("timeout", 30*time.Second, "default wall-clock limit per run")
	maxTimeout := flag.Duration("max-timeout", 5*time.Minute, "largest timeout a client may request")
	minDwell := flag.Duration("min-dwell", 3*time.Second, "minimum observation after navigation")
	maxDwell := flag.Duration("max-dwell", 15*time.Second, "maximum observation after navigation")
	jitter := flag.Duration("dwell-jitter", time.Second, "random extra minimum observation, up to this")
	useSnapshots := flag.Bool("snapshots", true, "restore runs from a snapshot (false: cold boot every run)")
	snapMaxAge := flag.Duration("snapshot-max-age", 24*time.Hour, "rebuild snapshots older than this, at startup and when idle (0: never); a restore moves the guest clock across the snapshot's age")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *exitTZ != "" {
		if _, err := time.LoadLocation(*exitTZ); err != nil || strings.ContainsAny(*exitTZ, " .") {
			return fmt.Errorf("-exit-timezone %q: not an IANA time zone", *exitTZ)
		}
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (sudo); the CLI doesn't need to")
	}
	// One daemon per host, decided before anything is touched: setup deletes and rebuilds the
	// namespaces, so a second daemon that got that far would break the first one's network
	// (found when the service started next to a dev daemon).
	unlock, err := singleInstance()
	if err != nil {
		return err
	}
	defer unlock()
	// VMs live in the service's own cgroup when systemd delegated it, so they can't outlive
	// the daemon. First thing after the lock: the daemon must move into its leaf before it
	// starts any child (unbound, tcpdump), or the service cgroup isn't empty and enabling its
	// controllers fails with EBUSY (found on the first delegated start).
	cgroupParent, err := daemon.ServiceCgroup()
	if err != nil {
		return err
	}
	op, err := operatorFrom(*opName)
	if err != nil {
		return err
	}
	dataDir := paths.DataDir(op.Home)
	orDefault := func(v *string, def string) {
		if *v == "" {
			*v = def
		}
	}
	orDefault(runsDir, filepath.Join(dataDir, "runs"))
	orDefault(imageDir, filepath.Join(dataDir, "images", "default"))
	orDefault(firecracker, filepath.Join(op.Home, ".local", "bin", "firecracker"))
	orDefault(jailer, filepath.Join(op.Home, ".local", "bin", "jailer"))
	// The jailer names jail directories after the exec file and copies it in; use the real file.
	if p, err := filepath.EvalSymlinks(*firecracker); err == nil {
		*firecracker = p
	}

	mode, err := policy.ParseEgressMode(*egress)
	if err != nil {
		return err
	}
	// The live interlock (docs/roadmap.md#live-gate-before-p6): live mode needs the dev sudo
	// rule gone and a WireGuard config; the daemon then won't serve until the tunnel has a
	// handshake and its own isolation self-test passes, live checks included.
	var wg *netns.WGConfig
	if mode == policy.EgressLive {
		if _, err := os.Stat(daemon.DevSudoersRule); err == nil {
			return interlockError{fmt.Errorf("live mode refused: %s still exists (the live gate requires removing it)", daemon.DevSudoersRule)}
		}
		if *wgConfig == "" {
			return fmt.Errorf("live mode needs -wg-config")
		}
		if fi, err := os.Stat(*wgConfig); err != nil {
			return err
		} else if fi.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s holds a private key: make it readable by root only (chmod 600)", *wgConfig)
		}
		if wg, err = netns.ParseWGQuick(*wgConfig); err != nil {
			return err
		}
	}

	// /run/urljail is root's; the VM socket directory is the operator's, because Firecracker
	// runs as the operator and creates its sockets there.
	if err := os.MkdirAll(paths.RunDir, 0o755); err != nil {
		return err
	}
	socketDir := filepath.Join(paths.RunDir, "vm")
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return err
	}
	if err := op.Chown(socketDir); err != nil {
		return err
	}

	cfg := daemon.Config{
		CgroupParent:   cgroupParent,
		Policy:         policy.Policy{Mode: mode, Allowlist: splitList(*allow)},
		RunsDir:        *runsDir,
		DefaultTimeout: *defTimeout,
		MaxTimeout:     *maxTimeout,
		MinDwell:       *minDwell,
		MaxDwell:       *maxDwell,
		DwellJitter:    *jitter,
		Firecracker:    *firecracker,
		Jailer:         *jailer,
		JailDir:        filepath.Join(dataDir, "jail"),
		DataDir:        dataDir,
		Started:        time.Now(),
		Operator:       op,
		SocketDir:      socketDir,
		WorkDir:        filepath.Join(dataDir, "work"),
		SnapshotsDir:   filepath.Join(dataDir, "snapshots"),
		SnapshotMaxAge: *snapMaxAge,
		MaxVMs:         *maxVMs,
		ExitTimezone:   *exitTZ,
		VCPUs:          *vcpus,
		MemMiB:         *mem,
	}
	if cfg.Image, err = image.Load(*imageDir); err != nil {
		return err
	}
	if err := firecrackerVersion(&cfg); err != nil {
		return err
	}
	if err := op.MkdirAll(cfg.RunsDir, 0o700); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		<-sigs
		stop()
		<-sigs // a second signal: don't wait for teardowns; the next start reaps what's left
		log.Warn("second signal: exiting without waiting for teardown")
		os.Exit(1)
	}()

	// SELinux: confine the VMMs in urljail_vmm_t and the resolver in named_t. Fail closed if
	// SELinux is on but the module can't be loaded. Before the egress namespace: the module
	// carries the resolver's transition.
	if daemon.SELinuxEnabled() {
		if *selinuxModule == "" {
			exe, _ := os.Executable()
			*selinuxModule = filepath.Join(filepath.Dir(filepath.Dir(exe)), "selinux", "urljail.pp")
		}
		installed, err := daemon.EnsurePolicy(*selinuxModule)
		if err != nil {
			return err
		}
		if installed {
			log.Info("SELinux policy module installed", "module", *selinuxModule)
		}
		if err := daemon.Relabel(filepath.Join(dataDir, "jail"), filepath.Join(dataDir, "ci"),
			filepath.Join(dataDir, "images"), filepath.Join(dataDir, "snapshots"), filepath.Join(dataDir, "runs")); err != nil {
			return err
		}
		cfg.SELinuxModule = *selinuxModule
	}
	daemon.Reap(ctx, cfg, log)
	var eg *netns.Egress
	if mode != policy.EgressOff {
		if eg, err = netns.Up(ctx, netns.EgressConfig{
			Upstreams:      splitList(*upstreams),
			StateDir:       filepath.Join(paths.RunDir, "unbound"),
			ResolverDomain: resolverDomain(cfg.SELinuxModule != "" && *confineResolver),
			Relabel:        daemon.Relabel,
			WG:             wg,
			TestVPN:        mode == policy.EgressLiveTest,
		}, log); err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		defer eg.Close(context.Background())
		if eg.Live() {
			hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := eg.WaitHandshake(hctx, time.Time{})
			cancel()
			if err != nil {
				return interlockError{fmt.Errorf("live interlock: %w", err)}
			}
			log.Info("WireGuard tunnel up")
		}
	}
	if err := daemon.SetupJails(cfg); err != nil {
		return err
	}

	srv := daemon.New(cfg, eg, log)
	srv.RecoverRuns(ctx) // runs a crash or SIGKILL left root-owned, without status or report
	if *useSnapshots && eg != nil {
		if err := op.MkdirAll(cfg.SnapshotsDir, 0o700); err != nil {
			return err
		}
		if err := srv.EnsureSnapshots(ctx); err != nil {
			return err
		}
	}
	if eg != nil && eg.Live() {
		res, err := srv.SelfTest(ctx, &daemonv1.SelfTestRequest{})
		if err != nil {
			return interlockError{fmt.Errorf("live interlock: self-test: %w", err)}
		}
		for _, c := range res.GetChecks() {
			log.Info("self-test", "check", c.GetName(), "result", c.GetResult(), "observed", c.GetObserved())
		}
		if !res.GetPassed() && !(mode == policy.EgressLiveTest && !hasFail(res)) {
			return interlockError{fmt.Errorf("live interlock: the isolation self-test failed (details in %s)", filepath.Join(res.GetRunDir(), "selftest.json"))}
		}
		log.Info("live interlock passed", "mode", mode)
	}
	l, err := daemon.Listen(*socket)
	if err != nil {
		return err
	}
	defer os.Remove(*socket)
	if err := op.Chown(*socket); err != nil {
		return err
	}

	gs := grpc.NewServer()
	daemonv1.RegisterDaemonServiceServer(gs, srv)
	go func() {
		<-ctx.Done()
		// Stop cancels running detonations; each one still runs its teardown.
		log.Info("shutting down: cancelling runs")
		gs.Stop()
	}()

	if *useSnapshots && eg != nil {
		go srv.RefreshSnapshots(ctx)
	}
	log.Info("urljaild listening", "version", version.String(), "socket", *socket, "egress", mode,
		"operator", op.Name, "firecracker", cfg.FirecrackerVersion, "image", cfg.Image.Manifest.Name)
	err = gs.Serve(l)
	if !srv.Wait(30 * time.Second) {
		log.Warn("teardowns still running after 30s; exiting, the next start reaps what's left")
	}
	return err
}

func operatorFrom(name string) (operator.Operator, error) {
	if name != "" {
		return operator.Lookup(name)
	}
	return operator.FromSudo()
}

// firecrackerVersion checks the firecracker binary runs and records its version.
func firecrackerVersion(cfg *daemon.Config) error {
	out, err := exec.Command(cfg.Firecracker, "--version").Output()
	if err != nil {
		return fmt.Errorf("%s --version: %w", cfg.Firecracker, err)
	}
	cfg.FirecrackerVersion = strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "Firecracker ")
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

func hasFail(res *daemonv1.SelfTestResponse) bool {
	for _, c := range res.GetChecks() {
		if c.GetResult() == "fail" {
			return true
		}
	}
	return false
}

// singleInstance holds an exclusive lock on /run/urljail/urljaild.lock for the daemon's lifetime.
func singleInstance() (func(), error) {
	if err := os.MkdirAll(paths.RunDir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(paths.RunDir, "urljaild.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another urljaild is running (lock %s held)", f.Name())
	}
	return func() { f.Close() }, nil
}

// resolverDomain is the SELinux domain unbound runs in: named_t, Fedora's own domain for it,
// when the daemon runs as a systemd service (unconfined_service_t, whose role may enter it).
// Development runs (sudo, unconfined_t) and SELinux off: "" (not confined).
func resolverDomain(want bool) string {
	if want && daemon.CurrentDomain() == "unconfined_service_t" {
		return "named_t"
	}
	return ""
}
