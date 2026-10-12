package netns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// EgressConfig configures the egress namespace.
type EgressConfig struct {
	// Upstream DNS servers the resolver forwards to, through the exit.
	Upstreams []string
	// StateDir holds the resolver's configuration (root-owned).
	StateDir string
	// WG makes the egress live: WireGuard is the only exit, and the resolver forwards to the
	// VPN's DNS (Upstreams is ignored). Nil: the dev exit through the host.
	WG *WGConfig
	// TestVPN builds a local WireGuard peer and uses it as the exit (live-test mode).
	TestVPN bool
}

// Egress is the running egress namespace.
type Egress struct {
	log       *slog.Logger
	rulesHash string
	resolver  *Resolver
	blocked   *blockLog
	stopLogs  context.CancelFunc

	mu       sync.Mutex
	vmHashes map[int]string

	exit       string // the only interface with a route out: exitVeth (dev) or WGDev (live)
	firewalld  bool
	zone       string
	addedMasq  bool
	dockerUser bool
	hostIfaces []string // host-side interfaces given a way out (hostExitUp)
}

// Live reports whether the exit is WireGuard.
func (e *Egress) Live() bool { return e.exit == WGDev }

// Up removes any leftover urljail namespaces, then builds the egress namespace with its
// dev-mode exit, loads its ruleset and starts the resolver. Close undoes all of it.
func Up(ctx context.Context, cfg EgressConfig, log *slog.Logger) (*Egress, error) {
	if err := DeleteAll(ctx, log); err != nil {
		return nil, err
	}
	e := &Egress{log: log, vmHashes: map[int]string{}}
	ok := false
	defer func() {
		if !ok {
			e.Close(context.WithoutCancel(ctx))
		}
	}()

	for _, s := range [][]string{{"netns", "add", EgressNS}, {"-n", EgressNS, "link", "set", "lo", "up"}} {
		if err := ip(ctx, s...); err != nil {
			return nil, err
		}
	}
	if err := sysctls(ctx, EgressNS, "net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"); err != nil {
		return nil, err
	}
	exitDesc := "dev (host NAT)"
	if cfg.TestVPN {
		wg, err := e.startTestVPN(ctx)
		if err != nil {
			return nil, err
		}
		cfg.WG = wg
	}
	if cfg.WG != nil {
		// Live: WireGuard is the only route out. There is no link to the host at all, so with
		// the tunnel down there is no route (fail closed, ADR 0003).
		if err := wireguardUp(ctx, cfg.WG); err != nil {
			return nil, err
		}
		e.exit = WGDev
		cfg.Upstreams = nil
		for _, d := range cfg.WG.DNS {
			cfg.Upstreams = append(cfg.Upstreams, d.String())
		}
		exitDesc = "WireGuard to " + cfg.WG.Endpoint.String()
		if cfg.TestVPN {
			exitDesc += " (local test peer)"
		}
	} else {
		for _, s := range [][]string{
			{"link", "add", hostVeth, "type", "veth", "peer", "name", exitVeth, "netns", EgressNS},
			{"addr", "add", hostSideIP + "/30", "dev", hostVeth},
			{"link", "set", hostVeth, "up"},
			{"-n", EgressNS, "addr", "add", exitIP + "/30", "dev", exitVeth},
			{"-n", EgressNS, "link", "set", exitVeth, "up"},
			{"-n", EgressNS, "route", "add", "default", "via", hostSideIP},
		} {
			if err := ip(ctx, s...); err != nil {
				return nil, err
			}
		}
		e.exit = exitVeth
		if err := e.hostExitUp(ctx, hostVeth); err != nil {
			return nil, err
		}
	}

	mtu, err := linkMTU(ctx, EgressNS, e.exit)
	if err != nil {
		return nil, err
	}
	hash, err := loadRules(ctx, EgressNS, egressRules, struct {
		Exit      string
		LogGroup  int
		Upstreams []string
		MSS       int
	}{e.exit, LogGroup, cfg.Upstreams, mtu - 40}) // IPv4 + TCP headers
	if err != nil {
		return nil, err
	}
	e.rulesHash = hash

	if e.resolver, err = startResolver(ctx, EgressNS, cfg, log); err != nil {
		return nil, err
	}
	logCtx, stopLogs := context.WithCancel(context.WithoutCancel(ctx))
	e.stopLogs = stopLogs
	if e.blocked, err = startBlockLog(logCtx, e); err != nil {
		return nil, err
	}
	ok = true
	log.Info("egress namespace up", "exit", exitDesc, "rules_sha256", hash[:12], "upstreams", cfg.Upstreams)
	return e, nil
}

// Resolver is the egress namespace's DNS resolver.
func (e *Egress) Resolver() *Resolver { return e.resolver }

// Close stops the resolver and removes the egress namespace and the host-side exit.
func (e *Egress) Close(ctx context.Context) {
	if e.resolver != nil {
		e.resolver.stop()
	}
	if e.stopLogs != nil {
		e.stopLogs()
	}
	if e.blocked != nil {
		e.blocked.nf.Close()
	}
	e.hostExitDown(ctx)
	_ = deleteNS(ctx, TestVPNNS)
	if err := deleteNS(ctx, EgressNS); err != nil && !strings.Contains(err.Error(), "No such file") {
		e.log.Warn("deleting egress namespace", "err", err)
	}
	e.log.Info("egress namespace down")
}

// Verify is the preflight check: every ruleset is still exactly what was loaded, and the
// resolver is running. Any difference refuses the run: fail closed.
func (e *Egress) Verify(ctx context.Context, slot int) error {
	if h, err := rulesHash(ctx, EgressNS); err != nil || h != e.rulesHash {
		return fmt.Errorf("egress ruleset changed or unreadable (want %.12s, got %.12s, %v)", e.rulesHash, h, err)
	}
	if !e.resolver.alive() {
		return errors.New("resolver is not running")
	}
	// Live: the tunnel must be alive. With PersistentKeepalive the handshake renews about every
	// two minutes; older than three means the VPN isn't answering.
	if e.Live() {
		t, err := e.Handshake()
		if err != nil || time.Since(t) > MaxHandshakeAge {
			return fmt.Errorf("WireGuard tunnel not healthy (last handshake %s ago, %v)", time.Since(t).Round(time.Second), err)
		}
	}
	// The only default route goes out of the exit.
	if out, err := in(ctx, EgressNS, "ip", "-4", "route", "show", "default"); err != nil || len(strings.Fields(out)) == 0 ||
		!strings.Contains(" "+out+" ", " dev "+e.exit+" ") || strings.Count(out, "\n") > 0 {
		return fmt.Errorf("egress default route isn't exactly one via %s: %q", e.exit, out)
	}
	return nil
}

// DeleteAll removes every urljail namespace, e.g. after a crashed daemon. Deleting a
// namespace destroys the TAP and veths inside it, and their peers.
func DeleteAll(ctx context.Context, log *slog.Logger) error {
	names, err := namespaces(ctx)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == EgressNS || n == TestVPNNS || strings.HasPrefix(n, VMPrefix) {
			log.Warn("removing leftover namespace", "netns", n, "killed", killAll(ctx, n))
			if err := ip(ctx, "netns", "del", n); err != nil {
				return err
			}
		}
	}
	for _, l := range []string{hostVeth, testVPNHost, WGDev} {
		if exec.CommandContext(ctx, "ip", "link", "show", l).Run() == nil {
			if err := ip(ctx, "link", "del", l); err != nil {
				return err
			}
		}
	}
	return nil
}
