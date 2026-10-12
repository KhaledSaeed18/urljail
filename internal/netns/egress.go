package netns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// EgressConfig configures the egress namespace.
type EgressConfig struct {
	// Upstream DNS servers the resolver forwards to, through the exit.
	Upstreams []string
	// StateDir holds the resolver's configuration (root-owned).
	StateDir string
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

	firewalld  bool
	zone       string
	addedMasq  bool
	dockerUser bool
}

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

	steps := [][]string{
		{"netns", "add", EgressNS},
		{"-n", EgressNS, "link", "set", "lo", "up"},
		{"link", "add", hostVeth, "type", "veth", "peer", "name", exitVeth, "netns", EgressNS},
		{"addr", "add", hostSideIP + "/30", "dev", hostVeth},
		{"link", "set", hostVeth, "up"},
		{"-n", EgressNS, "addr", "add", exitIP + "/30", "dev", exitVeth},
		{"-n", EgressNS, "link", "set", exitVeth, "up"},
		{"-n", EgressNS, "route", "add", "default", "via", hostSideIP},
	}
	for _, s := range steps {
		if err := ip(ctx, s...); err != nil {
			return nil, err
		}
	}
	if err := sysctls(ctx, EgressNS, "net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"); err != nil {
		return nil, err
	}
	if err := e.hostExitUp(ctx); err != nil {
		return nil, err
	}

	hash, err := loadRules(ctx, EgressNS, egressRules, struct {
		Exit     string
		LogGroup int
	}{exitVeth, LogGroup})
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
	log.Info("egress namespace up", "exit", "dev (host NAT)", "rules_sha256", hash[:12], "upstreams", cfg.Upstreams)
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
		if n == EgressNS || strings.HasPrefix(n, VMPrefix) {
			log.Warn("removing leftover namespace", "netns", n, "killed", killAll(ctx, n))
			if err := ip(ctx, "netns", "del", n); err != nil {
				return err
			}
		}
	}
	if exec.CommandContext(ctx, "ip", "link", "show", hostVeth).Run() == nil {
		return ip(ctx, "link", "del", hostVeth)
	}
	return nil
}
