package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/capture"
	"github.com/KhaledSaeed18/urljail/internal/guestinfo"
	"github.com/KhaledSaeed18/urljail/internal/netns"
	"github.com/KhaledSaeed18/urljail/internal/report"
	"github.com/KhaledSaeed18/urljail/internal/version"
	"github.com/KhaledSaeed18/urljail/internal/vm"
)

const (
	// maxHostRecords caps each host log (DNS replies, blocked packets) per run.
	maxHostRecords = 20000
	// maxPackets and maxPcapBytes cap the packet capture per run. Packets alone don't bound
	// size: with GSO one packet can be 64 KiB.
	maxPackets   = 500000
	maxPcapBytes = 256 << 20

	// shutdownGrace is how long the guest gets to shut down after Ctrl-Alt-Del before the VMM
	// is killed. A guest still booting ignores Ctrl-Alt-Del, and evidence is collected before
	// teardown, so there's nothing to wait for beyond a clean exit.
	shutdownGrace = 3 * time.Second
	// cleanupStepTimeout bounds each teardown step separately, so one slow step can't use up
	// the time the others need.
	cleanupStepTimeout = 10 * time.Second
)

// detonate runs the VM part of a detonation. It always tears down what it started.
func (s *Server) detonate(ctx context.Context, r *run, u *url.URL, profile string, timeout time.Duration) (err error) {
	img := s.cfg.Image
	slot, ok := s.slots.acquire()
	if !ok {
		return fmt.Errorf("all %d VM slots are busy", s.slots.size())
	}
	defer s.slots.release(slot)

	// Fail closed: the egress ruleset must be exactly what was loaded and the resolver running.
	if err := s.net.Verify(ctx, slot); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runDir := filepath.Join(s.cfg.RunsDir, r.id)
	if err := s.cfg.Operator.MkdirAll(filepath.Join(runDir, "host"), 0o700); err != nil {
		return err
	}
	m := report.Meta{
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
	_ = report.WriteMeta(runDir, m)
	defer func() {
		m.EndedAt = time.Now().UTC()
		r.mark("done")
		m.TimingsMs = r.timings()
		m.HostGaps = r.gapList()
		if m.Clone != nil { // teardown has run, so the serial log is complete
			b, _ := os.ReadFile(filepath.Join(runDir, "host", "serial.log"))
			m.Clone.VMGenIDReseed = bytes.Contains(b, []byte("crng reseeded due to virtual machine fork"))
		}
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
		_ = report.WriteMeta(runDir, m)
	}()

	// Teardown ignores cancellation of the run: a client disconnecting or the timeout firing
	// must still leave nothing behind. Each step gets its own fresh deadline.
	var cleanups []func(context.Context)
	defer func() {
		_ = r.send(daemonv1.RunState_RUN_STATE_TEARDOWN, "stopping VM, removing its namespace and disk")
		base := context.WithoutCancel(ctx)
		for i := len(cleanups) - 1; i >= 0; i-- {
			sctx, scancel := context.WithTimeout(base, cleanupStepTimeout)
			cleanups[i](sctx)
			scancel()
		}
	}()

	r.mark("preflight")
	if s.snap != nil {
		err = r.send(daemonv1.RunState_RUN_STATE_RESTORING, "restoring "+s.snap.manifest.Name)
	} else {
		err = r.send(daemonv1.RunState_RUN_STATE_BOOTING, "cold boot (no snapshot)")
	}
	if err != nil {
		return err
	}

	agent, clone, err := s.bootVM(ctx, r, slot, runDir, func(f func(context.Context)) { cleanups = append(cleanups, f) })
	if err != nil {
		return err
	}
	if clone != nil {
		m.Clone = clone
		m.Versions["snapshot"] = clone.Snapshot
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

// bootVM prepares slot's disk and namespace, starts the VM and waits for its guest agent.
// Everything it creates is registered with addCleanup, so the caller's teardown removes it.
func (s *Server) bootVM(ctx context.Context, r *run, slot int, runDir string, addCleanup func(func(context.Context))) (*grpc.ClientConn, *report.Clone, error) {
	img := s.cfg.Image
	op := s.cfg.Operator
	// Every VMM runs in a jail (P5); the VM's disk is created inside it.
	jail := s.jailFor(jailID(slot, r.id), slot, netns.VMNS(slot))
	if err := jail.Prepare(); err != nil {
		return nil, nil, err
	}
	addCleanup(func(context.Context) { _ = jail.Remove() }) // also if the VMM never started
	const rootfs, vsock = "rootfs.ext4", "v.sock"           // paths inside the jail
	base := img.Rootfs
	if s.snap != nil {
		base = s.snap.rootfs // the disk the snapshot's page cache expects
	}
	if err := vm.CloneFile(base, jail.Path(rootfs)); err != nil {
		return nil, nil, fmt.Errorf("cloning rootfs: %w", err)
	}
	if err := os.Chown(jail.Path(rootfs), jail.UID, jail.GID); err != nil {
		return nil, nil, err
	}
	r.mark("disk")

	netVM, err := s.net.AddVM(ctx, slot, jail.UID, jail.GID)
	if err != nil {
		return nil, nil, err
	}
	addCleanup(func(ctx context.Context) { s.net.RemoveVM(ctx, netVM) })
	if err := s.net.VerifyVM(ctx, netVM); err != nil {
		return nil, nil, fmt.Errorf("preflight: %w", err)
	}
	r.mark("netns")

	// Host-attested records: every DNS reply the resolver sends this VM, every packet of it
	// the egress ruleset drops, and a full packet capture of its TAP.
	client := netns.VMOutsideIP(slot)
	dns, err := newJSONLog(filepath.Join(runDir, "host", "dns.jsonl"), maxHostRecords)
	if err != nil {
		return nil, nil, err
	}
	s.net.Resolver().Attach(client, func(q netns.Query) { dns.write(q) })
	blocked, err := newJSONLog(filepath.Join(runDir, "host", "blocked.jsonl"), maxHostRecords)
	if err != nil {
		return nil, nil, err
	}
	s.net.AttachBlocked(client, func(b netns.Blocked) { blocked.write(b) })
	addCleanup(func(context.Context) {
		s.net.Resolver().Detach(client)
		s.net.DetachBlocked(client)
		if n := dns.close() + blocked.close(); n > 0 {
			r.log.Warn("host records over the limit were dropped", "count", n)
		}
	})
	probe, err := capture.Attach(netVM.NS, netns.TapName, r.log)
	if err != nil {
		return nil, nil, err
	}
	r.mark("ebpf")
	addCleanup(func(context.Context) {
		flows := probe.Close()
		fl, err := newJSONLog(filepath.Join(runDir, "host", "flows.jsonl"), maxHostRecords)
		if err != nil {
			r.log.Warn("writing flows", "err", err)
			return
		}
		for _, f := range flows {
			fl.write(f)
		}
		fl.close()
	})
	pcap := filepath.Join(runDir, "host", "capture.pcap")
	if err := op.Chown(filepath.Join(runDir, "host")); err != nil {
		return nil, nil, err
	}
	capture, err := netns.StartCapture(netVM, pcap, op.Name, maxPackets, maxPcapBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("packet capture: %w", err)
	}
	r.mark("capture")
	addCleanup(func(context.Context) {
		r.log.Info("capture stopped", "tcpdump", strings.Join(capture.Stop(), "; "))
		if capture.Truncated() {
			r.gap(fmt.Sprintf("The packet capture was stopped at its %d MiB cap: later traffic isn't in host/capture.pcap (flows, DNS and blocked records still cover it)", maxPcapBytes>>20))
		}
		_ = os.Chmod(pcap, 0o600) // tcpdump creates it 0644; runs are private
	})

	vmCfg := vm.Config{
		Jail:     jail,
		LogDir:   filepath.Join(runDir, "host"),
		Kernel:   img.Kernel,
		BootArgs: s.bootArgs(),
		Rootfs:   rootfs,
		TapName:  netns.TapName,
		GuestMAC: netns.GuestMAC,
		VsockUDS: vsock,
		VCPUs:    s.cfg.VCPUs,
		MemMiB:   s.cfg.MemMiB,
		NetRx:    netRxLimit,
		NetTx:    netTxLimit,
		Disk:     diskLimit,
	}
	t0 := time.Now()
	var machine *vm.Machine
	if s.snap != nil {
		machine, err = vm.Restore(ctx, vmCfg, s.snap.files)
	} else {
		machine, err = vm.Start(ctx, vmCfg)
	}
	if err != nil {
		return nil, nil, err
	}
	// Fail closed: the VMM must actually run with the rate limits (clones inherit them from
	// the snapshot, so a snapshot built without them would show here).
	if err := machine.VerifyLimits(ctx); err != nil {
		machine.Kill()
		return nil, nil, fmt.Errorf("preflight: %w", err)
	}
	r.mark("vmm")
	addCleanup(func(ctx context.Context) {
		gctx, gcancel := context.WithTimeout(ctx, shutdownGrace)
		defer gcancel()
		_ = machine.Shutdown(gctx)
	})
	r.log.Info("vm started", "pid", machine.PID(), "netns", netVM.NS, "outside", client)

	agent, err := dialAgent(jail.Path(vsock))
	if err != nil {
		return nil, nil, err
	}
	addCleanup(func(context.Context) { agent.Close() })
	hello, err := waitAgent(ctx, machine, guestv1.NewGuestAgentServiceClient(agent))
	if err != nil {
		return nil, nil, err
	}
	r.mark("agent")
	if hello.GetBrowserVersion() != img.Manifest.Browser.Version {
		// Guest-attested, so only a warning: the host's record (the image manifest) stands.
		r.log.Warn("guest reports a different browser than the image manifest",
			"guest", hello.GetBrowserVersion(), "manifest", img.Manifest.Browser.Version)
	}
	how := "cold boot"
	var clone *report.Clone
	if s.snap != nil {
		how = "restored " + s.snap.manifest.Name
		if !hello.GetPrepared() {
			r.log.Warn("restored guest has no prepared browser; it will launch one")
		}
	}
	skew := time.Since(hello.GetTime().AsTime())
	if skew < 0 {
		skew = -skew
	}
	if skew > 2*time.Second {
		r.log.Warn("guest clock is off after start", "skew", skew)
	}
	if s.snap != nil {
		clone = &report.Clone{Snapshot: s.snap.manifest.Name, GuestClockSkewMs: skew.Milliseconds(),
			GuestRandom: hex.EncodeToString(hello.GetRandom())}
	}
	if err := r.send(daemonv1.RunState_RUN_STATE_NET_READY,
		fmt.Sprintf("guest agent up %d ms after start (%s; Chrome %s; guest clock within %s)",
			time.Since(t0).Milliseconds(), how, hello.GetBrowserVersion(), skew.Round(time.Millisecond))); err != nil {
		return nil, nil, err
	}
	return agent, clone, nil
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

// jsonLog writes host-attested records, one JSON object per line, up to a limit; records past
// the limit are counted, not written (a page can make the guest generate them at will).
type jsonLog struct {
	mu      sync.Mutex
	f       *os.File
	enc     *json.Encoder
	n, max  int
	dropped int
}

func newJSONLog(path string, max int) (*jsonLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &jsonLog{f: f, enc: json.NewEncoder(f), max: max}, nil
}

func (l *jsonLog) write(v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if l.n >= l.max {
		l.dropped++
		return
	}
	l.n++
	_ = l.enc.Encode(v)
}

func (l *jsonLog) close() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	return l.dropped
}

// bootArgs is the guest kernel command line, the same for cold boots and snapshot builds.
// clocksource=kvm-clock keeps the guest on the clock Firecracker advances on restore
// (clock_realtime): left alone, Linux switches to tsc and a restored guest's wall clock
// resumes from snapshot time (found in P4).
func (s *Server) bootArgs() string {
	return "console=ttyS0 reboot=k panic=1 clocksource=kvm-clock init=" + s.cfg.Image.Manifest.Init + " " + netns.GuestBootArgs()
}
