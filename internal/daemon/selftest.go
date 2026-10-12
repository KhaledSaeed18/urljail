package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/netns"
	"github.com/KhaledSaeed18/urljail/internal/policy"
	"github.com/KhaledSaeed18/urljail/internal/report"
	"github.com/KhaledSaeed18/urljail/internal/version"
)

// isolationCheck is one row of the isolation test plan: a probe from inside the guest, the
// outcomes that pass, and the host-side evidence required on top.
type isolationCheck struct {
	name     string
	expected string
	probe    *guestv1.ProbeSpec // nil: a host-only check
	outcomes []string           // guest outcomes that pass
	counter  string             // drop counter that must increase ("" = none); "vm-*" are in the VM netns
	internet bool               // needs working internet through the exit to be judged
	dnsName  string             // name that must appear in the host's DNS log
	host     func() (bool, string)
}

// SelfTest implements DaemonService.SelfTest.
func (s *Server) SelfTest(ctx context.Context, _ *daemonv1.SelfTestRequest) (*daemonv1.SelfTestResponse, error) {
	if s.net == nil {
		return nil, status.Error(codes.FailedPrecondition, "no egress network (egress mode off)")
	}
	// Take every slot: the drop counters are shared, so nothing else may run meanwhile.
	var held []int
	defer func() {
		for _, n := range held {
			s.slots.release(n)
		}
	}()
	for range s.slots.size() {
		n, ok := s.slots.acquire()
		if !ok {
			return nil, status.Error(codes.Unavailable, "runs are active; the self-test needs the daemon to itself")
		}
		held = append(held, n)
	}
	slot := held[0]
	if err := s.net.Verify(ctx, slot); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "preflight: %v", err)
	}

	id, _ := uuid.NewV7()
	r := &run{id: id.String(), stream: noProgress{}, log: s.log.With("selftest", id.String()), start: time.Now()}
	runDir := filepath.Join(s.cfg.RunsDir, r.id)
	if err := s.cfg.Operator.MkdirAll(filepath.Join(runDir, "host"), 0o700); err != nil {
		return nil, err
	}
	defer s.cfg.Operator.ChownTree(runDir)
	m := report.Meta{RunID: r.id, URL: "selftest:isolation", Profile: "selftest", Egress: string(s.cfg.Policy.Mode),
		StartedAt: time.Now().UTC(), Versions: map[string]string{"urljail": version.String(), "image": s.cfg.Image.Manifest.Name}}
	_ = report.WriteMeta(runDir, m)

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var cleanups []func(context.Context)
	defer func() {
		base := context.WithoutCancel(ctx)
		for i := len(cleanups) - 1; i >= 0; i-- {
			sctx, scancel := context.WithTimeout(base, cleanupStepTimeout)
			cleanups[i](sctx)
			scancel()
		}
	}()
	agent, clone, err := s.bootVM(ctx, r, slot, runDir, func(f func(context.Context)) { cleanups = append(cleanups, f) })
	if err != nil {
		return nil, status.Errorf(codes.Internal, "booting the test VM: %v", err)
	}
	vm := &netns.VM{Slot: slot, NS: netns.VMNS(slot)}

	checks := s.isolationPlan(r.id)
	var probes []*guestv1.ProbeSpec
	for _, c := range checks {
		if c.probe != nil {
			probes = append(probes, c.probe)
		}
	}
	before, err := s.allCounters(ctx, vm)
	if err != nil {
		return nil, err
	}
	resp, err := guestv1.NewGuestAgentServiceClient(agent).Probe(ctx, &guestv1.ProbeRequest{
		Probes: probes, Timeout: durationpb.New(2 * time.Second)})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "guest probes: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // let the resolver's log lines arrive
	after, err := s.allCounters(ctx, vm)
	if err != nil {
		return nil, err
	}
	dnsSeen := dnsNames(filepath.Join(runDir, "host", "dns.jsonl"))
	blocked := blockedSet(filepath.Join(runDir, "host", "blocked.jsonl"))

	byID := map[string]*guestv1.ProbeResult{}
	for _, res := range resp.GetResults() {
		byID[res.GetId()] = res
	}
	out := &daemonv1.SelfTestResponse{Passed: true, RunDir: runDir, EgressMode: string(s.cfg.Policy.Mode)}
	online := byID["public-https"].GetOutcome() == "connected"
	for _, c := range checks {
		row := &daemonv1.Check{Name: c.name, Expected: c.expected}
		pass := true
		var obs []string
		if c.probe != nil {
			res := byID[c.probe.GetId()]
			outcome := "missing"
			if res != nil {
				outcome = res.GetOutcome()
				if len(res.GetDetail()) > 0 {
					outcome += " " + strings.Join(res.GetDetail(), ",")
				}
			}
			obs = append(obs, "guest: "+outcome)
			pass = res != nil && contains(c.outcomes, res.GetOutcome())
		}
		if c.counter != "" {
			d := after[c.counter] - before[c.counter]
			obs = append(obs, fmt.Sprintf("host: %s +%d", c.counter, d))
			pass = pass && d > 0
			// Egress drops are also logged per packet: require this probe's own destination.
			if target := probeTarget(c.probe); target != "" && !strings.HasPrefix(c.counter, "vm-") {
				seen := blocked[c.counter+" "+target]
				obs = append(obs, fmt.Sprintf("blocked log has %s: %v", target, seen))
				pass = pass && seen
			}
		}
		if c.dnsName != "" {
			seen := dnsSeen[strings.ToLower(c.dnsName)+"."]
			obs = append(obs, fmt.Sprintf("host dns log: %v", seen))
			pass = pass && seen
		}
		if c.host != nil {
			ok, msg := c.host()
			obs = append(obs, msg)
			pass = pass && ok
		}
		row.Observed = strings.Join(obs, "; ")
		row.Result = "pass"
		switch {
		case !pass && c.internet && !online:
			row.Result = "skip"
			row.Observed += "; inconclusive: no internet through the exit (public control failed)"
			out.Passed = false
			out.Inconclusive = true
		case !pass:
			row.Result = "fail"
			out.Passed = false
		}
		out.Checks = append(out.Checks, row)
	}
	out.Checks = append(out.Checks, &daemonv1.Check{Name: "VMM jailed and confined", Expected: "jail uid, seccomp, cgroup, chroot, urljail_vmm_t",
		Observed: "host: " + r.confinement, Result: "pass"}) // bootVM refuses to continue otherwise
	if clone != nil { // clone safety (P4)
		row := &daemonv1.Check{Name: "Guest clock after restore", Expected: "within 2s of the host",
			Observed: fmt.Sprintf("guest: %d ms off", clone.GuestClockSkewMs), Result: "pass"}
		if clone.GuestClockSkewMs > 2000 {
			row.Result, out.Passed = "fail", false
		}
		out.Checks = append(out.Checks, row)
		serial, _ := os.ReadFile(filepath.Join(runDir, "host", "serial.log"))
		reseeded := strings.Contains(string(serial), "crng reseeded due to virtual machine fork")
		row = &daemonv1.Check{Name: "Kernel RNG reseeded on restore", Expected: "VMGenID reseed in the guest log",
			Observed: fmt.Sprintf("serial log: %v", reseeded), Result: "pass"}
		if !reseeded {
			row.Result, out.Passed = "fail", false
		}
		out.Checks = append(out.Checks, row)
	}
	if s.net.Live() {
		for _, c := range s.liveChecks(ctx, guestv1.NewGuestAgentServiceClient(agent)) {
			if c.GetResult() == "fail" {
				out.Passed = false
			}
			out.Checks = append(out.Checks, c)
		}
	} else {
		for _, name := range []string{"VPN down ⇒ no egress", "Public IP seen by the guest is the VPN exit"} {
			out.Checks = append(out.Checks, &daemonv1.Check{Name: name, Expected: "live mode only", Result: "skip",
				Observed: "egress mode " + string(s.cfg.Policy.Mode)})
		}
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	_ = os.WriteFile(filepath.Join(runDir, "selftest.json"), append(b, '\n'), 0o600)
	m.EndedAt, m.Status = time.Now().UTC(), "completed"
	if !out.Passed {
		m.Status = "error"
		m.Error = "isolation self-test failed"
	}
	_ = report.WriteMeta(runDir, m)
	return out, nil
}

func (s *Server) isolationPlan(runID string) []isolationCheck {
	tcp := func(id, addr string) *guestv1.ProbeSpec {
		return &guestv1.ProbeSpec{Id: id, Kind: &guestv1.ProbeSpec_Tcp{Tcp: addr}}
	}
	dns := func(id, name string) *guestv1.ProbeSpec {
		return &guestv1.ProbeSpec{Id: id, Kind: &guestv1.ProbeSpec_Dns{Dns: name}}
	}
	dropped := []string{"timeout"}
	hijackName := fmt.Sprintf("selftest-%s.example.com", strings.ReplaceAll(runID, "-", "")[:16])

	checks := []isolationCheck{
		{name: "Public HTTPS reachable (control)", expected: "connected",
			probe: tcp("public-https", "example.com:443"), outcomes: []string{"connected"}, internet: true},
		{name: "Public non-web port", expected: "dropped (other)",
			probe: tcp("public-22", "1.1.1.1:22"), outcomes: dropped, counter: "other"},
		{name: "Cloud metadata 169.254.169.254", expected: "dropped (private)",
			probe: tcp("metadata", "169.254.169.254:80"), outcomes: dropped, counter: "private"},
		{name: "Another VM (10.200.1.2)", expected: "dropped (private)",
			probe: tcp("other-vm", "10.200.1.2:80"), outcomes: dropped, counter: "private"},
		{name: "Host side of the exit (10.199.0.1)", expected: "dropped (private)",
			probe: tcp("exit-host", "10.199.0.1:22"), outcomes: dropped, counter: "private"},
		{name: "Egress namespace itself (10.200.0.1:80)", expected: "dropped (input)",
			probe: tcp("egress-ns", netns.ResolverIP(0)+":80"), outcomes: dropped, counter: "input"},
		{name: "VM namespace itself (172.16.0.1:22)", expected: "dropped (vm-input)",
			probe: tcp("vm-ns", netns.TapIP+":22"), outcomes: dropped, counter: "vm-input"},
		{name: "QUIC (UDP 443)", expected: "dropped (quic)",
			probe:    &guestv1.ProbeSpec{Id: "quic", Kind: &guestv1.ProbeSpec_Udp{Udp: "1.1.1.1:443"}},
			outcomes: []string{"no reply"}, counter: "quic"},
		{name: "DNS to 8.8.8.8 answered by our resolver", expected: "answered, in host DNS log",
			probe: &guestv1.ProbeSpec{Id: "dns-hijack", Kind: &guestv1.ProbeSpec_DnsVia{
				DnsVia: &guestv1.DNSVia{Name: hijackName, Server: "8.8.8.8:53"}}},
			outcomes: []string{"no answer", "resolved"}, dnsName: hijackName, internet: true},
		{name: "Rebind control: public answer passes", expected: "resolved 1.1.1.1",
			probe: dns("rebind-control", "1.1.1.1.nip.io"), outcomes: []string{"resolved"}, internet: true},
		{name: "Rebind to RFC 1918 refused", expected: "no answer",
			probe: dns("rebind-private", "192.168.1.1.nip.io"), outcomes: []string{"no answer"}, internet: true},
		{name: "Rebind to loopback refused", expected: "no answer",
			probe: dns("rebind-loopback", "127.0.0.1.nip.io"), outcomes: []string{"no answer"}, internet: true},
		s.policyCheck(),
	}
	// The host's own LAN: default gateway, host addresses, Docker's bridge.
	for _, a := range hostLANTargets() {
		checks = append(checks, isolationCheck{name: "Home LAN / host: " + a.label, expected: "dropped (private)",
			probe: tcp("lan-"+a.addr, net.JoinHostPort(a.addr, "80")), outcomes: dropped, counter: "private"})
	}
	return checks
}

type lanTarget struct{ label, addr string }

// hostLANTargets finds the default gateway, the host's addresses on the default interface,
// and Docker's bridge address.
func hostLANTargets() []lanTarget {
	var out []lanTarget
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if b, err := exec.Command("ip", "-j", "-4", "route", "show", "default").Output(); err == nil && json.Unmarshal(b, &routes) == nil && len(routes) > 0 {
		if routes[0].Gateway != "" {
			out = append(out, lanTarget{"default gateway " + routes[0].Gateway, routes[0].Gateway})
		}
		for _, a := range ifaceAddrs(routes[0].Dev) {
			out = append(out, lanTarget{"host address " + a, a})
		}
	}
	for _, a := range ifaceAddrs("docker0") {
		out = append(out, lanTarget{"Docker bridge " + a, a})
	}
	return out
}

func ifaceAddrs(dev string) []string {
	var ifs []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	b, err := exec.Command("ip", "-j", "-4", "addr", "show", "dev", dev).Output()
	if err != nil || json.Unmarshal(b, &ifs) != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		for _, a := range i.AddrInfo {
			out = append(out, a.Local)
		}
	}
	return out
}

func (s *Server) allCounters(ctx context.Context, vm *netns.VM) (map[string]uint64, error) {
	eg, err := s.net.Counters(ctx)
	if err != nil {
		return nil, err
	}
	v, err := s.net.VMCounters(ctx, vm)
	if err != nil {
		return nil, err
	}
	for k, n := range v {
		eg[k] = n
	}
	return eg, nil
}

// probeTarget is "proto ip:port" for TCP and UDP probes.
func probeTarget(p *guestv1.ProbeSpec) string {
	switch {
	case p.GetTcp() != "":
		return "tcp " + p.GetTcp()
	case p.GetUdp() != "":
		return "udp " + p.GetUdp()
	}
	return ""
}

// blockedSet reads host/blocked.jsonl as a set of "reason proto ip:port".
func blockedSet(path string) map[string]bool {
	seen := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return seen
	}
	for _, line := range strings.Split(string(b), "\n") {
		var bl netns.Blocked
		if json.Unmarshal([]byte(line), &bl) == nil && bl.Dst != "" {
			seen[fmt.Sprintf("%s %s %s", bl.Reason, bl.Proto, net.JoinHostPort(bl.Dst, fmt.Sprint(bl.Port)))] = true
		}
	}
	return seen
}

func dnsNames(path string) map[string]bool {
	seen := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return seen
	}
	for _, line := range strings.Split(string(b), "\n") {
		var q struct {
			Name string `json:"qname"`
		}
		if json.Unmarshal([]byte(line), &q) == nil && q.Name != "" {
			seen[strings.ToLower(q.Name)] = true
		}
	}
	return seen
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ipEcho returns the caller's public IP as plain text.
const ipEcho = "https://api.ipify.org"

// liveChecks are the self-test rows that need the WireGuard exit (docs/network.md).
func (s *Server) liveChecks(ctx context.Context, agent guestv1.GuestAgentServiceClient) []*daemonv1.Check {
	var out []*daemonv1.Check
	probe := func(p *guestv1.ProbeSpec) *guestv1.ProbeResult {
		resp, err := agent.Probe(ctx, &guestv1.ProbeRequest{Probes: []*guestv1.ProbeSpec{p}, Timeout: durationpb.New(10 * time.Second)})
		if err != nil || len(resp.GetResults()) != 1 {
			return &guestv1.ProbeResult{Outcome: "error", Detail: []string{fmt.Sprint(err)}}
		}
		return resp.GetResults()[0]
	}

	// The exit IP: what the guest sees as its public address must not be the host's.
	row := &daemonv1.Check{Name: "Public IP seen by the guest is the VPN exit", Expected: "differs from the host's public IP"}
	// Free VPN servers are sometimes slow: up to three tries before calling it a failure.
	var guest *guestv1.ProbeResult
	for try := 0; try < 3; try++ {
		if guest = probe(&guestv1.ProbeSpec{Id: "exit-ip", Kind: &guestv1.ProbeSpec_HttpGet{HttpGet: ipEcho}}); guest.GetOutcome() == "http 200" {
			break
		}
	}
	hostIP, herr := hostPublicIP(ctx)
	guestIP := strings.Join(guest.GetDetail(), "")
	row.Observed = fmt.Sprintf("guest: %s %s; host: %s %v", guest.GetOutcome(), guestIP, hostIP, herr)
	switch {
	case s.cfg.Policy.Mode == policy.EgressLiveTest:
		row.Result, row.Observed = "skip", row.Observed+"; live-test: the local test peer exits through this host"
	case guest.GetOutcome() == "http 200" && net.ParseIP(guestIP) != nil && herr == nil && guestIP != hostIP:
		row.Result = "pass"
	default:
		row.Result = "fail"
	}
	out = append(out, row)

	// VPN down ⇒ no egress: take the tunnel down for real, check nothing gets out, restore it.
	row = &daemonv1.Check{Name: "VPN down ⇒ no egress", Expected: "public TCP 443 unreachable with the tunnel down"}
	if err := s.net.SetTunnel(ctx, false); err != nil {
		row.Result, row.Observed = "fail", "taking the tunnel down: "+err.Error()
		return append(out, row)
	}
	down := probe(&guestv1.ProbeSpec{Id: "vpn-down", Kind: &guestv1.ProbeSpec_Tcp{Tcp: "1.1.1.1:443"}})
	upAt := time.Now()
	upErr := s.net.SetTunnel(ctx, true)
	if upErr == nil {
		hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		upErr = s.net.WaitHandshake(hctx, upAt.Add(-time.Second))
		cancel()
	}
	row.Observed = "guest: " + down.GetOutcome() + " " + strings.Join(down.GetDetail(), " ")
	row.Result = "pass"
	if down.GetOutcome() == "connected" {
		row.Result = "fail"
	}
	if upErr != nil {
		row.Result, row.Observed = "fail", row.Observed+"; restoring the tunnel failed: "+upErr.Error()
	}
	return append(out, row)
}

// hostPublicIP asks the IP-echo service from the host's own network namespace.
func hostPublicIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipEcho, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.TrimSpace(string(b)), nil
}

// policyCheck tests the URL policy for the current mode: dev and live-test must refuse a
// non-allowlisted URL; live allows any public http(s) URL by design, but must still refuse
// other schemes and ports.
func (s *Server) policyCheck() isolationCheck {
	if s.cfg.Policy.Mode == policy.EgressLive {
		return isolationCheck{name: "Live mode refuses non-web schemes and ports", expected: "file:, javascript: and port 22 refused",
			host: func() (bool, string) {
				for _, u := range []string{"file:///etc/passwd", "javascript:alert(1)", "https://phish.test:22/"} {
					if _, err := s.cfg.Policy.Check(u); err == nil {
						return false, "host: allowed " + u
					}
				}
				return true, "host: all refused"
			}}
	}
	return isolationCheck{name: "Dev mode refuses a non-allowlisted URL", expected: "refused by policy",
		host: func() (bool, string) {
			_, err := s.cfg.Policy.Check("https://phish.test/login")
			if err == nil {
				return false, "host: allowed"
			}
			return true, "host: " + err.Error()
		}}
}
