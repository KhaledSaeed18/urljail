package netns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
)

// unboundConf: forwarding resolver for the VMs, inside the egress namespace (docs/network.md#dns).
var unboundConf = template.Must(template.New("unbound").Parse(`server:
	interface-automatic: yes
	port: 53
	do-ip6: no
	do-daemonize: no
	username: "unbound"
	chroot: ""
	directory: "{{.Dir}}"
	pidfile: ""
	use-syslog: no
	logfile: ""
	verbosity: 1
	log-replies: yes
	num-threads: 1
	hide-identity: yes
	hide-version: yes
	module-config: "iterator"
	access-control: 0.0.0.0/0 refuse
	access-control: 127.0.0.0/8 allow
	access-control: 10.200.0.0/16 allow
	# Rebind protection: answers pointing into private space are removed. For loopback this
	# is the only defense, since a guest's 127.0.0.1 never crosses the firewall.
	private-address: 0.0.0.0/8
	private-address: 10.0.0.0/8
	private-address: 100.64.0.0/10
	private-address: 127.0.0.0/8
	private-address: 169.254.0.0/16
	private-address: 172.16.0.0/12
	private-address: 192.168.0.0/16
	private-address: ::1/128
	private-address: ::ffff:0:0/96
	private-address: fc00::/7
	private-address: fe80::/10

remote-control:
	control-enable: no

forward-zone:
	name: "."
{{- range .Upstreams}}
	forward-addr: {{.}}
{{- end}}
`))

// Query is one DNS reply the resolver sent to a VM.
type Query struct {
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	Name   string    `json:"qname"`
	Type   string    `json:"qtype"`
	Rcode  string    `json:"rcode"`
	RTT    float64   `json:"rtt_s"`
	Cached bool      `json:"cached"`
}

// Resolver is unbound running in the egress namespace.
type Resolver struct {
	log  *slog.Logger
	cmd  *exec.Cmd
	done chan struct{}

	mu    sync.Mutex
	sinks map[string]func(Query) // by client address
}

func startResolver(ctx context.Context, ns string, cfg EgressConfig, log *slog.Logger) (*Resolver, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("resolver: no upstream DNS servers")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return nil, err
	}
	conf := filepath.Join(cfg.StateDir, "unbound.conf")
	f, err := os.OpenFile(conf, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	err = unboundConf.Execute(f, struct {
		Dir       string
		Upstreams []string
	}{cfg.StateDir, cfg.Upstreams})
	f.Close()
	if err != nil {
		return nil, err
	}
	if _, err := run(ctx, nil, "unbound-checkconf", conf); err != nil {
		return nil, err
	}
	if cfg.Relabel != nil {
		if err := cfg.Relabel(cfg.StateDir); err != nil {
			return nil, err
		}
	}

	r := &Resolver{log: log.With("component", "resolver"), done: make(chan struct{}), sinks: map[string]func(Query){}}
	// ip netns exec and runcon both exec in place: the pid is unbound's.
	args := []string{"netns", "exec", ns}
	if cfg.ResolverDomain != "" {
		args = append(args, "runcon", "-t", cfg.ResolverDomain)
	}
	r.cmd = exec.Command("ip", append(args, "unbound", "-d", "-c", conf)...)
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stderr, err := r.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := r.cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting unbound: %w", err)
	}
	ready := make(chan struct{})
	go r.read(stderr, ready)
	go func() {
		_ = r.cmd.Wait()
		close(r.done)
	}()

	select {
	case <-ready:
		if want := cfg.ResolverDomain; want != "" {
			if got := r.domain(); got != want {
				r.stop()
				return nil, fmt.Errorf("resolver: unbound runs as %q, not %q (SELinux transition missing?)", got, want)
			}
		}
		return r, nil
	case <-r.done:
		return nil, errors.New("unbound exited during startup (see the daemon log)")
	case <-time.After(5 * time.Second):
		r.stop()
		return nil, errors.New("unbound didn't report 'start of service' within 5s")
	}
}

func (r *Resolver) read(stderr interface{ Read([]byte) (int, error) }, ready chan struct{}) {
	sc := bufio.NewScanner(stderr)
	once := sync.Once{}
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "start of service") {
			once.Do(func() { close(ready) })
		}
		if q, ok := parseReply(line); ok {
			r.mu.Lock()
			sink := r.sinks[q.Client]
			r.mu.Unlock()
			if sink != nil {
				sink(q)
			}
			continue
		}
		r.log.Info(line)
	}
}

// parseReply parses unbound's log-replies line:
// "[1760281234] unbound[12:0] info: 10.200.0.2 example.com. A IN NOERROR 0.033149 0 56"
func parseReply(line string) (Query, bool) {
	i := strings.Index(line, " info: ")
	if i < 0 {
		return Query{}, false
	}
	f := strings.Fields(line[i+len(" info: "):])
	if len(f) < 8 || !strings.HasPrefix(f[0], "10.200.") {
		return Query{}, false
	}
	rtt, _ := strconv.ParseFloat(f[5], 64)
	return Query{
		Time:   time.Now().UTC(),
		Client: f[0],
		Name:   f[1],
		Type:   f[2],
		Rcode:  f[4],
		RTT:    rtt,
		Cached: f[6] == "1",
	}, true
}

// Attach sends every reply to client (a VM's outside address) to fn until Detach.
func (r *Resolver) Attach(client string, fn func(Query)) {
	r.mu.Lock()
	r.sinks[client] = fn
	r.mu.Unlock()
}

// Detach stops delivering replies for client.
func (r *Resolver) Detach(client string) {
	r.mu.Lock()
	delete(r.sinks, client)
	r.mu.Unlock()
}

func (r *Resolver) alive() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *Resolver) stop() {
	if !r.alive() {
		return
	}
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		_ = r.cmd.Process.Kill()
		<-r.done
	}
}

// domain is the SELinux type unbound runs as ("" if unknown).
func (r *Resolver) domain() string {
	if r.cmd == nil || r.cmd.Process == nil {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/current", r.cmd.Process.Pid))
	if err != nil {
		return ""
	}
	// user:role:type:level
	f := strings.Split(strings.TrimRight(string(b), "\x00\n"), ":")
	if len(f) < 3 {
		return ""
	}
	return f[2]
}
