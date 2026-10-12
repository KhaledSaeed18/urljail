package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/KhaledSaeed18/urljail/internal/netns"
)

// Flow is one connection as seen on the VM's TAP, oriented from the guest (host-attested).
type Flow struct {
	Proto    string    `json:"proto"`
	Src      string    `json:"src"`
	Sport    int       `json:"sport"`
	Dst      string    `json:"dst"`
	Dport    int       `json:"dport"`
	PktsOut  uint64    `json:"pkts_out"`
	BytesOut uint64    `json:"bytes_out"`
	PktsIn   uint64    `json:"pkts_in"`
	BytesIn  uint64    `json:"bytes_in"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	FlagsOut string    `json:"tcp_flags_out,omitempty"`
	FlagsIn  string    `json:"tcp_flags_in,omitempty"`
	SNI      string    `json:"sni,omitempty"`
	ALPN     []string  `json:"alpn,omitempty"`
	HTTPHost string    `json:"http_host,omitempty"` // Host header of a plain-HTTP request
	Source   string    `json:"source"`
}

// Probe is the eBPF program attached to one VM's TAP.
type Probe struct {
	log   *slog.Logger
	objs  flowObjects
	links []link.Link
	rd    *ringbuf.Reader
	read  chan struct{}
	stop  atomic.Bool
	mono  time.Duration // wall clock minus CLOCK_MONOTONIC, to convert bpf_ktime_get_ns

	mu   sync.Mutex
	segs map[flowFlowKey][]seg
}

// Attach loads the program and attaches it with TCX to iface inside network namespace ns.
func Attach(ns, iface string, log *slog.Logger) (*Probe, error) {
	p := &Probe{log: log, read: make(chan struct{}), segs: map[flowFlowKey][]seg{}}
	if err := loadFlowObjects(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF: %w", err)
	}
	err := netns.Do(ns, func() error { // ifindexes are per namespace
		ifc, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}
		for _, a := range []struct {
			prog *ebpf.Program
			at   ebpf.AttachType
		}{{p.objs.TapIngress, ebpf.AttachTCXIngress}, {p.objs.TapEgress, ebpf.AttachTCXEgress}} {
			l, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: a.prog, Attach: a.at})
			if err != nil {
				return err
			}
			p.links = append(p.links, l)
		}
		return nil
	})
	if err != nil {
		p.closeAll()
		return nil, fmt.Errorf("attaching eBPF to %s in %s: %w", iface, ns, err)
	}
	if p.rd, err = ringbuf.NewReader(p.objs.Segments); err != nil {
		p.closeAll()
		return nil, err
	}
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	p.mono = time.Duration(time.Now().UnixNano() - ts.Nano())
	go p.readSegments()
	return p, nil
}

func (p *Probe) readSegments() {
	defer close(p.read)
	for {
		// A deadline set while Read is already blocked doesn't wake it, so poll: each Read
		// waits at most 200 ms, and once Close asked to stop, an empty buffer ends the loop.
		p.rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := p.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if p.stop.Load() {
				return
			}
			continue
		}
		if err != nil {
			return
		}
		var s flowSegment
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &s); err != nil {
			continue
		}
		n := min(int(s.Len), len(s.Data))
		p.mu.Lock()
		p.segs[s.Key] = append(p.segs[s.Key], seg{seq: s.Seq, data: append([]byte(nil), s.Data[:n]...)})
		p.mu.Unlock()
	}
}

// Close detaches the program, drains the ring buffer and returns every flow it saw.
func (p *Probe) Close() []Flow {
	for _, l := range p.links {
		l.Close()
	}
	p.links = nil
	p.stop.Store(true)
	select {
	case <-p.read:
	case <-time.After(2 * time.Second):
		// Never let teardown hang on the reader: closing it unblocks Read for certain.
		p.log.Warn("eBPF ring buffer reader didn't stop; closing it")
		p.rd.Close()
		<-p.read
	}

	var flows []Flow
	var k flowFlowKey
	var v flowFlowVal
	it := p.objs.Flows.Iterate()
	for it.Next(&k, &v) {
		f := Flow{
			Proto: protoName(k.Proto), Src: ip4(k.Saddr), Sport: int(k.Sport), Dst: ip4(k.Daddr), Dport: int(k.Dport),
			PktsOut: v.PktsOut, BytesOut: v.BytesOut, PktsIn: v.PktsIn, BytesIn: v.BytesIn,
			First: p.wall(v.FirstNs), Last: p.wall(v.LastNs),
			FlagsOut: tcpFlags(v.TcpFlagsOut), FlagsIn: tcpFlags(v.TcpFlagsIn), Source: "host.ebpf",
		}
		p.mu.Lock()
		segs := p.segs[k]
		p.mu.Unlock()
		data := reassemble(segs)
		if h, err := parseClientHello(data); err == nil {
			f.SNI, f.ALPN = h.SNI, h.ALPN
		} else {
			f.HTTPHost = parseHTTPHost(data)
		}
		flows = append(flows, f)
	}
	if err := it.Err(); err != nil {
		p.log.Warn("reading eBPF flows", "err", err)
	}
	p.closeAll()
	sort.Slice(flows, func(i, j int) bool { return flows[i].First.Before(flows[j].First) })
	return flows
}

func (p *Probe) closeAll() {
	for _, l := range p.links {
		l.Close()
	}
	if p.rd != nil {
		p.rd.Close()
	}
	p.objs.Close()
}

func (p *Probe) wall(ns uint64) time.Time { return time.Unix(0, int64(ns)+int64(p.mono)).UTC() }

// ip4 converts an address stored in network byte order, read as a little-endian uint32.
func ip4(v uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b).String()
}

func protoName(p uint8) string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	}
	return fmt.Sprint(p)
}

func tcpFlags(f uint8) string {
	var out []string
	for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
		if f&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}

// Supported reports whether the kernel exposes BTF, which loading the program needs; doctor
// uses it. TCX itself needs Linux 6.6+, which Attach reports if missing.
func Supported() error {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return errors.New("no kernel BTF (/sys/kernel/btf/vmlinux)")
	}
	return nil
}
