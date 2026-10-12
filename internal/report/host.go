package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

// Host-side records, as urljaild writes them (internal/netns, internal/capture).
type (
	hostDNS struct {
		Time   time.Time `json:"time"`
		Name   string    `json:"qname"`
		Type   string    `json:"qtype"`
		Rcode  string    `json:"rcode"`
		Cached bool      `json:"cached"`
	}
	hostFlow struct {
		Proto    string    `json:"proto"`
		Dst      string    `json:"dst"`
		Dport    int       `json:"dport"`
		PktsOut  uint64    `json:"pkts_out"`
		BytesOut uint64    `json:"bytes_out"`
		PktsIn   uint64    `json:"pkts_in"`
		BytesIn  uint64    `json:"bytes_in"`
		First    time.Time `json:"first"`
		Last     time.Time `json:"last"`
		FlagsOut string    `json:"tcp_flags_out"`
		SNI      string    `json:"sni"`
		ALPN     []string  `json:"alpn"`
		HTTPHost string    `json:"http_host"`
	}
	hostBlocked struct {
		Time   time.Time `json:"time"`
		Reason string    `json:"reason"`
		Dst    string    `json:"dst"`
		Proto  string    `json:"proto"`
		Port   int       `json:"dst_port"`
	}
)

// readJSONL decodes one record per line, skipping lines that don't parse.
func readJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			out = append(out, v)
		}
	}
	return out, sc.Err()
}

// addHost fills the host-attested sections and the reconciliation. It reports whether the
// run has host-side records at all (runs from before P3 don't).
func addHost(r *reportv0.Report, runDir string) bool {
	host := filepath.Join(runDir, "host")
	dns, dnsErr := readJSONL[hostDNS](filepath.Join(host, "dns.jsonl"))
	flows, flowErr := readJSONL[hostFlow](filepath.Join(host, "flows.jsonl"))
	blocked, blockErr := readJSONL[hostBlocked](filepath.Join(host, "blocked.jsonl"))
	if dnsErr != nil && flowErr != nil && blockErr != nil {
		return false
	}
	if flowErr != nil {
		r.Gaps = append(r.Gaps, "No host flow records (host/flows.jsonl missing): the eBPF capture didn't report")
	}

	// What the guest's browser says it fetched over the network.
	guestHosts := map[string]bool{} // URL hosts
	guestAddrs := map[string]bool{} // "ip:port" the guest reported connecting to
	var pending []*reportv0.Request // requests that should have crossed the network
	for _, q := range r.GetNetwork().GetRequests() {
		u, err := url.Parse(q.GetUrl())
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		guestHosts[h] = true
		if q.GetRemoteIp() != "" && !q.GetFromCache() {
			guestAddrs[net.JoinHostPort(q.GetRemoteIp(), portOf(u))] = true
			pending = append(pending, q)
		}
	}
	isPageHost := func(h string) bool { return guestHosts[strings.TrimSuffix(strings.ToLower(h), ".")] }

	rec := &reportv0.Reconciliation{}
	hostAddrs, hostSNI := map[string]bool{}, map[string]bool{}
	for _, f := range flows {
		fl := &reportv0.Flow{
			Proto: f.Proto, DstIp: f.Dst, DstPort: uint32(f.Dport), Sni: f.SNI, Alpn: f.ALPN,
			PacketsOut: clampU32(float64(f.PktsOut)), BytesOut: clampU32(float64(f.BytesOut)),
			PacketsIn: clampU32(float64(f.PktsIn)), BytesIn: clampU32(float64(f.BytesIn)),
			First: ts(f.First), Last: ts(f.Last), TcpFlagsOut: f.FlagsOut, Source: "host.ebpf", HttpHost: f.HTTPHost,
		}
		name := f.SNI // the name the guest asked for on this connection, if it said
		if name == "" {
			name = f.HTTPHost
		}
		addr := net.JoinHostPort(f.Dst, fmt.Sprint(f.Dport))
		switch {
		case f.Dst == "172.16.0.1" && (f.Dport == 53 || f.Proto == "icmp"):
			// DNS to our resolver, and the guest's ICMP errors for late replies to it.
			fl.Label = "dns"
		case guestAddrs[addr] || (name != "" && isPageHost(name)):
			fl.Label = "page"
			rec.PageFlows++
		case name != "" && isBackground(name):
			fl.Label = "browser-background"
			rec.BackgroundFlows++
		case f.Proto == "tcp" && !strings.Contains(f.FlagsOut, "PSH") && name == "",
			f.Proto == "icmp" && f.PktsOut == 0:
			// Handshake only (preconnects, attempts the firewall dropped), or ICMP the guest
			// only received.
			fl.Label = "no-data"
		default:
			fl.Label = "unexplained"
			if name == "" {
				name = "no SNI or Host"
			}
			rec.UnexplainedFlows = append(rec.UnexplainedFlows, fmt.Sprintf("%s %s (%s)", f.Proto, addr, name))
		}
		hostAddrs[addr] = true
		if f.SNI != "" {
			hostSNI[strings.ToLower(f.SNI)] = true
		}
		r.Network.Flows = append(r.Network.Flows, fl)
	}

	seenName := map[string]bool{}
	for _, q := range dns {
		label := "unexplained"
		switch {
		case isPageHost(q.Name):
			label = "page"
		case isBackground(q.Name):
			label = "browser-background"
		}
		r.Network.Dns = append(r.Network.Dns, &reportv0.DnsQuery{Qname: q.Name, Qtype: q.Type, Rcode: q.Rcode,
			Cached: q.Cached, Time: ts(q.Time), Label: label, Source: "host.dns"})
		if n := strings.TrimSuffix(q.Name, "."); label == "unexplained" && !seenName[n] {
			seenName[n] = true
			rec.UnexplainedDns = append(rec.UnexplainedDns, n)
		}
	}

	if flowErr == nil {
		for _, q := range pending {
			u, _ := url.Parse(q.GetUrl())
			addr := net.JoinHostPort(q.GetRemoteIp(), portOf(u))
			if !hostAddrs[addr] && !hostSNI[strings.ToLower(u.Hostname())] {
				rec.GuestOnlyRequests = append(rec.GuestOnlyRequests, q.GetUrl())
			}
		}
	}

	type bkey struct {
		reason, proto, dst string
		port               int
	}
	groups := map[bkey]*reportv0.Blocked{}
	var order []bkey
	for _, b := range blocked {
		k := bkey{b.Reason, b.Proto, b.Dst, b.Port}
		if groups[k] == nil {
			groups[k] = &reportv0.Blocked{Reason: b.Reason, Proto: b.Proto, DstIp: b.Dst, DstPort: uint32(b.Port),
				First: ts(b.Time), Source: "host.fw"}
			order = append(order, k)
		}
		groups[k].Count++
	}
	for _, k := range order {
		r.Network.Blocked = append(r.Network.Blocked, groups[k])
	}

	sort.Strings(rec.UnexplainedDns)
	rec.Consistent = len(rec.UnexplainedFlows) == 0 && len(rec.UnexplainedDns) == 0 && len(rec.GuestOnlyRequests) == 0
	r.Reconciliation = rec
	r.Gaps = append(r.Gaps,
		"DNS answers aren't logged: host.dns has names, types and response codes only",
		"Browser-background labels come from a list of known Chrome endpoints (internal/report/background.go); a page that loads those hosts itself is labeled page",
	)
	return true
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
