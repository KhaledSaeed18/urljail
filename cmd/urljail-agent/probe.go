package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
)

const maxProbes = 64

// Probe implements the isolation self-test's guest side: it only reports what happened.
func (a *agent) Probe(ctx context.Context, req *guestv1.ProbeRequest) (*guestv1.ProbeResponse, error) {
	probes := req.GetProbes()
	if len(probes) > maxProbes {
		probes = probes[:maxProbes]
	}
	timeout := req.GetTimeout().AsDuration()
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 2 * time.Second
	}
	results := make([]*guestv1.ProbeResult, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			res := probe(pctx, p, timeout)
			res.Id = p.GetId()
			results[i] = res
		}()
	}
	wg.Wait()
	return &guestv1.ProbeResponse{Results: results}, nil
}

func probe(ctx context.Context, p *guestv1.ProbeSpec, timeout time.Duration) *guestv1.ProbeResult {
	switch k := p.GetKind().(type) {
	case *guestv1.ProbeSpec_Tcp:
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", k.Tcp)
		if err == nil {
			c.Close()
			return &guestv1.ProbeResult{Outcome: "connected"}
		}
		return netErr(err)
	case *guestv1.ProbeSpec_Udp:
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", k.Udp)
		if err != nil {
			return netErr(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("urljail isolation probe")); err != nil {
			return netErr(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(timeout / 2))
		if _, err := c.Read(make([]byte, 512)); err == nil {
			return &guestv1.ProbeResult{Outcome: "reply"}
		}
		return &guestv1.ProbeResult{Outcome: "no reply"}
	case *guestv1.ProbeSpec_Dns:
		return resolve(ctx, net.DefaultResolver, k.Dns)
	case *guestv1.ProbeSpec_DnsVia:
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, k.DnsVia.GetServer())
		}}
		return resolve(ctx, r, k.DnsVia.GetName())
	}
	return &guestv1.ProbeResult{Outcome: "error", Detail: []string{"unknown probe kind"}}
}

func resolve(ctx context.Context, r *net.Resolver, name string) *guestv1.ProbeResult {
	addrs, err := r.LookupIPAddr(ctx, name)
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(addrs) > 0:
		res := &guestv1.ProbeResult{Outcome: "resolved"}
		for _, a := range addrs {
			res.Detail = append(res.Detail, a.IP.String())
		}
		return res
	case err == nil, errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return &guestv1.ProbeResult{Outcome: "no answer"}
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		return &guestv1.ProbeResult{Outcome: "timeout"}
	}
	return &guestv1.ProbeResult{Outcome: "error", Detail: []string{err.Error()}}
}

func netErr(err error) *guestv1.ProbeResult {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return &guestv1.ProbeResult{Outcome: "timeout"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return &guestv1.ProbeResult{Outcome: "refused"}
	}
	return &guestv1.ProbeResult{Outcome: "error", Detail: []string{err.Error()}}
}
