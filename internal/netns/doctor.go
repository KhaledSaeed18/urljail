package netns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// CheckExit opens a TCP connection to addr from inside the egress namespace. The namespace's
// own processes may only reach the exit on ports 53 and 853 (the resolver's upstream), so use
// one of those: anything else is dropped by design.
func (e *Egress) CheckExit(addr string) error {
	return Do(EgressNS, func() error {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			c.Close()
		}
		return err
	})
}

// CheckResolver sends one DNS query for name (type A) to the resolver from inside the egress
// namespace. It builds the query by hand: Go's resolver dials from other goroutines, whose
// threads aren't in the namespace.
func (e *Egress) CheckResolver(name string) error {
	return Do(EgressNS, func() error {
		c, err := net.Dial("udp", "127.0.0.1:53") // the socket is created on this thread, in the namespace
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		q := []byte{0x75, 0x6a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0} // id, RD, 1 question
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			q = append(q, byte(len(label)))
			q = append(q, label...)
		}
		q = append(q, 0, 0, 1, 0, 1) // root, type A, class IN
		if _, err := c.Write(q); err != nil {
			return err
		}
		resp := make([]byte, 1500)
		n, err := c.Read(resp)
		switch {
		case err != nil:
			return err
		case n < 12 || resp[0] != 0x75 || resp[1] != 0x6a:
			return errors.New("malformed reply")
		case resp[3]&0x0f != 0:
			return fmt.Errorf("rcode %d", resp[3]&0x0f)
		case binary.BigEndian.Uint16(resp[6:8]) == 0:
			return errors.New("no answers")
		}
		return nil
	})
}

// BlockLogRunning reports whether the NFLOG listener is attached.
func (e *Egress) BlockLogRunning() bool { return e.blocked != nil }

// IPv6Disabled reports whether IPv6 is off in the egress namespace.
func (e *Egress) IPv6Disabled(ctx context.Context) bool {
	out, err := in(ctx, EgressNS, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")
	return err == nil && strings.TrimSpace(out) == "1"
}

// VMNamespaces lists the VM namespaces that currently exist.
func VMNamespaces(ctx context.Context) ([]string, error) {
	names, err := namespaces(ctx)
	if err != nil {
		return nil, err
	}
	var vms []string
	for _, n := range names {
		if strings.HasPrefix(n, VMPrefix) {
			vms = append(vms, n)
		}
	}
	return vms, nil
}
