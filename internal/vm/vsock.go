package vm

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// GuestCID is the guest's vsock context ID. Every VM has its own Unix socket on the host,
// so all of them can use the same CID.
const GuestCID = 3

// DialVsock opens a host-initiated vsock connection to port in the guest, through
// Firecracker's Unix socket: send "CONNECT <port>\n", expect "OK <host_port>\n" (ADR 0007).
// After the handshake the connection is a plain byte stream.
func DialVsock(ctx context.Context, uds string, port uint32) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", uds)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if _, err := fmt.Fprintf(c, "CONNECT %d\n", port); err != nil {
		c.Close()
		return nil, err
	}
	// Read the reply one byte at a time: a buffered reader could swallow the first bytes
	// of the stream that follows.
	var line []byte
	b := make([]byte, 1)
	for len(line) < 64 {
		if _, err := c.Read(b); err != nil {
			c.Close()
			return nil, fmt.Errorf("vsock handshake: %w", err)
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	if !strings.HasPrefix(string(line), "OK ") {
		c.Close()
		return nil, fmt.Errorf("vsock handshake: unexpected reply %q", line)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
