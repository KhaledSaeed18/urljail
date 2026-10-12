package vm

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakeFirecracker accepts one connection, checks the CONNECT line, replies, then echoes.
func fakeFirecracker(t *testing.T, reply string) string {
	t.Helper()
	uds := filepath.Join(t.TempDir(), "v.sock")
	l, err := net.Listen("unix", uds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, _ := r.ReadString('\n')
		if line != "CONNECT 1024\n" {
			return
		}
		// Reply and the first stream bytes in one write, as a real peer might.
		io.WriteString(c, reply+"hello")
		io.Copy(c, r)
	}()
	return uds
}

func TestDialVsock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := DialVsock(ctx, fakeFirecracker(t, "OK 1073741824\n"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("first stream bytes = %q, %v; the handshake must not swallow them", buf, err)
	}
}

func TestDialVsockRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := DialVsock(ctx, fakeFirecracker(t, "NOPE\n"), 1024); err == nil {
		t.Fatal("handshake accepted a non-OK reply")
	}
}
