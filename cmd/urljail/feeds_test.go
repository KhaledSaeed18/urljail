package main

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTransient(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{status.Error(codes.Unavailable, "connection error: dial unix /run/urljail/urljaild.sock: connect: no such file"), true},
		{errors.New("preflight: WireGuard tunnel not healthy (last handshake 3m10s ago, <nil>)"), true},
		{errors.New("all 3 VM slots are busy"), true},
		{errors.New("refused by policy: port 22 is not allowed"), false},
		{errors.New(`unknown profile "x" (have: baseline, stealth)`), false},
		{nil, false},
	} {
		if got := transient(c.err); got != c.want {
			t.Errorf("transient(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
