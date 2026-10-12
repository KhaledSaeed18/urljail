package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/policy"
)

// startServer serves a daemon on a real Unix socket and returns a client for it.
func startServer(t *testing.T) daemonv1.DaemonServiceClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	daemonv1.RegisterDaemonServiceServer(gs, New(Config{
		Policy:         policy.Policy{Mode: policy.EgressDev, Allowlist: policy.DefaultDevAllowlist},
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     time.Minute,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))
	go gs.Serve(l)
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return daemonv1.NewDaemonServiceClient(conn)
}

func TestSocketPermissions(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket mode %v, want no group/other access", perm)
	}
	if _, err := Listen(sock); err == nil || !strings.Contains(err.Error(), "listening") {
		t.Fatalf("second Listen = %v, want 'another urljaild is listening'", err)
	}
}

func TestDetonateStates(t *testing.T) {
	c := startServer(t)
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{"refused by dev allowlist", "https://evil.test/", "not on the allowlist"},
		{"bad scheme", "file:///etc/passwd", "scheme"},
		{"allowlisted passes preflight", "https://example.com/", "no VM backend"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, err := c.Detonate(ctx, &daemonv1.DetonateRequest{Url: tt.url})
			if err != nil {
				t.Fatal(err)
			}
			var states []daemonv1.RunState
			var last *daemonv1.DetonateResponse
			for {
				m, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				states = append(states, m.GetState())
				last = m
			}
			want := []daemonv1.RunState{
				daemonv1.RunState_RUN_STATE_REQUESTED,
				daemonv1.RunState_RUN_STATE_PREFLIGHT,
				daemonv1.RunState_RUN_STATE_FAILED,
			}
			if len(states) != len(want) {
				t.Fatalf("states %v, want %v", states, want)
			}
			for i := range want {
				if states[i] != want[i] {
					t.Fatalf("states %v, want %v", states, want)
				}
			}
			if !strings.Contains(last.GetError(), tt.wantErr) {
				t.Fatalf("error %q, want it to contain %q", last.GetError(), tt.wantErr)
			}
			if last.GetRunId() == "" {
				t.Fatal("no run id")
			}
		})
	}
}
