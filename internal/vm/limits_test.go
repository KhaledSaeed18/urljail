package vm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// fakeVMM serves GET /vm/config with cfg on a Unix socket.
func fakeVMM(t *testing.T, cfg VMConfig) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "fc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(cfg)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestVerifyLimits(t *testing.T) {
	limit := &RateLimiter{Bandwidth: &TokenBucket{Size: 2 << 20, RefillTime: 100}, Ops: &TokenBucket{Size: 2000, RefillTime: 100}}
	want := Config{NetRx: limit, NetTx: limit, Disk: limit}
	limited := VMConfig{
		Drives:            []Drive{{DriveID: "rootfs", RateLimiter: limit}},
		NetworkInterfaces: []NetworkInterface{{IfaceID: "net1", RxRateLimiter: limit, TxRateLimiter: limit}},
	}
	other := &RateLimiter{Bandwidth: &TokenBucket{Size: 1, RefillTime: 100}}
	cases := []struct {
		name string
		got  VMConfig
		ok   bool
	}{
		{"all limited", limited, true},
		{"network tx missing", VMConfig{Drives: limited.Drives,
			NetworkInterfaces: []NetworkInterface{{IfaceID: "net1", RxRateLimiter: limit}}}, false},
		{"disk different", VMConfig{NetworkInterfaces: limited.NetworkInterfaces,
			Drives: []Drive{{DriveID: "rootfs", RateLimiter: other}}}, false},
		{"no devices", VMConfig{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Machine{cfg: want, client: NewClient(fakeVMM(t, c.got))}
			err := m.VerifyLimits(context.Background())
			if c.ok != (err == nil) {
				t.Fatalf("VerifyLimits = %v, want ok=%v", err, c.ok)
			}
		})
	}
}
