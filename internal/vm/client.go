// Package vm runs Firecracker microVMs: a hand-written client for the Firecracker API over its
// Unix socket (ADR 0011) and the VMM process lifecycle. Types follow firecracker_spec-v1.17.0.yaml,
// limited to the fields urljail uses.
package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to one Firecracker process's API socket.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the API socket at sock.
func NewClient(sock string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: 10 * time.Second}}
}

// APIError is a non-2xx response from Firecracker.
type APIError struct {
	Path   string
	Status int
	Fault  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("firecracker %s: %d %s", e.Path, e.Status, e.Fault)
}

func (c *Client) put(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodPut, path, body)
}

func (c *Client) do(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var fault struct {
		FaultMessage string `json:"fault_message"`
	}
	if json.Unmarshal(raw, &fault) != nil || fault.FaultMessage == "" {
		fault.FaultMessage = string(raw)
	}
	return &APIError{Path: method + " " + path, Status: resp.StatusCode, Fault: fault.FaultMessage}
}

// Logger is PUT /logger.
type Logger struct {
	LogPath   string `json:"log_path"`
	Level     string `json:"level,omitempty"`
	ShowLevel bool   `json:"show_level,omitempty"`
}

// BootSource is PUT /boot-source.
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
}

// TokenBucket refills Size tokens every RefillTime milliseconds.
type TokenBucket struct {
	Size       int64 `json:"size"`
	RefillTime int64 `json:"refill_time"`
}

// RateLimiter bounds a device's bytes/s (Bandwidth) and operations/s (Ops).
type RateLimiter struct {
	Bandwidth *TokenBucket `json:"bandwidth,omitempty"`
	Ops       *TokenBucket `json:"ops,omitempty"`
}

// Drive is PUT /drives/{drive_id}.
type Drive struct {
	DriveID      string       `json:"drive_id"`
	PathOnHost   string       `json:"path_on_host"`
	IsRootDevice bool         `json:"is_root_device"`
	IsReadOnly   bool         `json:"is_read_only"`
	RateLimiter  *RateLimiter `json:"rate_limiter,omitempty"`
}

// NetworkInterface is PUT /network-interfaces/{iface_id}. Rx is what the guest receives,
// Tx what it sends.
type NetworkInterface struct {
	IfaceID       string       `json:"iface_id"`
	GuestMAC      string       `json:"guest_mac,omitempty"`
	HostDevName   string       `json:"host_dev_name"`
	RxRateLimiter *RateLimiter `json:"rx_rate_limiter,omitempty"`
	TxRateLimiter *RateLimiter `json:"tx_rate_limiter,omitempty"`
}

// VMConfig is the part of GET /vm/config urljail checks.
type VMConfig struct {
	Drives            []Drive            `json:"drives"`
	NetworkInterfaces []NetworkInterface `json:"network-interfaces"`
}

// GetVMConfig is GET /vm/config: the configuration the VMM is actually running with.
func (c *Client) GetVMConfig(ctx context.Context) (VMConfig, error) {
	var cfg VMConfig
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/vm/config", nil)
	if err != nil {
		return cfg, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return cfg, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("firecracker GET /vm/config: %d", resp.StatusCode)
	}
	return cfg, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg)
}

// MachineConfig is PUT /machine-config.
type MachineConfig struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

// Vsock is PUT /vsock.
type Vsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

func (c *Client) PutLogger(ctx context.Context, l Logger) error { return c.put(ctx, "/logger", l) }

func (c *Client) PutBootSource(ctx context.Context, b BootSource) error {
	return c.put(ctx, "/boot-source", b)
}

func (c *Client) PutDrive(ctx context.Context, d Drive) error {
	return c.put(ctx, "/drives/"+d.DriveID, d)
}

func (c *Client) PutNetworkInterface(ctx context.Context, n NetworkInterface) error {
	return c.put(ctx, "/network-interfaces/"+n.IfaceID, n)
}

func (c *Client) PutMachineConfig(ctx context.Context, m MachineConfig) error {
	return c.put(ctx, "/machine-config", m)
}

func (c *Client) PutVsock(ctx context.Context, v Vsock) error { return c.put(ctx, "/vsock", v) }

// Action is PUT /actions: "InstanceStart", "SendCtrlAltDel" or "FlushMetrics".
func (c *Client) Action(ctx context.Context, action string) error {
	return c.put(ctx, "/actions", struct {
		ActionType string `json:"action_type"`
	}{action})
}

// SetState is PATCH /vm: "Paused" or "Resumed".
func (c *Client) SetState(ctx context.Context, state string) error {
	return c.do(ctx, http.MethodPatch, "/vm", struct {
		State string `json:"state"`
	}{state})
}

// CreateSnapshot is PUT /snapshot/create (a full snapshot of a paused VM).
func (c *Client) CreateSnapshot(ctx context.Context, vmstate, mem string) error {
	return c.put(ctx, "/snapshot/create", struct {
		SnapshotType string `json:"snapshot_type"`
		SnapshotPath string `json:"snapshot_path"`
		MemFilePath  string `json:"mem_file_path"`
	}{"Full", vmstate, mem})
}

// LoadSnapshot is PUT /snapshot/load.
type LoadSnapshot struct {
	SnapshotPath string `json:"snapshot_path"`
	MemBackend   struct {
		BackendType string `json:"backend_type"`
		BackendPath string `json:"backend_path"`
	} `json:"mem_backend"`
	ResumeVM      bool `json:"resume_vm"`
	ClockRealtime bool `json:"clock_realtime"`
	VsockOverride *struct {
		UDSPath string `json:"uds_path"`
	} `json:"vsock_override,omitempty"`
}

func (c *Client) LoadSnapshot(ctx context.Context, l LoadSnapshot) error {
	return c.put(ctx, "/snapshot/load", l)
}
