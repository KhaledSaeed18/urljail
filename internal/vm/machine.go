package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Config describes one microVM.
type Config struct {
	Firecracker string // path to the firecracker binary
	Socket      string // API socket path (keep it short: Unix socket paths are limited to 108 bytes)
	LogDir      string // receives serial.log and firecracker.log

	Kernel   string
	BootArgs string
	Rootfs   string // writable, owned by this VM alone

	TapName  string // empty: no network card
	GuestMAC string

	VCPUs  int
	MemMiB int
}

// Machine is a running Firecracker process.
type Machine struct {
	cfg    Config
	cmd    *exec.Cmd
	client *Client
	done   chan struct{}
	err    error // set before done is closed
}

// Start launches Firecracker, configures the VM over the API and boots it.
// On error, nothing is left running.
func Start(ctx context.Context, cfg Config) (*Machine, error) {
	if err := os.MkdirAll(cfg.LogDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(cfg.Socket)

	serial, err := os.OpenFile(filepath.Join(cfg.LogDir, "serial.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer serial.Close() // the child keeps its own copy of the fd

	fcLog := filepath.Join(cfg.LogDir, "firecracker.log")
	if err := os.WriteFile(fcLog, nil, 0o600); err != nil {
		return nil, err
	}

	cmd := exec.Command(cfg.Firecracker, "--api-sock", cfg.Socket, "--enable-pci")
	cmd.Stdout, cmd.Stderr = serial, serial // the guest's serial console
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // signals to the daemon's terminal don't reach the VMM; the daemon decides
		// If the daemon dies, its VMMs die with it. Linux ties this to the forking OS thread,
		// not the process, so it's a first line only; Reap at daemon start is the backstop.
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting firecracker: %w", err)
	}
	m := &Machine{cfg: cfg, cmd: cmd, client: NewClient(cfg.Socket), done: make(chan struct{})}
	go func() {
		m.err = cmd.Wait() // Go tracks the child with a pidfd on Linux, so Kill can't hit a reused PID
		close(m.done)
	}()

	if err := m.configure(ctx, fcLog); err != nil {
		m.Kill()
		return nil, err
	}
	return m, nil
}

func (m *Machine) configure(ctx context.Context, fcLog string) error {
	if err := m.waitSocket(ctx); err != nil {
		return err
	}
	c, cfg := m.client, m.cfg
	steps := []func() error{
		func() error { return c.PutLogger(ctx, Logger{LogPath: fcLog, Level: "Info", ShowLevel: true}) },
		func() error {
			return c.PutBootSource(ctx, BootSource{KernelImagePath: cfg.Kernel, BootArgs: cfg.BootArgs})
		},
		func() error {
			return c.PutDrive(ctx, Drive{DriveID: "rootfs", PathOnHost: cfg.Rootfs, IsRootDevice: true})
		},
		func() error {
			if cfg.TapName == "" {
				return nil
			}
			return c.PutNetworkInterface(ctx, NetworkInterface{IfaceID: "net1", GuestMAC: cfg.GuestMAC, HostDevName: cfg.TapName})
		},
		func() error {
			return c.PutMachineConfig(ctx, MachineConfig{VCPUCount: cfg.VCPUs, MemSizeMiB: cfg.MemMiB})
		},
		func() error { return c.Action(ctx, "InstanceStart") },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) waitSocket(ctx context.Context) error {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(m.cfg.Socket); err == nil {
			return nil
		}
		select {
		case <-m.done:
			return fmt.Errorf("firecracker exited before its API socket appeared: %v (see %s)", m.err, filepath.Join(m.cfg.LogDir, "serial.log"))
		case <-deadline:
			return errors.New("firecracker API socket didn't appear within 5s")
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Done is closed when the VMM process has exited (guest shutdown, panic, or kill).
func (m *Machine) Done() <-chan struct{} { return m.done }

// PID is the VMM's process ID.
func (m *Machine) PID() int { return m.cmd.Process.Pid }

// Shutdown asks the guest to shut down (Ctrl-Alt-Del; with reboot=k Firecracker then exits)
// and kills the VMM if it hasn't exited by the time ctx ends.
func (m *Machine) Shutdown(ctx context.Context) error {
	select {
	case <-m.done:
	default:
		_ = m.client.Action(ctx, "SendCtrlAltDel")
		select {
		case <-m.done:
		case <-ctx.Done():
			m.Kill()
		}
	}
	_ = os.Remove(m.cfg.Socket)
	return nil
}

// Kill stops the VMM immediately and waits for it to exit.
func (m *Machine) Kill() {
	_ = m.cmd.Process.Kill()
	<-m.done
	_ = os.Remove(m.cfg.Socket)
}
