// Command urljail-init is PID 1 in the guest (kernel arg init=/sbin/urljail-init). It mounts the
// pseudo-filesystems, brings up loopback, starts the guest agent as an unprivileged user, reaps
// zombies, and reboots on Ctrl-Alt-Del, which makes Firecracker exit (boot arg reboot=k).
// It never handles page content: that's the agent's job, in a separate unprivileged process.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	agentPath = "/usr/local/bin/urljail-agent"
	agentUID  = 1000 // user "urljail", created in the image
	agentGID  = 1000
)

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "urljail-init: "+format+"\n", args...)
}

func main() {
	if os.Getpid() != 1 {
		logf("must run as PID 1")
		os.Exit(1)
	}
	mountAll()
	_ = unix.Sethostname([]byte("urljail-guest"))
	if err := loopbackUp(); err != nil {
		logf("loopback: %v", err)
	}
	// Turn Ctrl-Alt-Del into SIGINT for PID 1 instead of an immediate kernel reboot,
	// so children get a chance to exit.
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_CAD_OFF)

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGCHLD, syscall.SIGINT, syscall.SIGTERM)

	agent, err := startAgent()
	if err != nil {
		logf("starting agent: %v", err)
		shutdown()
	}
	logf("agent started (pid %d)", agent)

	for sig := range sigs {
		switch sig {
		case syscall.SIGCHLD:
			if reap(agent) {
				logf("agent exited; shutting down")
				shutdown()
			}
		default:
			logf("%v: shutting down", sig)
			shutdown()
		}
	}
}

func mountAll() {
	mounts := []struct {
		src, target, fstype string
		flags               uintptr
		data                string
	}{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", unix.MS_NOSUID | unix.MS_NOEXEC, "gid=5,mode=0620,ptmxmode=0666"},
		{"tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=1777"}, // Chrome needs it
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
		{"tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=1777"},
	}
	for _, m := range mounts {
		_ = os.MkdirAll(m.target, 0o755)
		if err := unix.Mount(m.src, m.target, m.fstype, m.flags, m.data); err != nil && err != unix.EBUSY {
			logf("mount %s: %v", m.target, err)
		}
	}
	// No udev in the guest, so device nodes keep devtmpfs's root-only mode. The agent
	// (unprivileged) needs vsock to reach the host.
	if err := os.Chown("/dev/vsock", 0, agentGID); err != nil {
		logf("chown /dev/vsock: %v", err)
	}
	_ = os.Chmod("/dev/vsock", 0o660)

	// Agent-owned working area: downloads land here and are never executed.
	for _, d := range []string{"/run/urljail", "/run/urljail/downloads"} {
		_ = os.MkdirAll(d, 0o750)
		_ = os.Chown(d, agentUID, agentGID)
	}
	_ = unix.Mount("tmpfs", "/run/urljail/downloads", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC,
		fmt.Sprintf("mode=0750,uid=%d,gid=%d", agentUID, agentGID))
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// startAgent starts the agent without os/exec's Wait: PID 1 reaps every child itself.
func startAgent() (int, error) {
	console, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		console = os.Stdout
	}
	attr := &os.ProcAttr{
		Dir:   "/home/urljail",
		Env:   []string{"HOME=/home/urljail", "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"},
		Files: []*os.File{nil, console, console},
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: agentUID, Gid: agentGID, Groups: []uint32{}},
			Setsid:     true,
		},
	}
	p, err := os.StartProcess(agentPath, []string{agentPath}, attr)
	if err != nil {
		return 0, err
	}
	return p.Pid, nil
}

// reap collects every exited child and reports whether the agent was one of them.
func reap(agent int) bool {
	agentDied := false
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return agentDied
		}
		if pid == agent {
			logf("agent status: %v", ws)
			agentDied = true
		}
	}
}

func shutdown() {
	_ = unix.Kill(-1, unix.SIGTERM)
	time.Sleep(500 * time.Millisecond)
	_ = unix.Kill(-1, unix.SIGKILL)
	unix.Sync()
	// With reboot=k, a guest reboot makes Firecracker exit.
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}
