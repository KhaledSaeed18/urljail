package netns

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Capture is tcpdump writing everything on a VM's TAP to a pcap file (open question Q5:
// tcpdump first, in-process capture later if needed). It writes raw packets only (-w), so it
// never dissects hostile traffic, and it drops to the operator before opening the file.
type Capture struct {
	cmd       *exec.Cmd
	done      chan struct{}
	summary   []string // tcpdump's closing lines ("N packets captured", "M packets dropped by kernel")
	truncated atomic.Bool
}

// Truncated reports whether the capture was stopped at its size cap.
func (c *Capture) Truncated() bool { return c.truncated.Load() }

// StartCapture starts tcpdump on vm's TAP and returns once it is listening. The capture stops
// at maxPackets packets or maxBytes bytes, whichever comes first.
func StartCapture(vm *VM, path, user string, maxPackets int, maxBytes int64) (*Capture, error) {
	c := &Capture{done: make(chan struct{})}
	c.cmd = exec.Command("ip", "netns", "exec", vm.NS, "tcpdump",
		"-i", TapName, "-n", "-s", "0", "-U", "--immediate-mode",
		"-c", strconv.Itoa(maxPackets), "-Z", user, "-w", path)
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := c.cmd.Start(); err != nil {
		return nil, err
	}
	listening := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, "listening on") {
				close(listening)
				continue
			}
			c.summary = append(c.summary, line)
		}
	}()
	go func() {
		_ = c.cmd.Wait()
		close(c.done)
	}()
	select {
	case <-listening:
		go c.watchSize(path, maxBytes)
		return c, nil
	case <-c.done:
		return nil, errors.New("tcpdump exited at start: " + strings.Join(c.summary, "; "))
	case <-time.After(5 * time.Second):
		c.Stop()
		return nil, errors.New("tcpdump didn't start listening within 5s")
	}
}

// Stop ends the capture (flushing the file) and returns tcpdump's summary lines.
func (c *Capture) Stop() []string {
	select {
	case <-c.done:
	default:
		_ = c.cmd.Process.Signal(syscall.SIGINT)
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.done
		}
	}
	return c.summary
}

// watchSize stops tcpdump once the file passes maxBytes (tcpdump can rotate files, but has no
// "stop after N bytes").
func (c *Capture) watchSize(path string, maxBytes int64) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if fi, err := os.Stat(path); err == nil && fi.Size() >= maxBytes {
				c.truncated.Store(true)
				_ = c.cmd.Process.Signal(syscall.SIGINT)
				return
			}
		}
	}
}
