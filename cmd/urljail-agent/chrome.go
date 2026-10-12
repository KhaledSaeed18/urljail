package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/browser"
	cdpctx "github.com/chromedp/cdproto/cdp"

	"github.com/KhaledSaeed18/urljail/internal/cdp"
)

const (
	chromeBin  = "/usr/bin/google-chrome" // Google's wrapper script, as on a real install
	runDir     = "/run/urljail"
	keyLogPath = runDir + "/sslkeys.log" // TLS keys for offline decryption of the host pcap (ADR 0004)
	chromeLog  = runDir + "/chrome.log"
)

// chromeArgs are the flags for one detonation. Policy (/etc/opt/chrome/policies/managed)
// covers QUIC, ECH, DoH, Safe Browsing and telemetry; flags cover what policy can't.
func chromeArgs(profile string) []string {
	return []string{
		"--headless=new",          // the real browser, not the old headless shell (ADR 0009)
		"--remote-debugging-pipe", // CDP on fds 3/4: no debugging port for a page to reach
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--password-store=basic",
		// GCM, component updates and other background requests to Google would add noise to
		// the host's capture. Pages can't observe this flag (docs/guest-image.md).
		"--disable-background-networking",
		"--window-size=1920,1080",
		"about:blank",
	}
}

// chrome is one running browser with its CDP connection.
type chrome struct {
	cmd     *exec.Cmd
	conn    *cdp.Conn
	profile string
	exited  chan struct{}
}

func launchChrome() (*chrome, error) {
	profile, err := os.MkdirTemp("/tmp", "chrome-profile-")
	if err != nil {
		return nil, err
	}
	// Chrome reads commands from fd 3 and writes to fd 4.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	logf, err := os.OpenFile(chromeLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer logf.Close()

	cmd := exec.Command(chromeBin, chromeArgs(profile)...)
	cmd.ExtraFiles = []*os.File{cmdR, outW} // fd 3, fd 4
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), "SSLKEYLOGFILE="+keyLogPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // so the whole process tree can be killed
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting chrome: %w", err)
	}
	cmdR.Close()
	outW.Close()

	c := &chrome{cmd: cmd, conn: cdp.New(cmdW, outR), profile: profile, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		cmdW.Close()
		close(c.exited)
	}()
	return c, nil
}

// close asks Chrome to exit (which flushes the key log), then kills the process group.
func (c *chrome) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = browser.Close().Do(cdpctx.WithExecutor(ctx, c.conn.Browser()))
	select {
	case <-c.exited:
	case <-time.After(3 * time.Second):
	}
	_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
	<-c.exited
	_ = os.RemoveAll(c.profile)
}
