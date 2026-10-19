package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/browser"
	cdpctx "github.com/chromedp/cdproto/cdp"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/cdp"
)

const runDir = "/run/urljail"

// Variables only so the Chrome integration test can point them elsewhere.
var (
	chromeBin  = "/usr/bin/google-chrome" // Google's wrapper script, as on a real install
	keyLogPath = runDir + "/sslkeys.log"  // TLS keys for offline decryption of the host pcap (ADR 0004)
	chromeLog  = runDir + "/chrome.log"
)

// chromeArgs are the flags for one detonation. Policy (/etc/opt/chrome/policies/managed)
// covers QUIC, ECH, DoH, Safe Browsing and telemetry; flags cover what policy can't.
func chromeArgs(profile string, bp *guestv1.BrowserProfile, browserVersion string) []string {
	args := []string{
		"--remote-debugging-pipe", // CDP on fds 3/4: no debugging port for a page to reach
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--password-store=basic",
		// GCM, component updates and other background requests to Google would add noise to
		// the host's capture. Pages can't observe this flag (docs/guest-image.md).
		"--disable-background-networking",
		"--window-size=1920,1080",
	}
	if bp.GetHeadful() {
		// On Xvfb. Without a GPU, headful Chrome turns WebGL off instead of falling back to
		// SwiftShader as headless does (found in P6 M5); "unsafe" means exposing SwiftShader to
		// pages, which headless already does, inside the disposable VM.
		args = append(args, "--ozone-platform=x11", "--window-position=0,0", "--enable-unsafe-swiftshader")
	} else {
		args = append(args, "--headless=new") // the real browser, not the old headless shell (ADR 0009)
	}
	// The experimental condition (P6). Only flags a page can't see as flags.
	if bp.GetDesktopUserAgent() {
		if ua := desktopUserAgent(browserVersion); ua != "" {
			args = append(args, "--user-agent="+ua)
		}
	}
	if bp.GetHideWebdriver() {
		args = append(args, "--disable-blink-features=AutomationControlled")
	}
	if l := bp.GetLanguage(); validLanguage.MatchString(l) {
		// Like a real install: the regional language, then the base one ("en-US,en"). A
		// single entry is rarer than headless itself (found in P6 M2).
		accept := l
		if base, _, ok := strings.Cut(l, "-"); ok {
			accept += "," + base
		}
		args = append(args, "--lang="+l, "--accept-lang="+accept)
	}
	return append(args, "about:blank")
}

var (
	validLanguage = regexp.MustCompile(`^[a-z]{2,3}(-[A-Z]{2})?$`)
	validTimezone = regexp.MustCompile(`^[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}$`)
)

// desktopUserAgent is the User-Agent Chrome reports when it isn't headless: the reduced form
// with only the major version ("Chrome/155.0.0.0"), as headless reports "HeadlessChrome/...".
func desktopUserAgent(browserVersion string) string {
	major, _, _ := strings.Cut(browserVersion, ".")
	if major == "" || strings.Trim(major, "0123456789") != "" {
		return ""
	}
	return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + major + ".0.0.0 Safari/537.36"
}

// chrome is one running browser with its CDP connection.
type chrome struct {
	xvfb    *exec.Cmd // headful profile only
	cmd     *exec.Cmd
	conn    *cdp.Conn
	profile string
	exited  chan struct{}
}

func launchChrome(bp *guestv1.BrowserProfile, browserVersion string) (*chrome, error) {
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

	var xvfb *exec.Cmd
	if bp.GetHeadful() {
		if xvfb, err = startXvfb(); err != nil {
			return nil, err
		}
	}
	cmd := exec.Command(chromeBin, chromeArgs(profile, bp, browserVersion)...)
	cmd.ExtraFiles = []*os.File{cmdR, outW} // fd 3, fd 4
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = append(os.Environ(), "SSLKEYLOGFILE="+keyLogPath)
	if xvfb != nil {
		cmd.Env = append(cmd.Env, "DISPLAY="+xDisplay)
	}
	if tz := bp.GetTimezone(); validTimezone.MatchString(tz) {
		cmd.Env = append(cmd.Env, "TZ="+tz) // Chrome's ICU has its own zone data
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // so the whole process tree can be killed
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting chrome: %w", err)
	}
	cmdR.Close()
	outW.Close()

	c := &chrome{xvfb: xvfb, cmd: cmd, conn: cdp.New(cmdW, outR), profile: profile, exited: make(chan struct{})}
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
	if c.xvfb != nil {
		_ = c.xvfb.Process.Kill()
		_ = c.xvfb.Wait()
	}
	_ = os.RemoveAll(c.profile)
}

const (
	xDisplay = ":99"
	xSocket  = "/tmp/.X11-unix/X99"
)

// startXvfb starts a virtual display for headful Chrome and waits for its socket. No GPU:
// Chrome renders in software, as headless does.
func startXvfb() (*exec.Cmd, error) {
	cmd := exec.Command("/usr/bin/Xvfb", xDisplay, "-screen", "0", "1920x1080x24", "-nolisten", "tcp", "-noreset")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting Xvfb: %w", err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(xSocket); err == nil {
			return cmd, nil
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return nil, errors.New("Xvfb didn't create its socket within 5 s")
}
