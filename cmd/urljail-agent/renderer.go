package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto"
	cdpctx "github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/inspector"
	"github.com/chromedp/cdproto/target"
)

// freshRenderer moves the session to a page whose renderer was forked after the restore. A
// renderer from before the snapshot carries its V8 random state in the snapshot: every clone's
// pages replayed the same Math.random() sequence (research R2, 2026-10-19: one Google Analytics
// client ID on two sites hours apart). The kernel reseeds on restore (VMGenID), so a renderer
// forked now seeds itself afresh.
//
// It kills Chrome's renderers (the tab's and any spare), waits until Chrome has seen the tab's
// go, opens a new foreground window, whose renderer is forked now, and drives that one, closing
// the old tab. Reloading the crashed tab in place was tried first and deployed briefly: its
// pages did less (lazy images and analytics hits missing, a third fewer connections; journal
// P7, 2026-10-20).
func (b *browserSession) freshRenderer(ctx context.Context) error {
	pids := rendererPIDs("/proc", b.ch.cmd.Process.Pid)
	if len(pids) == 0 {
		return nil
	}
	pctx := cdpctx.WithExecutor(ctx, b.page)
	// Browser-side only: the Inspector domain lives in the browser process and isn't visible
	// to pages, unlike Runtime (ADR 0013).
	if err := inspector.Enable().Do(pctx); err != nil {
		return fmt.Errorf("inspector: %w", err)
	}
	defer func() { _ = inspector.Disable().Do(pctx) }()
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case m, ok := <-b.ch.conn.Events():
			if !ok {
				return errors.New("chrome exited while its renderers were replaced")
			}
			if m.Method == cdproto.EventInspectorTargetCrashed && m.SessionID == b.page.ID {
				return b.newWindow(ctx)
			}
		case <-timeout.C:
			return fmt.Errorf("chrome didn't report its renderer gone within 5 s (killed %d)", len(pids))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// newWindow opens a foreground window, drives it instead of the current page, and closes the
// current one.
func (b *browserSession) newWindow(ctx context.Context) error {
	bctx := cdpctx.WithExecutor(ctx, b.browser)
	old := b.targetID
	id, err := target.CreateTarget("about:blank").WithNewWindow(true).WithBackground(false).Do(bctx)
	if err != nil {
		return fmt.Errorf("new window: %w", err)
	}
	if err := b.attach(ctx, id); err != nil {
		return err
	}
	return target.CloseTarget(old).Do(bctx)
}

// rendererPIDs lists Chrome's renderer processes: those in Chrome's process group (the agent
// starts it as a group leader) whose command line says --type=renderer.
func rendererPIDs(proc string, chromePID int) []int {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(proc, e.Name(), "cmdline"))
		if err != nil || !slices.Contains(argv(cmdline), "--type=renderer") {
			continue
		}
		if pgrp, ok := processGroup(filepath.Join(proc, e.Name(), "stat")); ok && pgrp == chromePID {
			out = append(out, pid)
		}
	}
	return out
}

// argv splits /proc/<pid>/cmdline. Chrome's zygote rewrites its children's process title into
// one string, arguments separated by spaces (found testing against Chrome 155).
func argv(cmdline []byte) []string {
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(args) == 1 {
		args = strings.Fields(args[0])
	}
	return args
}

// processGroup reads the process group from /proc/<pid>/stat: the fifth field, counted after
// the command name, which may itself hold spaces and parentheses.
func processGroup(statPath string) (int, bool) {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:]) // state ppid pgrp ...
	if len(f) < 3 {
		return 0, false
	}
	pgrp, err := strconv.Atoi(f[2])
	return pgrp, err == nil
}
