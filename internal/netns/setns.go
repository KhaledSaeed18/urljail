package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// Do runs fn on an OS thread that has joined network namespace ns. Sockets fn creates
// (netlink, BPF links by ifindex) belong to ns for their lifetime. The thread switches
// back afterwards; if it can't, it stays locked and Go discards it instead of reusing a
// thread that's in the wrong namespace.
func Do(ns string, fn func() error) error {
	target, err := os.Open(filepath.Join("/run/netns", ns))
	if err != nil {
		return err
	}
	defer target.Close()

	runtime.LockOSThread()
	orig, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("setns %s: %w", ns, err)
	}
	fnErr := fn()
	if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("returning from %s: %w (thread retired)", ns, err) // stays locked
	}
	runtime.UnlockOSThread()
	return fnErr
}
