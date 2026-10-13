package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KhaledSaeed18/urljail/internal/vm"
)

const (
	// Each VM slot's VMM runs as its own uid (jailUIDBase+slot), not the operator: a VMM escape
	// lands in an account that owns nothing outside its jail. The snapshot builder gets
	// jailUIDBase+99. All share jailGID, which may read the snapshot's files.
	jailUIDBase = 64000
	jailGID     = 64000
	buildSlot   = 99

	// DevCgroupParent holds the VM cgroups when the daemon doesn't run as a systemd service
	// with a delegated cgroup (development); the jailer creates one child per VM.
	DevCgroupParent = "urljail"
	jailNoFile      = 1024
)

func jailUID(slot int) int { return jailUIDBase + slot }

// jailFor describes the jail of one VM. id must be unique among running VMs and short.
func (s *Server) jailFor(id string, slot int, ns string) *vm.Jail {
	return &vm.Jail{
		Jailer:       s.cfg.Jailer,
		ExecFile:     s.cfg.Firecracker,
		BaseDir:      s.cfg.JailDir,
		ID:           id,
		UID:          jailUID(slot),
		GID:          jailGID,
		NetNS:        ns,
		ParentCgroup: s.cfg.CgroupParent,
		Cgroups: map[string]string{
			// Guest memory plus room for the VMM itself; the snapshot's shared pages are
			// charged to whichever cgroup first read them.
			"memory.max": strconv.Itoa((s.cfg.MemMiB + 256) << 20),
			"pids.max":   "64",
			"cpu.max":    fmt.Sprintf("%d 100000", s.cfg.VCPUs*100000), // its vCPUs' worth
		},
		NoFile: jailNoFile,
	}
}

// jailID is short because the API socket lives at <jail base>/<exec>/<id>/root/fc.sock.
func jailID(slot int, runID string) string {
	return fmt.Sprintf("s%d-%s", slot, runID[len(runID)-12:])
}

// SetupJails prepares the jail base (root-owned, as the jailer requires) and the delegated
// cgroup parent, and removes jails and cgroups left by a crashed daemon. Call it after Reap.
func SetupJails(cfg Config) error {
	if err := os.MkdirAll(cfg.JailDir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(cfg.JailDir, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(cfg.JailDir, 0o700); err != nil {
		return err
	}
	entries, _ := os.ReadDir(cfg.JailDir)
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(cfg.JailDir, e.Name()))
	}

	parent := filepath.Join("/sys/fs/cgroup", cfg.CgroupParent)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	// Every jailed VMM lives in a child cgroup: kill what a crashed daemon left there, then
	// remove the cgroups. Also in the development location, in case a dev run left VMs.
	reapCgroups(parent)
	if cfg.CgroupParent != DevCgroupParent {
		dev := filepath.Join("/sys/fs/cgroup", DevCgroupParent)
		reapCgroups(dev)
		_ = os.Remove(dev)
	}
	if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0); err != nil {
		return fmt.Errorf("cgroup: delegating controllers: %w", err)
	}
	return nil
}

// reapCgroups kills every process in parent's child cgroups and removes them.
func reapCgroups(parent string) {
	children, _ := os.ReadDir(parent)
	for _, c := range children {
		if !c.IsDir() {
			continue
		}
		dir := filepath.Join(parent, c.Name())
		if b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")); err == nil {
			for _, f := range strings.Fields(string(b)) {
				if pid, err := strconv.Atoi(f); err == nil {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
		for i := 0; i < 50; i++ { // rmdir succeeds once the killed processes are gone
			if err := os.Remove(dir); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// ServiceCgroup sets up the VM cgroup parent inside the daemon's own cgroup when systemd
// delegated it (Delegate= in deploy/urljaild.service): the daemon moves into a "daemon" leaf
// (cgroup v2 allows no processes in a node with enabled controllers) and VMs go under "vms".
// Then stopping the service, or the daemon crashing, takes every VMM with it (threat model:
// "daemon crash leaves live VMs browsing"). It returns the parent relative to
// /sys/fs/cgroup, or DevCgroupParent when the cgroup isn't delegated.
func ServiceCgroup() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	own := strings.TrimPrefix(strings.TrimSpace(string(b)), "0::")
	own = strings.TrimSuffix(own, "/daemon") // a restart within the same cgroup
	if !strings.HasSuffix(own, ".service") {
		return DevCgroupParent, nil
	}
	svc := filepath.Join("/sys/fs/cgroup", own)
	if ctl, err := os.ReadFile(filepath.Join(svc, "cgroup.controllers")); err != nil ||
		!strings.Contains(string(ctl), "memory") || !strings.Contains(string(ctl), "pids") || !strings.Contains(string(ctl), "cpu") {
		return DevCgroupParent, nil // not delegated with the controllers the jails need
	}
	leaf := filepath.Join(svc, "daemon")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return "", fmt.Errorf("moving the daemon into %s: %w", leaf, err)
	}
	if err := os.WriteFile(filepath.Join(svc, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0); err != nil {
		return "", fmt.Errorf("cgroup: enabling controllers in %s: %w", svc, err)
	}
	vms := filepath.Join(own, "vms")
	if err := os.MkdirAll(filepath.Join("/sys/fs/cgroup", vms), 0o755); err != nil {
		return "", err
	}
	return strings.TrimPrefix(vms, "/"), nil
}

// Rate limits for every VM (P5): generous for loading pages, but a hostile guest can't
// saturate the host's network or disk. Token buckets refill every 100 ms.
var (
	netTxLimit = &vm.RateLimiter{ // guest → out: 20 MiB/s, 20k packets/s
		Bandwidth: &vm.TokenBucket{Size: 2 << 20, RefillTime: 100},
		Ops:       &vm.TokenBucket{Size: 2000, RefillTime: 100},
	}
	netRxLimit = &vm.RateLimiter{ // → guest: 40 MiB/s, 40k packets/s
		Bandwidth: &vm.TokenBucket{Size: 4 << 20, RefillTime: 100},
		Ops:       &vm.TokenBucket{Size: 4000, RefillTime: 100},
	}
	diskLimit = &vm.RateLimiter{ // 100 MiB/s, 10k IOPS
		Bandwidth: &vm.TokenBucket{Size: 10 << 20, RefillTime: 100},
		Ops:       &vm.TokenBucket{Size: 1000, RefillTime: 100},
	}
)
