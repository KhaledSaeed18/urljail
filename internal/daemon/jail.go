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

	// cgroupParent is /sys/fs/cgroup/urljail; the jailer creates one child per VM.
	cgroupParent = "urljail"
	jailNoFile   = 1024
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
		ParentCgroup: cgroupParent,
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

	parent := filepath.Join("/sys/fs/cgroup", cgroupParent)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("cgroup: %w", err)
	}
	// Every jailed VMM lives in a child cgroup: kill what a crashed daemon left there, then
	// remove the cgroups.
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
	if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0); err != nil {
		return fmt.Errorf("cgroup: delegating controllers: %w", err)
	}
	return nil
}
