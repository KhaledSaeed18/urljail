package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Jail runs the VMM under Firecracker's jailer (P5): its own chroot, mount and PID namespace,
// network namespace, cgroup v2 limits and an unprivileged uid/gid, with Firecracker's built-in
// seccomp filters. Resources reach it only as files placed in the chroot.
type Jail struct {
	Jailer   string // jailer binary
	ExecFile string // firecracker binary (its file name names the chroot directory)
	BaseDir  string // chroot base; root-owned, on the same filesystem as images and snapshots
	ID       string // unique per running VM; keep it short (socket paths are limited to 108 bytes)
	UID, GID int
	NetNS    string // network namespace name (/run/netns/<name>)

	ParentCgroup string            // under /sys/fs/cgroup; must exist with controllers delegated
	Cgroups      map[string]string // e.g. memory.max, pids.max, cpu.max
	NoFile       int               // RLIMIT_NOFILE for the VMM
}

// Chroot is the jail's root directory on the host.
func (j *Jail) Chroot() string {
	return filepath.Join(j.BaseDir, filepath.Base(j.ExecFile), j.ID, "root")
}

// Path is a file inside the jail, as the host sees it.
func (j *Jail) Path(name string) string { return filepath.Join(j.Chroot(), name) }

// Prepare creates an empty chroot for a new VM (removing a leftover one with the same ID).
func (j *Jail) Prepare() error {
	if err := os.RemoveAll(filepath.Dir(j.Chroot())); err != nil {
		return err
	}
	return os.MkdirAll(j.Chroot(), 0o700)
}

// Link hard-links a host file into the chroot as name. Hard links keep page-cache sharing
// (snapshot memory, kernel) and need the chroot on the same filesystem.
func (j *Jail) Link(src, name string) error {
	dst := j.Path(name)
	_ = os.Remove(dst)
	if err := os.Link(src, dst); err != nil {
		return fmt.Errorf("linking %s into the jail: %w", src, err)
	}
	return nil
}

// Remove deletes the jail directory and the VM's cgroup. Call it after the VMM has exited.
func (j *Jail) Remove() error {
	err := os.RemoveAll(filepath.Dir(j.Chroot()))
	if j.ParentCgroup != "" {
		_ = os.Remove(filepath.Join("/sys/fs/cgroup", j.ParentCgroup, j.ID)) // rmdir of an empty cgroup
	}
	return err
}

// args is the jailer command line, followed by Firecracker's own arguments.
func (j *Jail) args(fcArgs []string) []string {
	a := []string{
		"--id", j.ID,
		"--exec-file", j.ExecFile,
		"--uid", strconv.Itoa(j.UID), "--gid", strconv.Itoa(j.GID),
		"--chroot-base-dir", j.BaseDir,
		"--cgroup-version", "2",
	}
	if j.NetNS != "" {
		a = append(a, "--netns", filepath.Join("/run/netns", j.NetNS))
	}
	if j.ParentCgroup != "" {
		a = append(a, "--parent-cgroup", j.ParentCgroup)
	}
	for k, v := range j.Cgroups {
		a = append(a, "--cgroup", k+"="+v)
	}
	if j.NoFile > 0 {
		a = append(a, "--resource-limit", "no-file="+strconv.Itoa(j.NoFile))
	}
	return append(append(a, "--"), fcArgs...)
}
