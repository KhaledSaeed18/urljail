package daemon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// confinement is what a VMM process actually runs with, read from /proc.
type confinement struct {
	PID        int
	UID        int
	NoNewPrivs bool
	Seccomp    int // 2: filter mode
	Cgroup     string
	Chrooted   bool // its root isn't the host's
	SELinux    string
}

func readConfinement(pid int) (confinement, error) {
	c := confinement{PID: pid}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return c, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		switch k {
		case "Uid":
			c.UID, _ = strconv.Atoi(f[0])
		case "NoNewPrivs":
			c.NoNewPrivs = f[0] == "1"
		case "Seccomp":
			c.Seccomp, _ = strconv.Atoi(f[0])
		}
	}
	cg, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	c.Cgroup = strings.TrimPrefix(strings.TrimSpace(string(cg)), "0::")
	var host, root syscall.Stat_t
	if syscall.Stat("/", &host) == nil && syscall.Stat(fmt.Sprintf("/proc/%d/root", pid), &root) == nil {
		c.Chrooted = host.Dev != root.Dev || host.Ino != root.Ino
	}
	if ctx, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/current", pid)); err == nil {
		c.SELinux = ctxType(bytes.TrimRight(ctx, "\x00\n"))
	}
	return c, nil
}

// check reports how c falls short of a jailed, confined VMM ("" if it doesn't).
// wantUID < 0 accepts any jail uid; selinux says whether urljail_vmm_t is required.
func (c confinement) check(wantUID int, wantCgroup string, selinux bool) string {
	var bad []string
	switch {
	case wantUID >= 0 && c.UID != wantUID:
		bad = append(bad, fmt.Sprintf("uid %d (want %d)", c.UID, wantUID))
	case c.UID < jailUIDBase || c.UID > jailUIDBase+buildSlot:
		bad = append(bad, fmt.Sprintf("uid %d is not a jail uid", c.UID))
	}
	if !c.NoNewPrivs {
		bad = append(bad, "no_new_privs off")
	}
	if c.Seccomp != 2 {
		bad = append(bad, fmt.Sprintf("seccomp mode %d", c.Seccomp))
	}
	if wantCgroup != "" && c.Cgroup != wantCgroup || !strings.HasPrefix(c.Cgroup, "/"+cgroupParent+"/") {
		bad = append(bad, "cgroup "+c.Cgroup)
	}
	if !c.Chrooted {
		bad = append(bad, "not chrooted")
	}
	if selinux && c.SELinux != "urljail_vmm_t" {
		bad = append(bad, "SELinux domain "+c.SELinux)
	}
	return strings.Join(bad, ", ")
}

func (c confinement) String() string {
	return fmt.Sprintf("pid %d: uid %d, no_new_privs, seccomp filter, cgroup %s, chrooted, %s", c.PID, c.UID, c.Cgroup, c.SELinux)
}

// allVMMs finds every Firecracker process on the host, ours or not, by executable name.
func allVMMs() []int {
	var pids []int
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		exe, err := os.Readlink(filepath.Join(p, "exe"))
		if err != nil {
			continue
		}
		base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		if strings.HasPrefix(base, "firecracker") {
			if pid, err := strconv.Atoi(filepath.Base(p)); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}
