package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	daemonv1 "github.com/KhaledSaeed18/urljail/gen/urljail/daemon/v1"
	"github.com/KhaledSaeed18/urljail/internal/capture"
	"github.com/KhaledSaeed18/urljail/internal/netns"
)

// Doctor implements DaemonService.Doctor.
func (s *Server) Doctor(ctx context.Context, _ *daemonv1.DoctorRequest) (*daemonv1.DoctorResponse, error) {
	out := &daemonv1.DoctorResponse{Healthy: true}
	add := func(name, result, observed string) {
		out.Checks = append(out.Checks, &daemonv1.Check{Name: name, Result: result, Observed: observed})
		if result == "fail" {
			out.Healthy = false
		}
	}
	okOr := func(name string, err error, okMsg string) {
		if err != nil {
			add(name, "fail", err.Error())
		} else {
			add(name, "ok", okMsg)
		}
	}

	// The VM layer.
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		add("KVM", "fail", err.Error())
	} else {
		f.Close()
		add("KVM", "ok", "/dev/kvm usable")
	}
	add("Firecracker", "ok", s.cfg.FirecrackerVersion+" ("+s.cfg.Firecracker+")")
	img := s.cfg.Image
	if sum, err := fileSHA256(img.Rootfs); err != nil {
		add("Guest image", "fail", err.Error())
	} else if sum != img.Manifest.RootfsSHA256 {
		add("Guest image", "fail", fmt.Sprintf("%s: rootfs SHA-256 %.12s doesn't match the manifest's %.12s", img.Manifest.Name, sum, img.Manifest.RootfsSHA256))
	} else {
		add("Guest image", "ok", fmt.Sprintf("%s (Chrome %s), rootfs matches its manifest", img.Manifest.Name, img.Manifest.Browser.Version))
	}

	// The network layer.
	switch {
	case s.net == nil:
		add("Egress", "fail", "egress mode off: no network for VMs")
	default:
		okOr("Rulesets and resolver", s.net.Verify(ctx, 0), "egress ruleset matches its loaded hash; resolver running")
		okOr("Resolver answers", s.net.CheckResolver("example.com"), "example.com resolved through the exit")
		okOr("Internet through the exit", s.net.CheckExit("1.1.1.1:53"), "TCP 1.1.1.1:53 from the egress namespace (the resolver's upstream path)")
		if s.net.BlockLogRunning() {
			add("Blocked-attempt log", "ok", "NFLOG listener attached")
		} else {
			add("Blocked-attempt log", "fail", "NFLOG listener not running")
		}
		if s.net.IPv6Disabled(ctx) {
			add("IPv6", "ok", "disabled in the egress namespace")
		} else {
			add("IPv6", "fail", "enabled in the egress namespace")
		}
	}
	add("Egress mode", "warn", string(s.cfg.Policy.Mode)+": guests leave from the home IP; allowlisted benign URLs only")

	// Capture.
	if err := capture.Supported(); err != nil {
		add("eBPF", "fail", err.Error())
	} else if rel := kernelRelease(); !atLeast(rel, 6, 6) {
		add("eBPF", "fail", "kernel "+rel+": TCX needs Linux 6.6+")
	} else {
		add("eBPF", "ok", "kernel "+kernelRelease()+" with BTF")
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		add("Packet capture", "fail", "tcpdump not installed")
	} else {
		add("Packet capture", "ok", "tcpdump available")
	}

	// The host around it.
	if out, err := exec.CommandContext(ctx, "nft", "list", "chain", "ip", "filter", "FORWARD").Output(); err == nil {
		state := "loaded"
		if strings.Contains(string(out), "policy drop") {
			state = "loaded with FORWARD policy drop"
		}
		add("Docker firewall", "warn", state+" (even if Docker is stopped); urljaild adds tagged DOCKER-USER exceptions for its exit")
	} else {
		add("Docker firewall", "ok", "no Docker tables")
	}
	if exec.CommandContext(ctx, "systemctl", "is-active", "-q", "firewalld").Run() == nil {
		add("firewalld", "ok", "running; urljaild's exit is in the trusted zone while it runs")
	} else {
		add("firewalld", "ok", "not running")
	}
	switch b, err := os.ReadFile("/sys/fs/selinux/enforce"); {
	case err != nil:
		add("SELinux", "warn", "not available")
	case strings.TrimSpace(string(b)) == "1":
		add("SELinux", "ok", "enforcing")
	default:
		add("SELinux", "warn", "permissive")
	}
	if pp := s.cfg.SELinuxModule; pp != "" {
		switch {
		case !moduleLoaded("urljail"):
			add("VMM confinement", "fail", "urljail policy module not loaded")
		case domainPermissive(pp):
			add("VMM confinement", "warn", "urljail_vmm_t is permissive (development): denials are logged, not enforced")
		default:
			add("VMM confinement", "ok", "VMMs run confined in urljail_vmm_t")
		}
		if avcs, err := urljailAVCs(s.cfg.Started); err != nil {
			add("SELinux denials", "warn", err.Error())
		} else if len(avcs) == 0 {
			add("SELinux denials", "ok", "none for urljail types since the daemon started")
		} else {
			add("SELinux denials", "warn", fmt.Sprintf("%d kinds since the daemon started:\n    %s", len(avcs), strings.Join(avcs, "\n    ")))
		}
	}
	// No VMM may run outside a jail: check every Firecracker process on the host.
	var unjailed []string
	vmms := allVMMs()
	for _, pid := range vmms {
		c, err := readConfinement(pid)
		if err != nil {
			continue // exited meanwhile
		}
		if bad := c.check(-1, "", s.cfg.SELinuxModule != ""); bad != "" {
			unjailed = append(unjailed, fmt.Sprintf("pid %d: %s", pid, bad))
		}
	}
	if len(unjailed) > 0 {
		add("VMMs jailed", "fail", strings.Join(unjailed, "; "))
	} else {
		add("VMMs jailed", "ok", fmt.Sprintf("%d Firecracker processes on the host, all jailed and confined", len(vmms)))
	}
	if vms, err := netns.VMNamespaces(ctx); err != nil {
		add("Leftovers", "warn", err.Error())
	} else if n := s.slots.inUse(); len(vms) > n {
		add("Leftovers", "warn", fmt.Sprintf("%d VM namespaces for %d running VMs: %v", len(vms), n, vms))
	} else {
		add("Leftovers", "ok", fmt.Sprintf("%d VM namespaces, %d running VMs", len(vms), n))
	}
	if _, err := os.Stat("/etc/sudoers.d/urljail-dev"); err == nil {
		add("Dev sudo rule", "warn", "/etc/sudoers.d/urljail-dev is root-equivalent: remove before the live gate")
	} else {
		add("Dev sudo rule", "ok", "not installed")
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

func atLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, _ := strconv.Atoi(parts[0])
	mi, _ := strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	return ma > major || ma == major && mi >= minor
}
