// Package hostnet sets up dev-mode networking on the host, the Go version of scripts/p1:
// one user-owned TAP per VM, NAT out through the host's default zone, and an exception in
// Docker's leftover FORWARD drop. There is no isolation here; per-VM network namespaces
// replace it in P3 (docs/network.md).
//
// Privileged steps go through `sudo -n` for ip, firewall-cmd and nft only, matching the
// dev sudoers rule (docs/threat-model.md).
package hostnet

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// TapPrefix names every TAP urljaild creates, so leftovers can be found and removed.
const TapPrefix = "uj"

// tag marks nft rules created by urljaild.
const tag = "urljaild"

// Egress is the host-wide part of dev egress, set up once per daemon.
type Egress struct {
	log        *slog.Logger
	firewalld  bool
	zone       string
	addedMasq  bool
	dockerUser bool
}

// Up prepares host-wide dev egress. Close undoes exactly what Up changed.
func Up(ctx context.Context, log *slog.Logger) (*Egress, error) {
	e := &Egress{log: log}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(b)) != "1" {
		if err := sudo(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return nil, err
		}
	}

	if exec.CommandContext(ctx, "systemctl", "is-active", "-q", "firewalld").Run() == nil {
		e.firewalld = true
		zone, err := sudoOut(ctx, "firewall-cmd", "--get-default-zone")
		if err != nil {
			return nil, err
		}
		e.zone = zone
		if sudo(ctx, "firewall-cmd", "-q", "--zone="+zone, "--query-masquerade") != nil {
			if err := sudo(ctx, "firewall-cmd", "-q", "--zone="+zone, "--add-masquerade"); err != nil {
				return nil, err
			}
			e.addedMasq = true
		}
	}

	// Docker's ip filter FORWARD chain (policy drop) stays loaded even with Docker stopped.
	if sudo(ctx, "nft", "list", "chain", "ip", "filter", "DOCKER-USER") == nil {
		e.dockerUser = true
		e.deleteDockerRules(ctx) // leftovers from a crashed daemon
		for _, rule := range [][]string{
			{"iifname", TapPrefix + "*", "counter", "accept"},
			{"oifname", TapPrefix + "*", "ct", "state", "related,established", "counter", "accept"},
		} {
			args := append([]string{"add", "rule", "ip", "filter", "DOCKER-USER"}, rule...)
			args = append(args, "comment", `"`+tag+`"`)
			if err := sudo(ctx, "nft", args...); err != nil {
				e.Close(ctx)
				return nil, err
			}
		}
	}
	log.Info("dev egress up", "firewalld", e.firewalld, "zone", e.zone, "added_masquerade", e.addedMasq, "docker_user", e.dockerUser)
	return e, nil
}

// Close removes the host-wide changes made by Up.
func (e *Egress) Close(ctx context.Context) {
	if e.dockerUser {
		e.deleteDockerRules(ctx)
	}
	if e.addedMasq {
		if err := sudo(ctx, "firewall-cmd", "-q", "--zone="+e.zone, "--remove-masquerade"); err != nil {
			e.log.Warn("removing masquerade", "err", err)
		}
	}
	e.log.Info("dev egress down")
}

func (e *Egress) deleteDockerRules(ctx context.Context) {
	out, err := sudoOut(ctx, "nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`+tag+`"`) {
			continue
		}
		if i := strings.LastIndex(line, "# handle "); i >= 0 {
			h := strings.TrimSpace(line[i+len("# handle "):])
			if err := sudo(ctx, "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", h); err != nil {
				e.log.Warn("deleting DOCKER-USER rule", "handle", h, "err", err)
			}
		}
	}
}

// Tap is one VM's network: a /30 with the host at .1 and the guest at .2.
type Tap struct {
	Name     string
	HostIP   string
	GuestIP  string
	GuestMAC string
}

// TapFor returns the addressing for run slot n (0–255): 172.16.n.0/30.
// The MAC encodes the guest IP the way Firecracker's CI rootfs expects (06:00:<ip bytes>).
func TapFor(n int) Tap {
	return Tap{
		Name:     fmt.Sprintf("%s%d", TapPrefix, n),
		HostIP:   fmt.Sprintf("172.16.%d.1", n),
		GuestIP:  fmt.Sprintf("172.16.%d.2", n),
		GuestMAC: fmt.Sprintf("06:00:AC:10:%02X:02", n),
	}
}

// BootArgs is the kernel ip= argument that configures the guest's address and gateway.
func (t Tap) BootArgs() string {
	return fmt.Sprintf("ip=%s::%s:255.255.255.252::eth0:off", t.GuestIP, t.HostIP)
}

// AddTap creates t owned by the current user, so Firecracker can open it without root.
func (e *Egress) AddTap(ctx context.Context, t Tap) error {
	// The slot is ours, so a TAP with its name is a leftover from a failed teardown.
	if exec.CommandContext(ctx, "ip", "link", "show", t.Name).Run() == nil {
		e.log.Warn("removing stale tap", "tap", t.Name)
		e.RemoveTap(ctx, t.Name)
	}
	user := fmt.Sprint(os.Getuid())
	steps := [][]string{
		{"ip", "tuntap", "add", "dev", t.Name, "mode", "tap", "user", user, "group", fmt.Sprint(os.Getgid())},
		{"ip", "addr", "add", t.HostIP + "/30", "dev", t.Name},
		{"ip", "link", "set", t.Name, "up"},
	}
	if e.firewalld {
		// trusted also lets the guest reach the host and LAN: dev mode only (P3 replaces this).
		steps = append(steps, []string{"firewall-cmd", "-q", "--zone=trusted", "--add-interface=" + t.Name})
	}
	for _, s := range steps {
		if err := sudo(ctx, s[0], s[1:]...); err != nil {
			e.RemoveTap(ctx, t.Name)
			return err
		}
	}
	return nil
}

// RemoveTap deletes a TAP and its firewalld zone binding. Missing pieces are ignored.
func (e *Egress) RemoveTap(ctx context.Context, name string) {
	if e.firewalld && sudo(ctx, "firewall-cmd", "-q", "--zone=trusted", "--query-interface="+name) == nil {
		if err := sudo(ctx, "firewall-cmd", "-q", "--zone=trusted", "--remove-interface="+name); err != nil {
			e.log.Warn("firewalld remove-interface", "tap", name, "err", err)
		}
	}
	if exec.CommandContext(ctx, "ip", "link", "show", name).Run() == nil {
		if err := sudo(ctx, "ip", "link", "del", name); err != nil {
			e.log.Warn("deleting tap", "tap", name, "err", err)
		}
	}
}

// LeftoverTaps lists TAPs with urljaild's prefix, e.g. from a crashed daemon.
func LeftoverTaps(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-o", "link", "show", "type", "tun").Output()
	if err != nil {
		return nil, err
	}
	var taps []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line) // "12: uj0: <...>"
		if len(f) >= 2 {
			name := strings.TrimSuffix(f[1], ":")
			if strings.HasPrefix(name, TapPrefix) {
				taps = append(taps, name)
			}
		}
	}
	return taps, nil
}

func sudo(ctx context.Context, name string, args ...string) error {
	_, err := sudoOut(ctx, name, args...)
	return err
}

func sudoOut(ctx context.Context, name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sudo", append([]string{"-n", name}, args...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("sudo %s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
