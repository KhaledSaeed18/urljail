package netns

import (
	"context"
	"os/exec"
	"strings"
)

// hostExitUp lets traffic from host-side interface iface out through the host: firewalld must
// forward and NAT it, and Docker's leftover FORWARD drop needs an exception (P1 findings).
// Used for the dev-mode exit (uj-host) and the live-test VPN peer; in live mode traffic
// reaches the host only as WireGuard's own UDP, which needs neither.
func (e *Egress) hostExitUp(ctx context.Context, iface string) error {
	e.hostIfaces = append(e.hostIfaces, iface)
	if exec.CommandContext(ctx, "systemctl", "is-active", "-q", "firewalld").Run() == nil {
		e.firewalld = true
		if e.zone == "" {
			zone, err := run(ctx, nil, "firewall-cmd", "--get-default-zone")
			if err != nil {
				return err
			}
			e.zone = zone
		}
		if _, err := run(ctx, nil, "firewall-cmd", "-q", "--zone=trusted", "--add-interface="+iface); err != nil {
			return err
		}
		if _, err := run(ctx, nil, "firewall-cmd", "-q", "--zone="+e.zone, "--query-masquerade"); err != nil {
			if _, err := run(ctx, nil, "firewall-cmd", "-q", "--zone="+e.zone, "--add-masquerade"); err != nil {
				return err
			}
			e.addedMasq = true
		}
	}
	if _, err := run(ctx, nil, "nft", "list", "chain", "ip", "filter", "DOCKER-USER"); err == nil {
		if !e.dockerUser {
			e.dockerUser = true
			e.deleteDockerRules(ctx) // leftovers from a crashed daemon
		}
		for _, rule := range [][]string{
			{"iifname", iface, "counter", "accept"},
			{"oifname", iface, "ct", "state", "related,established", "counter", "accept"},
		} {
			args := append([]string{"add", "rule", "ip", "filter", "DOCKER-USER"}, rule...)
			if _, err := run(ctx, nil, "nft", append(args, "comment", `"`+tag+`"`)...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Egress) hostExitDown(ctx context.Context) {
	if e.dockerUser {
		e.deleteDockerRules(ctx)
	}
	if e.firewalld {
		for _, iface := range e.hostIfaces {
			_, _ = run(ctx, nil, "firewall-cmd", "-q", "--zone=trusted", "--remove-interface="+iface)
		}
		if e.addedMasq {
			if _, err := run(ctx, nil, "firewall-cmd", "-q", "--zone="+e.zone, "--remove-masquerade"); err != nil {
				e.log.Warn("removing masquerade", "err", err)
			}
		}
	}
}

func (e *Egress) deleteDockerRules(ctx context.Context) {
	out, err := run(ctx, nil, "nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`+tag+`"`) {
			continue
		}
		if i := strings.LastIndex(line, "# handle "); i >= 0 {
			h := strings.TrimSpace(line[i+len("# handle "):])
			if _, err := run(ctx, nil, "nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", h); err != nil {
				e.log.Warn("deleting DOCKER-USER rule", "handle", h, "err", err)
			}
		}
	}
}
