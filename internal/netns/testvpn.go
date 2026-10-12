package netns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// live-test mode: a local stand-in for a VPN provider, so the live exit (WireGuard in the
// egress namespace, fail-closed routing, the live self-test checks) can be exercised without
// an account. It terminates the tunnel in its own namespace and NATs it out through the host,
// so its exit IP is the home IP: the URL policy stays the dev allowlist in this mode.
const (
	TestVPNNS    = "uj-testvpn"
	testVPNHost  = "vh-testvpn" // host side of its link
	testVPNInner = "vn-testvpn"
	testVPNDev   = "wg-test"
	testVPNPort  = 51820
)

func (e *Egress) startTestVPN(ctx context.Context) (*WGConfig, error) {
	_ = deleteNS(ctx, TestVPNNS)
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	client, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	for _, s := range [][]string{
		{"netns", "add", TestVPNNS},
		{"-n", TestVPNNS, "link", "set", "lo", "up"},
		{"link", "add", testVPNHost, "type", "veth", "peer", "name", testVPNInner, "netns", TestVPNNS},
		{"addr", "add", "10.198.0.1/30", "dev", testVPNHost},
		{"link", "set", testVPNHost, "up"},
		{"-n", TestVPNNS, "addr", "add", "10.198.0.2/30", "dev", testVPNInner},
		{"-n", TestVPNNS, "link", "set", testVPNInner, "up"},
		{"-n", TestVPNNS, "route", "add", "default", "via", "10.198.0.1"},
		// Created inside its namespace, so its UDP socket listens there.
		{"-n", TestVPNNS, "link", "add", testVPNDev, "type", "wireguard"},
		{"-n", TestVPNNS, "addr", "add", "10.199.10.1/24", "dev", testVPNDev},
	} {
		if err := ip(ctx, s...); err != nil {
			return nil, fmt.Errorf("test VPN: %w", err)
		}
	}
	if err := sysctls(ctx, TestVPNNS, "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}
	port := testVPNPort
	_, clientNet, _ := net.ParseCIDR("10.199.10.2/32")
	err = Do(TestVPNNS, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		return c.ConfigureDevice(testVPNDev, wgtypes.Config{PrivateKey: &server, ListenPort: &port, ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{PublicKey: client.PublicKey(), ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*clientNet}}}})
	})
	if err != nil {
		return nil, fmt.Errorf("test VPN: %w", err)
	}
	if err := ip(ctx, "-n", TestVPNNS, "link", "set", testVPNDev, "up"); err != nil {
		return nil, err
	}
	rules := "table ip testvpn {\n\tchain post {\n\t\ttype nat hook postrouting priority srcnat;\n\t\toifname \"" + testVPNInner + "\" masquerade\n\t}\n}\n"
	if _, err := run(ctx, strings.NewReader(rules), "ip", "netns", "exec", TestVPNNS, "nft", "-f", "-"); err != nil {
		return nil, err
	}
	if err := e.hostExitUp(ctx, testVPNHost); err != nil {
		return nil, err
	}
	addr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("10.198.0.2:%d", testVPNPort))
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	_, a, _ := net.ParseCIDR("10.199.10.2/32")
	a.IP = net.ParseIP("10.199.10.2").To4()
	return &WGConfig{
		PrivateKey: client, Address: a, DNS: []net.IP{net.ParseIP("1.1.1.1").To4()},
		PeerKey: server.PublicKey(), Endpoint: addr, AllowedIPs: []net.IPNet{*all}, Keepalive: 25 * time.Second,
	}, nil
}
