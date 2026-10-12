package netns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDev is the live exit: a WireGuard interface created in the host namespace (so its
// encrypted UDP leaves through the host's network) and moved into the egress namespace, where
// it holds the only default route (ADR 0003).
const WGDev = "wg0"

// MaxHandshakeAge is how old the tunnel's last handshake may be before runs are refused.
const MaxHandshakeAge = 3 * time.Minute

// WGConfig is the part of a wg-quick configuration urljail uses (one peer, IPv4).
type WGConfig struct {
	PrivateKey   wgtypes.Key
	Address      *net.IPNet
	DNS          []net.IP
	PeerKey      wgtypes.Key
	PresharedKey *wgtypes.Key
	Endpoint     *net.UDPAddr
	AllowedIPs   []net.IPNet
	Keepalive    time.Duration
}

// ParseWGQuick reads a wg-quick style file, as VPN providers hand them out.
func ParseWGQuick(path string) (*WGConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &WGConfig{Keepalive: 25 * time.Second}
	section := ""
	var peers int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("wireguard config: bad line %q", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var err error
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey, err = wgtypes.ParseKey(v)
		case "interface.address":
			for _, a := range strings.Split(v, ",") {
				if ip, n, e := net.ParseCIDR(strings.TrimSpace(a)); e == nil && ip.To4() != nil && c.Address == nil {
					n.IP = ip
					c.Address = n
				}
			}
		case "interface.dns":
			for _, d := range strings.Split(v, ",") {
				if ip := net.ParseIP(strings.TrimSpace(d)); ip != nil && ip.To4() != nil {
					c.DNS = append(c.DNS, ip)
				}
			}
		case "peer.publickey":
			c.PeerKey, err = wgtypes.ParseKey(v)
		case "peer.presharedkey":
			var k wgtypes.Key
			if k, err = wgtypes.ParseKey(v); err == nil {
				c.PresharedKey = &k
			}
		case "peer.endpoint":
			c.Endpoint, err = net.ResolveUDPAddr("udp4", v)
		case "peer.allowedips":
			for _, a := range strings.Split(v, ",") {
				if _, n, e := net.ParseCIDR(strings.TrimSpace(a)); e == nil && n.IP.To4() != nil {
					c.AllowedIPs = append(c.AllowedIPs, *n)
				}
			}
		case "peer.persistentkeepalive":
			var s int
			if s, err = strconv.Atoi(v); err == nil {
				c.Keepalive = time.Duration(s) * time.Second
			}
		}
		if err != nil {
			return nil, fmt.Errorf("wireguard config %s: %w", k, err)
		}
	}
	switch {
	case peers != 1:
		return nil, fmt.Errorf("wireguard config: want exactly one [Peer], got %d", peers)
	case c.Address == nil:
		return nil, errors.New("wireguard config: no IPv4 Address")
	case c.Endpoint == nil:
		return nil, errors.New("wireguard config: no Endpoint")
	case len(c.DNS) == 0:
		return nil, errors.New("wireguard config: no IPv4 DNS (the resolver forwards to the VPN's DNS)")
	case c.PrivateKey == (wgtypes.Key{}) || c.PeerKey == (wgtypes.Key{}):
		return nil, errors.New("wireguard config: missing keys")
	}
	return c, sc.Err()
}

// wireguardUp creates wg0 in the host namespace, moves it into the egress namespace,
// configures it and makes it the only default route there.
func wireguardUp(ctx context.Context, cfg *WGConfig) error {
	_ = ip(ctx, "link", "del", WGDev) // a leftover in the host namespace
	for _, s := range [][]string{
		{"link", "add", WGDev, "type", "wireguard"}, // the UDP socket stays in the host namespace
		{"link", "set", WGDev, "netns", EgressNS},
	} {
		if err := ip(ctx, s...); err != nil {
			return err
		}
	}
	err := Do(EgressNS, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		ka := cfg.Keepalive
		return c.ConfigureDevice(WGDev, wgtypes.Config{
			PrivateKey:   &cfg.PrivateKey,
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey: cfg.PeerKey, PresharedKey: cfg.PresharedKey, Endpoint: cfg.Endpoint,
				ReplaceAllowedIPs: true, AllowedIPs: cfg.AllowedIPs, PersistentKeepaliveInterval: &ka,
			}},
		})
	})
	if err != nil {
		return fmt.Errorf("configuring %s: %w", WGDev, err)
	}
	for _, s := range [][]string{
		{"-n", EgressNS, "addr", "add", cfg.Address.String(), "dev", WGDev},
		{"-n", EgressNS, "link", "set", WGDev, "up"},
		{"-n", EgressNS, "route", "add", "default", "dev", WGDev},
	} {
		if err := ip(ctx, s...); err != nil {
			return err
		}
	}
	return nil
}

// Handshake is the time of the tunnel's latest handshake (zero: none yet).
func (e *Egress) Handshake() (time.Time, error) {
	var t time.Time
	err := Do(EgressNS, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		d, err := c.Device(WGDev)
		if err != nil {
			return err
		}
		if len(d.Peers) == 1 {
			t = d.Peers[0].LastHandshakeTime
		}
		return nil
	})
	return t, err
}

// WaitHandshake waits until the tunnel has a handshake newer than since.
func (e *Egress) WaitHandshake(ctx context.Context, since time.Time) error {
	for {
		if t, err := e.Handshake(); err == nil && t.After(since) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no WireGuard handshake: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// SetTunnel takes the tunnel down or brings it back (the self-test's "VPN down" check).
// Down removes the egress namespace's only default route with it.
func (e *Egress) SetTunnel(ctx context.Context, up bool) error {
	if !up {
		return ip(ctx, "-n", EgressNS, "link", "set", WGDev, "down")
	}
	if err := ip(ctx, "-n", EgressNS, "link", "set", WGDev, "up"); err != nil {
		return err
	}
	return ip(ctx, "-n", EgressNS, "route", "replace", "default", "dev", WGDev)
}
