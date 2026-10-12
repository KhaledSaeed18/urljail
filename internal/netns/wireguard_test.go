package netns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseWGQuick(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	conf := "[Interface]\n# a Mullvad-style file\nPrivateKey = " + priv.String() +
		"\nAddress = 10.66.1.2/32,fc00:bbbb:bbbb:bb01::3:102/128\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = " +
		peer.PublicKey().String() + "\nAllowedIPs = 0.0.0.0/0,::0/0\nEndpoint = 193.32.248.66:51820\n"
	path := filepath.Join(t.TempDir(), "mullvad.conf")
	os.WriteFile(path, []byte(conf), 0o600)
	c, err := ParseWGQuick(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address.String() != "10.66.1.2/32" || c.DNS[0].String() != "10.64.0.1" || c.Endpoint.String() != "193.32.248.66:51820" ||
		len(c.AllowedIPs) != 1 || c.AllowedIPs[0].String() != "0.0.0.0/0" || c.PeerKey != peer.PublicKey() || c.Keepalive != 25*time.Second {
		t.Fatalf("parsed %+v", c)
	}
	os.WriteFile(path, []byte("[Interface]\nPrivateKey = "+priv.String()+"\n"), 0o600)
	if _, err := ParseWGQuick(path); err == nil {
		t.Fatal("config without a peer accepted")
	}
}
