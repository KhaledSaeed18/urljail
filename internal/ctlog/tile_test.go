package ctlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"
	"time"
)

func testCert(t testing.TB, names ...string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1e9, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func u24(b []byte) []byte {
	return append([]byte{byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}
func u16(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }

// leaf builds a TileLeaf: precert carries the TBS, x509 the whole certificate.
func leaf(c *x509.Certificate, precert bool, ms uint64) []byte {
	b := binary.BigEndian.AppendUint64(nil, ms)
	if precert {
		b = append(b, 0, 1)
		b = append(b, make([]byte, 32)...)
		b = append(b, u24(c.RawTBSCertificate)...)
		b = append(b, u16(nil)...)
		b = append(b, u24(c.Raw)...) // pre_certificate
	} else {
		b = append(b, 0, 0)
		b = append(b, u24(c.Raw)...)
		b = append(b, u16(nil)...)
	}
	return append(b, u16(make([]byte, 32))...) // one chain fingerprint
}

func TestParseDataTile(t *testing.T) {
	a := testCert(t, "Login-PayPaI.example.test", "*.example.test")
	b := testCert(t, "other.test", "bad name.test")
	tile := append(leaf(a, true, 1760000000000), leaf(b, false, 1760000001000)...)
	es, err := ParseDataTile(tile, 512)
	if err != nil || len(es) != 2 {
		t.Fatalf("%v %v", es, err)
	}
	if es[0].Index != 512 || !es[0].Precert || !slices.Equal(es[0].Names, []string{"login-paypai.example.test", "*.example.test"}) {
		t.Errorf("entry 0: %+v", es[0])
	}
	if es[1].Precert || !slices.Equal(es[1].Names, []string{"other.test"}) || es[1].Timestamp.UnixMilli() != 1760000001000 {
		t.Errorf("entry 1: %+v", es[1])
	}
	if es, err := ParseDataTile(tile[:len(tile)-5], 0); err == nil || len(es) != 1 {
		t.Errorf("truncated tile: %d entries, %v", len(es), err)
	}
}

func TestTilePathAndCheckpoint(t *testing.T) {
	for n, want := range map[uint64]string{0: "000", 7: "007", 1234067: "x001/x234/067", 3933180: "x003/x933/180", 1000: "x001/000"} {
		if got := TilePath(n); got != want {
			t.Errorf("TilePath(%d) = %q, want %q", n, got, want)
		}
	}
	cp, err := ParseCheckpoint([]byte("log.example/2026h2\n1006892316\nroot=\n\n— sig\n"))
	if err != nil || cp.Size != 1006892316 || cp.Origin != "log.example/2026h2" {
		t.Errorf("%+v %v", cp, err)
	}
	for _, bad := range []string{"", "x\n", "x\n-1\nr\n", "x\n12a\nr\n"} {
		if _, err := ParseCheckpoint([]byte(bad)); err == nil {
			t.Errorf("ParseCheckpoint(%q) accepted", bad)
		}
	}
}

func FuzzParseDataTile(f *testing.F) {
	c := testCert(f, "a.example.test")
	f.Add(append(leaf(c, true, 1), leaf(c, false, 2)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		es, _ := ParseDataTile(b, 0)
		for _, e := range es {
			if len(e.Names) > maxNamesPerCert {
				t.Fatalf("%d names", len(e.Names))
			}
			for _, n := range e.Names {
				if !validName([]byte(n)) {
					t.Fatalf("invalid name %q", n)
				}
			}
		}
	})
}
