package ctlog

import (
	"io"
	"net/http"
	"os"
	"testing"
)

// TestLiveTile reads one real tile when URLJAIL_CT_LIVE is set (not in normal runs).
func TestLiveTile(t *testing.T) {
	prefix := os.Getenv("URLJAIL_CT_LIVE")
	if prefix == "" {
		t.Skip("set URLJAIL_CT_LIVE to a static-ct-api monitoring prefix")
	}
	get := func(p string) []byte {
		resp, err := http.Get(prefix + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		return b
	}
	cp, err := ParseCheckpoint(get("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	n := cp.Size/TileWidth - 1
	es, err := ParseDataTile(get("tile/data/"+TilePath(n)), n*TileWidth)
	if err != nil {
		t.Fatal(err)
	}
	names, pre := 0, 0
	for _, e := range es {
		names += len(e.Names)
		if e.Precert {
			pre++
		}
	}
	t.Logf("%s size %d: tile %s: %d entries (%d precerts), %d names; first %v %v, last %v", cp.Origin, cp.Size, TilePath(n), len(es), pre, names, es[0].Timestamp, es[0].Names, es[len(es)-1].Timestamp)
	if len(es) != TileWidth || names == 0 {
		t.Fatal("unexpected tile")
	}
}
