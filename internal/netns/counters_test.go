package netns

import "testing"

func TestParseCounters(t *testing.T) {
	const out = `{"nftables": [{"metainfo": {"version": "1.1.3"}},
	{"table": {"family": "inet", "name": "urljail", "handle": 1}},
	{"rule": {"family": "inet", "table": "urljail", "chain": "forward", "handle": 7, "comment": "private",
	  "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "veth-eg-*"}},
	           {"log": {"prefix": "uj private ", "group": 2}}, {"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}},
	{"rule": {"family": "inet", "table": "urljail", "chain": "forward", "handle": 9,
	  "expr": [{"counter": {"packets": 99, "bytes": 1}}, {"accept": null}]}}]}`
	c, err := parseCounters([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 || c["private"] != 3 {
		t.Fatalf("counters = %v", c)
	}
}
