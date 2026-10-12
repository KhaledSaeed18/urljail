package netns

import (
	"context"
	"encoding/json"
)

// Counters returns the packet counters of the commented rules in the egress namespace
// ("private", "quic", "other", "input").
func (e *Egress) Counters(ctx context.Context) (map[string]uint64, error) {
	return counters(ctx, EgressNS)
}

// VMCounters returns the commented rule counters of a VM namespace ("vm-input", "vm-forward").
func (e *Egress) VMCounters(ctx context.Context, vm *VM) (map[string]uint64, error) {
	return counters(ctx, vm.NS)
}

func counters(ctx context.Context, ns string) (map[string]uint64, error) {
	out, err := in(ctx, ns, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseCounters([]byte(out))
}

// parseCounters reads `nft -j list ruleset` output: rules carrying a comment and a counter.
func parseCounters(b []byte) (map[string]uint64, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := map[string]uint64{}
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment == "" {
			continue
		}
		for _, raw := range item.Rule.Expr {
			var e struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			}
			if json.Unmarshal(raw, &e) == nil && e.Counter != nil {
				out[item.Rule.Comment] += e.Counter.Packets
			}
		}
	}
	return out, nil
}
