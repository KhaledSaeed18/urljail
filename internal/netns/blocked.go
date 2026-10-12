package netns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

// Blocked is one packet a VM sent that the egress ruleset dropped (host-attested).
type Blocked struct {
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"` // "private", "quic", "other" or "input"
	Src    string    `json:"src"`
	Dst    string    `json:"dst"`
	Proto  string    `json:"proto"`
	Port   int       `json:"dst_port,omitempty"`
}

// blockLog reads the NFLOG group the egress rules log drops to and routes each packet to
// the run whose VM sent it.
type blockLog struct {
	nf *nflog.Nflog

	mu    sync.Mutex
	sinks map[string]func(Blocked) // by VM outside address
}

func startBlockLog(ctx context.Context, e *Egress) (*blockLog, error) {
	b := &blockLog{sinks: map[string]func(Blocked){}}
	// The netlink socket must be created inside the egress namespace.
	err := Do(EgressNS, func() error {
		nf, err := nflog.Open(&nflog.Config{Group: LogGroup, Copymode: nflog.CopyPacket})
		b.nf = nf
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("nflog: %w", err)
	}
	err = b.nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		prefix := ""
		if a.Prefix != nil {
			prefix = *a.Prefix
		}
		bl, ok := parseBlocked(prefix, *a.Payload)
		if !ok {
			return 0
		}
		b.mu.Lock()
		sink := b.sinks[bl.Src]
		b.mu.Unlock()
		if sink != nil {
			sink(bl)
		}
		return 0
	}, func(err error) int {
		// ENOBUFS under a flood: some log lines are lost, the drops themselves still happen.
		e.log.Warn("nflog", "err", err)
		return 0
	})
	if err != nil {
		b.nf.Close()
		return nil, err
	}
	return b, nil
}

// parseBlocked reads an NFLOG prefix ("uj private ") and the IPv4 packet that was dropped.
func parseBlocked(prefix string, pkt []byte) (Blocked, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return Blocked{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return Blocked{}, false
	}
	bl := Blocked{
		Time:   time.Now().UTC(),
		Reason: strings.TrimSpace(strings.TrimPrefix(prefix, "uj ")),
		Src:    net.IP(pkt[12:16]).String(),
		Dst:    net.IP(pkt[16:20]).String(),
	}
	switch pkt[9] {
	case 6:
		bl.Proto = "tcp"
	case 17:
		bl.Proto = "udp"
	case 1:
		bl.Proto = "icmp"
	default:
		bl.Proto = fmt.Sprint(pkt[9])
	}
	if (bl.Proto == "tcp" || bl.Proto == "udp") && len(pkt) >= ihl+4 {
		bl.Port = int(binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]))
	}
	return bl, true
}

// AttachBlocked sends every drop of packets from client to fn until DetachBlocked.
func (e *Egress) AttachBlocked(client string, fn func(Blocked)) {
	e.blocked.mu.Lock()
	e.blocked.sinks[client] = fn
	e.blocked.mu.Unlock()
}

// DetachBlocked stops delivering drops for client.
func (e *Egress) DetachBlocked(client string) {
	e.blocked.mu.Lock()
	delete(e.blocked.sinks, client)
	e.blocked.mu.Unlock()
}
