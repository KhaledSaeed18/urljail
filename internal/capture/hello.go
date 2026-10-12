package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Hello is what a TLS ClientHello reveals in clear text (with ECH off, as urljail's policy sets).
type Hello struct {
	SNI  string
	ALPN []string
}

type seg struct {
	seq  uint32
	data []byte
}

// reassemble joins a flow's first outgoing segments in sequence order, from the lowest
// sequence number, until a gap. Retransmissions overlap and are trimmed.
func reassemble(segs []seg) []byte {
	if len(segs) == 0 {
		return nil
	}
	sort.Slice(segs, func(i, j int) bool { return int32(segs[i].seq-segs[j].seq) < 0 })
	base := segs[0].seq
	var out []byte
	for _, s := range segs {
		off := int(int32(s.seq - base))
		switch {
		case off > len(out):
			return out // gap: a segment we didn't capture
		case off+len(s.data) <= len(out):
			continue // retransmission already covered
		}
		out = append(out, s.data[len(out)-off:]...)
	}
	return out
}

var errNotHello = errors.New("not a TLS ClientHello")

// parseClientHello reads SNI and ALPN from the start of a TLS stream. The bytes come from a
// hostile guest, so every length is checked before use.
func parseClientHello(b []byte) (Hello, error) {
	var h Hello
	// TLS record: type 22 (handshake), version, length.
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return h, errNotHello
	}
	b = b[5:] // the handshake may span several records; Chrome uses one
	// Handshake: type 1 (ClientHello), 3-byte length.
	if len(b) < 4 || b[0] != 0x01 {
		return h, errNotHello
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if n < len(b) {
		b = b[:n]
	}
	r := reader{b: b}
	r.skip(2 + 32)  // client_version, random
	r.skip(r.u8())  // session_id
	r.skip(r.u16()) // cipher_suites
	r.skip(r.u8())  // compression_methods
	extLen := r.u16()
	if r.err {
		return h, errors.New("truncated ClientHello")
	}
	// If the capture cut the hello short, read the extensions that are there: SNI and ALPN
	// are usually early, and a partial answer beats none.
	ext := r.b[:min(extLen, len(r.b))]
	er := reader{b: ext}
	for !er.err && len(er.b) >= 4 {
		typ, body := er.u16(), er.bytes(er.u16())
		br := reader{b: body}
		switch typ {
		case 0: // server_name
			list := reader{b: br.bytes(br.u16())}
			for !list.err && len(list.b) >= 3 {
				kind, name := list.u8(), list.bytes(list.u16())
				if kind == 0 && !list.err && h.SNI == "" {
					h.SNI = hostname(string(name))
				}
			}
		case 16: // application_layer_protocol_negotiation
			list := reader{b: br.bytes(br.u16())}
			for !list.err && len(list.b) >= 1 {
				if p := list.bytes(list.u8()); !list.err {
					h.ALPN = append(h.ALPN, string(p))
				}
			}
		}
	}
	return h, nil
}

// reader consumes big-endian fields and records (instead of panicking) when input runs out.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) bytes(n int) []byte {
	if r.err || n < 0 || n > len(r.b) {
		r.err = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() int {
	if v := r.bytes(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.bytes(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

// parseHTTPHost returns the Host header of a plain-HTTP request at the start of a stream,
// the HTTP counterpart of SNI. Only the first 2 KiB are looked at.
func parseHTTPHost(b []byte) string {
	b = b[:min(len(b), 2048)]
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(b)
	}
	lines := bytes.Split(b[:end], []byte("\r\n"))
	if len(lines) == 0 || !bytes.Contains(lines[0], []byte(" HTTP/1.")) {
		return ""
	}
	for _, l := range lines[1:] {
		k, v, ok := bytes.Cut(l, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			host := strings.TrimSpace(string(v))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return hostname(host)
		}
	}
	return ""
}

// hostname returns s lowercased if it's a plausible DNS name (ASCII letters, digits, '.', '-',
// '_', at most 253 bytes). The bytes come from a hostile guest: anything else is kept as
// evidence, but hex-encoded and short, never as free text (found by fuzzing: lowercasing
// invalid UTF-8 grows it and lets junk through).
func hostname(s string) string {
	if s == "" {
		return ""
	}
	ok := len(s) <= 253
	for i := 0; ok && i < len(s); i++ {
		c := s[i]
		ok = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
	}
	if ok {
		return strings.ToLower(s)
	}
	b := []byte(s)
	if len(b) > 32 {
		b = b[:32]
	}
	return fmt.Sprintf("invalid:%x", b)
}
