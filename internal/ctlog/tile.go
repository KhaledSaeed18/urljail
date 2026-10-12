// Package ctlog reads Certificate Transparency logs that serve the static-ct-api
// (c2sp.org/static-ct-api: Let's Encrypt, Google, Geomys, ...) for P6's own discovery of fresh
// phishing domains (docs/feed-ingestion.md#ct-discovery). It only extracts DNS names; it never
// verifies, trusts or acts on a certificate. Everything it parses comes from the internet and
// is bounded and fuzzed.
package ctlog

import (
	"bytes"
	encasn1 "encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// TileWidth is the number of entries in a full data tile.
const TileWidth = 256

const maxNamesPerCert = 100

// Checkpoint is the part of a log checkpoint urljail uses: its origin line and tree size. The
// signature isn't verified: a forged checkpoint could only make urljail visit other domains,
// and every visit goes through the same isolation as any URL.
type Checkpoint struct {
	Origin string
	Size   uint64
}

// ParseCheckpoint reads the first two lines of a checkpoint (c2sp.org/tlog-checkpoint).
func ParseCheckpoint(b []byte) (Checkpoint, error) {
	lines := strings.SplitN(string(b), "\n", 3)
	if len(lines) < 3 || lines[0] == "" || len(lines[0]) > 256 {
		return Checkpoint{}, errors.New("checkpoint: malformed")
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint size: %w", err)
	}
	return Checkpoint{Origin: lines[0], Size: n}, nil
}

// TilePath encodes a tile index as in c2sp.org/tlog-tiles: groups of three digits, all but
// the last prefixed with "x" (1234067 → "x001/x234/067").
func TilePath(n uint64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n /= 1000; n > 0; n /= 1000 {
		s = fmt.Sprintf("x%03d/", n%1000) + s
	}
	return s
}

// Entry is one log entry, reduced to what discovery needs.
type Entry struct {
	Index     uint64
	Timestamp time.Time // the log's timestamp (SCT time), close to issuance
	Precert   bool
	Names     []string // dNSName SANs, lowercased
}

// ParseDataTile reads the entries of a data tile whose first entry has index first.
// A malformed entry ends parsing: what came before it is returned with the error.
func ParseDataTile(b []byte, first uint64) ([]Entry, error) {
	s := cryptobyte.String(b)
	var out []Entry
	for i := uint64(0); !s.Empty(); i++ {
		e, err := readLeaf(&s)
		if err != nil {
			return out, fmt.Errorf("entry %d: %w", first+i, err)
		}
		e.Index = first + i
		out = append(out, e)
	}
	return out, nil
}

// readLeaf reads one TileLeaf (c2sp.org/static-ct-api#log-entries).
func readLeaf(s *cryptobyte.String) (Entry, error) {
	var e Entry
	var ts uint64
	var typ uint16
	if !s.ReadUint64(&ts) || !s.ReadUint16(&typ) {
		return e, errors.New("truncated header")
	}
	e.Timestamp = time.UnixMilli(int64(ts & (1<<62 - 1))).UTC()
	var tbs []byte
	switch typ {
	case 0: // x509_entry: the certificate itself
		var cert cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&cert) {
			return e, errors.New("truncated certificate")
		}
		var inner cryptobyte.String
		if !cert.ReadASN1(&inner, asn1.SEQUENCE) || !inner.ReadASN1Element((*cryptobyte.String)(&tbs), asn1.SEQUENCE) {
			return e, errors.New("certificate: not a SEQUENCE")
		}
	case 1: // precert_entry: issuer key hash + TBSCertificate
		var t cryptobyte.String
		if !s.Skip(32) || !s.ReadUint24LengthPrefixed(&t) {
			return e, errors.New("truncated precertificate")
		}
		tbs, e.Precert = t, true
	default:
		return e, fmt.Errorf("unknown entry type %d", typ)
	}
	var ext, pre, chain cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ext) {
		return e, errors.New("truncated extensions")
	}
	if e.Precert && !s.ReadUint24LengthPrefixed(&pre) {
		return e, errors.New("truncated pre_certificate")
	}
	if !s.ReadUint16LengthPrefixed(&chain) {
		return e, errors.New("truncated chain")
	}
	e.Names = dnsNames(tbs) // a TBS urljail can't read just yields no names
	return e, nil
}

var oidSAN = encasn1.ObjectIdentifier{2, 5, 29, 17}

// dnsNames returns the dNSName entries of a TBSCertificate's subjectAltName extension.
func dnsNames(der []byte) []string {
	s := cryptobyte.String(der)
	var tbs cryptobyte.String
	if !s.ReadASN1(&tbs, asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific()) || // version
		!tbs.SkipASN1(asn1.INTEGER) { // serialNumber
		return nil
	}
	for range 5 { // signature, issuer, validity, subject, subjectPublicKeyInfo
		if !tbs.SkipASN1(asn1.SEQUENCE) {
			return nil
		}
	}
	if !tbs.SkipOptionalASN1(asn1.Tag(1).ContextSpecific()) || !tbs.SkipOptionalASN1(asn1.Tag(2).ContextSpecific()) {
		return nil
	}
	var exts cryptobyte.String
	var present bool
	if !tbs.ReadOptionalASN1(&exts, &present, asn1.Tag(3).Constructed().ContextSpecific()) || !present {
		return nil
	}
	var seq cryptobyte.String
	if !exts.ReadASN1(&seq, asn1.SEQUENCE) {
		return nil
	}
	for !seq.Empty() {
		var ext, val cryptobyte.String
		var oid encasn1.ObjectIdentifier
		if !seq.ReadASN1(&ext, asn1.SEQUENCE) || !ext.ReadASN1ObjectIdentifier(&oid) ||
			!ext.SkipOptionalASN1(asn1.BOOLEAN) || !ext.ReadASN1(&val, asn1.OCTET_STRING) {
			return nil
		}
		if !oid.Equal(oidSAN) {
			continue
		}
		var gns cryptobyte.String
		if !val.ReadASN1(&gns, asn1.SEQUENCE) {
			return nil
		}
		var names []string
		for !gns.Empty() && len(names) < maxNamesPerCert {
			var gn cryptobyte.String
			var tag asn1.Tag
			if !gns.ReadAnyASN1(&gn, &tag) {
				break
			}
			if tag == asn1.Tag(2).ContextSpecific() && validName(gn) {
				names = append(names, strings.ToLower(string(gn)))
			}
		}
		return names
	}
	return nil
}

// validName accepts DNS names (with an optional leading "*.") of sane length.
func validName(b []byte) bool {
	if len(b) == 0 || len(b) > 253 {
		return false
	}
	b = bytes.TrimPrefix(b, []byte("*."))
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return len(b) > 0
}
