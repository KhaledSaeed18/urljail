// Package kits recognises phishing kits by the shape of their pages: the same kit served from
// many hosts keeps its DOM structure while the text, brand and domain change. A fingerprint is
// a MinHash of the page's element paths (tag names, plus the type and name of form fields), so
// two pages' fingerprints estimate how much of their structure they share.
package kits

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"io"
	"math"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// Size is the number of MinHash values: the Jaccard estimate's error is about 1/sqrt(Size).
const Size = 128

// MinShingles is the fewest distinct paths a page needs for a fingerprint: tiny pages (a
// redirect, an empty body) look alike whatever they are.
const MinShingles = 20

const maxDOM = 32 << 20 // bytes of DOM read
const maxDepth = 256

// Fingerprint is a page's structure.
type Fingerprint struct {
	Shingles int          `json:"shingles"` // distinct element paths
	Min      [Size]uint64 `json:"min"`
}

// skip are elements whose content isn't page structure.
var skip = map[string]bool{"script": true, "style": true, "noscript": true, "template": true, "svg": true}

// Of fingerprints a serialized DOM. ok is false for a page with fewer than MinShingles paths.
func Of(dom io.Reader) (Fingerprint, bool) {
	z := html.NewTokenizer(io.LimitReader(dom, maxDOM))
	var stack []string
	skipDepth := 0
	set := map[uint64]bool{}
	add := func(tok string) {
		// The element with its parent and grandparent: where it sits, not just what it is.
		n := len(stack)
		parts := []string{tok}
		if n > 0 {
			parts = append([]string{stack[n-1]}, parts...)
		}
		if n > 1 {
			parts = append([]string{stack[n-2]}, parts...)
		}
		h := fnv.New64a()
		h.Write([]byte(strings.Join(parts, ">")))
		set[h.Sum64()] = true
	}
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return finish(set)
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if skipDepth > 0 {
				if tt == html.StartTagToken && !void[tag] && skip[tag] {
					skipDepth++
				}
				continue
			}
			if skip[tag] {
				if tt == html.StartTagToken && !void[tag] {
					skipDepth = 1
				}
				continue
			}
			tok := tag
			if tag == "input" || tag == "button" || tag == "select" || tag == "textarea" || tag == "form" {
				var typ, nm string
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					switch string(k) {
					case "type":
						typ = strings.ToLower(string(v))
					case "name":
						nm = strings.ToLower(string(v))
					}
				}
				if len(nm) > 40 {
					nm = nm[:40]
				}
				tok += "[" + typ + "|" + nm + "]"
			}
			add(tok)
			if tt == html.StartTagToken && !void[tag] && len(stack) < maxDepth {
				stack = append(stack, tag)
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if skipDepth > 0 {
				if skip[tag] {
					skipDepth--
				}
				continue
			}
			// Pop to the matching element (the DOM is browser-serialized, so well nested).
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i] == tag {
					stack = stack[:i]
					break
				}
			}
		}
	}
}

func finish(set map[uint64]bool) (Fingerprint, bool) {
	var f Fingerprint
	f.Shingles = len(set)
	if f.Shingles < MinShingles {
		return f, false
	}
	for i := range f.Min {
		f.Min[i] = math.MaxUint64
	}
	var b [16]byte
	for s := range set {
		binary.LittleEndian.PutUint64(b[:8], s)
		for i := range f.Min {
			binary.LittleEndian.PutUint64(b[8:], uint64(i)*0x9e3779b97f4a7c15)
			if v := mix(b[:]); v < f.Min[i] {
				f.Min[i] = v
			}
		}
	}
	return f, true
}

// mix hashes 16 bytes (the shingle and the permutation index) to 64 bits.
func mix(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	x := h.Sum64()
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	return x
}

// Similarity estimates the Jaccard similarity of two pages' structures (0..1).
func Similarity(a, b Fingerprint) float64 {
	same := 0
	for i := range a.Min {
		if a.Min[i] == b.Min[i] {
			same++
		}
	}
	return float64(same) / Size
}

var void = map[string]bool{"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true}

// SamePlace reports whether two hosts are the same site or the same publishing platform: the
// same registrable domain, or the same private public suffix (github.io, pages.dev, gitbook.io:
// everyone's pages there share the platform's template). A kit match only counts across places.
func SamePlace(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	if a == "" || b == "" {
		return true
	}
	ra, erra := publicsuffix.EffectiveTLDPlusOne(a)
	rb, errb := publicsuffix.EffectiveTLDPlusOne(b)
	if erra != nil || errb != nil || ra == rb {
		return true
	}
	sa, icannA := publicsuffix.PublicSuffix(a)
	sb, _ := publicsuffix.PublicSuffix(b)
	return !icannA && sa == sb
}

// Ref is a phishing page a person labelled: the kit fingerprint to look for elsewhere.
type Ref struct {
	Run         string      `json:"run"`
	Host        string      `json:"host"` // where it was seen
	Kind        string      `json:"kind"`
	Brand       string      `json:"brand"`
	Labelled    string      `json:"labelled"` // date, YYYY-MM-DD
	Fingerprint Fingerprint `json:"fingerprint"`
}

// Threshold is the similarity from which two pages count as one kit. On P7's labelled pages,
// leave-one-out and across sites: 0.6 and 0.7 both matched 17 of 66 phishing pages to another
// and none of 61 others; 0.7 leaves margin (journal P7, S7). Rechecked with the references of
// all labelled sets (S13): 49 of 137 phishing pages, none of 102 others; the closest of those
// others is 0.53.
const Threshold = 0.7

//go:embed refs.json
var refsJSON []byte

// Refs returns the kit references (refs.json, made by `urljail kits refs`).
func Refs() []Ref {
	var r []Ref
	_ = json.Unmarshal(refsJSON, &r)
	return r
}

// Match returns the most similar reference seen at another site or platform, if it reaches
// Threshold.
func Match(refs []Ref, f Fingerprint, host string) (Ref, float64, bool) {
	var best Ref
	bestSim := 0.0
	for _, r := range refs {
		if SamePlace(host, r.Host) {
			continue
		}
		if s := Similarity(f, r.Fingerprint); s > bestSim {
			best, bestSim = r, s
		}
	}
	return best, bestSim, bestSim >= Threshold
}
