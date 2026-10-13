// Package visual fingerprints screenshots so that pages that look alike can be found: the same
// phishing kit on many domains, or a page that copies a brand's login screen.
package visual

import (
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"math/bits"
	"os"
	"slices"
	"strconv"
)

// maxPixels caps what Hash decodes: screenshots are 1920×1080, but the PNG comes from the guest.
const maxPixels = 4096 * 4096

// blankStdDev is the luminance spread (0–255) under which a screenshot counts as blank: one
// colour, or nearly. Blank pages all hash alike, so they'd form one meaningless cluster.
const blankStdDev = 2.0

// ErrBlank means the screenshot is almost uniform and has no useful hash.
var ErrBlank = errors.New("screenshot is blank")

// Hash is a 64-bit DCT perceptual hash (pHash): the image reduced to 32×32 grey levels, a 2-D
// DCT, and one bit per low-frequency coefficient (the 8×8 corner) for "above the median".
// Small edits, rescaling and recompression move it a few bits; a different layout moves it
// about half of them.
type Hash uint64

func (h Hash) String() string { return fmt.Sprintf("%016x", uint64(h)) }

// Distance is the number of differing bits (0–64).
func Distance(a, b Hash) int { return bits.OnesCount64(uint64(a ^ b)) }

// Parse reads a hash written by String.
func Parse(s string) (Hash, error) {
	if len(s) != 16 {
		return 0, fmt.Errorf("phash %q: want 16 hex digits", s)
	}
	v, err := strconv.ParseUint(s, 16, 64)
	return Hash(v), err
}

// HashFile hashes a PNG file.
func HashFile(path string) (Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return HashPNG(f)
}

// HashPNG decodes a PNG (refusing anything over maxPixels before decoding) and hashes it.
func HashPNG(r io.ReadSeeker) (Hash, error) {
	cfg, err := png.DecodeConfig(r)
	if err != nil {
		return 0, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxPixels {
		return 0, fmt.Errorf("png is %d×%d, over the limit", cfg.Width, cfg.Height)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	img, err := png.Decode(r)
	if err != nil {
		return 0, err
	}
	return HashImage(img)
}

const side = 32 // reduced image
const keep = 8  // low frequencies kept per axis

// HashImage hashes a decoded image.
func HashImage(img image.Image) (Hash, error) {
	g := grey(img)
	if stddev(g[:]) < blankStdDev {
		return 0, ErrBlank
	}
	c := dct2(&g)
	var low [keep * keep]float64
	for y := range keep {
		for x := range keep {
			low[y*keep+x] = c[y][x]
		}
	}
	med := median(low[1:]) // the DC term is the mean brightness, not structure
	var h Hash
	for i, v := range low {
		if v > med {
			h |= 1 << uint(63-i)
		}
	}
	return h, nil
}

// grey reduces the image to side×side luminance by averaging the source pixels in each cell
// (an area filter, so thin text and borders still count).
func grey(img image.Image) [side * side]float64 {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	var sum [side * side]float64
	var n [side * side]float64
	// Fast paths for what png.Decode returns for screenshots; At() for anything else.
	var pix func(x, y int) (r, g, bl uint8)
	switch m := img.(type) {
	case *image.RGBA:
		pix = func(x, y int) (uint8, uint8, uint8) {
			i := m.PixOffset(b.Min.X+x, b.Min.Y+y)
			return m.Pix[i], m.Pix[i+1], m.Pix[i+2]
		}
	case *image.NRGBA:
		pix = func(x, y int) (uint8, uint8, uint8) {
			i := m.PixOffset(b.Min.X+x, b.Min.Y+y)
			a := uint32(m.Pix[i+3])
			return uint8(uint32(m.Pix[i]) * a / 255), uint8(uint32(m.Pix[i+1]) * a / 255), uint8(uint32(m.Pix[i+2]) * a / 255)
		}
	default:
		pix = func(x, y int) (uint8, uint8, uint8) {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA() // 16-bit, alpha-premultiplied
			return uint8(r >> 8), uint8(g >> 8), uint8(bl >> 8)
		}
	}
	for y := range h {
		cy := y * side / h
		for x := range w {
			cx := x * side / w
			r, g, bl := pix(x, y)
			sum[cy*side+cx] += 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)
			n[cy*side+cx]++
		}
	}
	for i := range sum {
		if n[i] > 0 {
			sum[i] /= n[i]
		}
	}
	return sum
}

// dct2 is the 2-D DCT-II of the side×side image (separable: rows, then columns).
func dct2(g *[side * side]float64) [side][side]float64 {
	var cos [side][side]float64
	for k := range side {
		for i := range side {
			cos[k][i] = math.Cos(math.Pi / side * (float64(i) + 0.5) * float64(k))
		}
	}
	var rows [side][side]float64
	for y := range side {
		for k := range side {
			var s float64
			for x := range side {
				s += g[y*side+x] * cos[k][x]
			}
			rows[y][k] = s
		}
	}
	var out [side][side]float64
	for k := range side {
		for x := range side {
			var s float64
			for y := range side {
				s += rows[y][x] * cos[k][y]
			}
			out[k][x] = s
		}
	}
	return out
}

func stddev(v []float64) float64 {
	var mean float64
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	var ss float64
	for _, x := range v {
		ss += (x - mean) * (x - mean)
	}
	return math.Sqrt(ss / float64(len(v)))
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
