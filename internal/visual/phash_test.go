package visual

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// page draws a crude "login page": a background, a header bar, a centred box with two fields.
func page(w, h int, bg, accent color.Color, boxX int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	fill := func(x0, y0, x1, y1 int, c color.Color) {
		for y := y0; y < y1; y++ {
			for x := x0; x < x1; x++ {
				img.Set(x, y, c)
			}
		}
	}
	fill(0, 0, w, h, bg)
	fill(0, 0, w, h/10, accent)
	bx := boxX * w / 100
	fill(bx, h/3, bx+w/4, h*2/3, color.White)
	fill(bx+w/40, h*4/10, bx+w/4-w/40, h*4/10+h/30, color.Gray{200})
	fill(bx+w/40, h*5/10, bx+w/4-w/40, h*5/10+h/30, color.Gray{200})
	fill(bx+w/40, h*6/10-h/40, bx+w/4-w/40, h*6/10, accent)
	return img
}

func mustHash(t *testing.T, img image.Image) Hash {
	t.Helper()
	h, err := HashImage(img)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSimilarPagesAreClose(t *testing.T) {
	blue := color.RGBA{0, 90, 200, 255}
	a := mustHash(t, page(1920, 1080, color.Gray{240}, blue, 37))
	// The same page at another size (a different window) and with a slightly different shade.
	b := mustHash(t, page(1280, 720, color.Gray{236}, color.RGBA{10, 95, 205, 255}, 37))
	// A different layout: box on the left, dark background.
	c := mustHash(t, page(1920, 1080, color.Gray{30}, color.RGBA{220, 40, 40, 255}, 5))
	if d := Distance(a, b); d > 6 {
		t.Errorf("same page, other size: distance %d (a=%s b=%s)", d, a, b)
	}
	if d := Distance(a, c); d < 16 {
		t.Errorf("different layout: distance only %d (a=%s c=%s)", d, a, c)
	}
}

func TestBlank(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 800, 600))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	img.Set(10, 10, color.Black) // one stray pixel doesn't make a page
	if _, err := HashImage(img); !errors.Is(err, ErrBlank) {
		t.Errorf("white page: err = %v, want ErrBlank", err)
	}
}

func TestHashPNGRoundTripAndParse(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, page(640, 360, color.Gray{240}, color.RGBA{0, 90, 200, 255}, 37)); err != nil {
		t.Fatal(err)
	}
	h, err := HashPNG(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(h.String())
	if err != nil || p != h {
		t.Errorf("Parse(%s) = %s, %v", h, p, err)
	}
	if _, err := Parse("xyz"); err == nil {
		t.Error("Parse accepted a bad hash")
	}
}

func TestHashPNGRefusesHuge(t *testing.T) {
	// A valid PNG header claiming 100000×100000: refused before any pixel is decoded.
	var buf bytes.Buffer
	png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1)))
	b := buf.Bytes()
	// IHDR width/height are at bytes 16–23; the CRC is then wrong, but DecodeConfig reads the
	// size first only if the CRC is right, so rewrite it too.
	putU32 := func(o int, v uint32) { b[o], b[o+1], b[o+2], b[o+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v) }
	putU32(16, 100000)
	putU32(20, 100000)
	putU32(29, crc(b[12:29]))
	if _, err := HashPNG(bytes.NewReader(b)); err == nil {
		t.Error("a 100000×100000 PNG was accepted")
	}
}

func crc(b []byte) uint32 {
	var table [256]uint32
	for i := range table {
		c := uint32(i)
		for range 8 {
			if c&1 == 1 {
				c = 0xedb88320 ^ c>>1
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	c := ^uint32(0)
	for _, x := range b {
		c = table[byte(c)^x] ^ c>>8
	}
	return ^c
}

func FuzzHashPNG(f *testing.F) {
	var buf bytes.Buffer
	png.Encode(&buf, page(64, 36, color.Gray{240}, color.RGBA{0, 90, 200, 255}, 37))
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = HashPNG(bytes.NewReader(b))
	})
}

// The fast paths and the generic At() path agree.
func TestPixelFormatsAgree(t *testing.T) {
	src := page(320, 180, color.Gray{240}, color.RGBA{0, 90, 200, 255}, 37)
	nrgba := image.NewNRGBA(src.Bounds())
	gray := image.NewGray(src.Bounds())
	for y := range 180 {
		for x := range 320 {
			nrgba.Set(x, y, src.At(x, y))
			gray.Set(x, y, src.At(x, y))
		}
	}
	a, b := mustHash(t, src), mustHash(t, nrgba)
	if a != b {
		t.Errorf("RGBA %s != NRGBA %s", a, b)
	}
	if d := Distance(a, mustHash(t, gray)); d > 2 {
		t.Errorf("RGBA vs Gray: distance %d", d)
	}
}
