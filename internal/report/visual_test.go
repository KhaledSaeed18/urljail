package report

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScreenshotHash(t *testing.T) {
	encode := func(img image.Image) []byte {
		var b bytes.Buffer
		png.Encode(&b, img)
		return b.Bytes()
	}
	content := image.NewRGBA(image.Rect(0, 0, 320, 180))
	blank := image.NewRGBA(image.Rect(0, 0, 320, 180))
	for y := range 180 {
		for x := range 320 {
			blank.Set(x, y, color.White)
			if x > 100 && x < 220 && y > 40 && y < 140 {
				content.Set(x, y, color.White)
			} else {
				content.Set(x, y, color.RGBA{0, 90, 200, 255})
			}
		}
	}
	for _, tc := range []struct {
		name      string
		file      []byte
		wantHash  bool
		wantBlank bool
		wantGap   bool
	}{
		{"content", encode(content), true, false, false},
		{"blank", encode(blank), false, true, false},
		{"not a png", []byte("png"), false, false, true},
	} {
		dir := writeRun(t, true)
		os.WriteFile(filepath.Join(dir, "guest", "screenshot.png"), tc.file, 0o600)
		r, err := Build(dir)
		if err != nil {
			t.Fatal(err)
		}
		gap := strings.Contains(strings.Join(r.GetGaps(), "\n"), "perceptual hash")
		if (r.GetPage().GetScreenshotPhash() != "") != tc.wantHash || r.GetPage().GetScreenshotBlank() != tc.wantBlank || gap != tc.wantGap {
			t.Errorf("%s: phash=%q blank=%v gap=%v", tc.name, r.GetPage().GetScreenshotPhash(), r.GetPage().GetScreenshotBlank(), gap)
		}
	}
}
