package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

var faviconFile = regexp.MustCompile(`^favicon-[0-3]$`)

// favicons reads guest/favicons.json (written by the agent: URL, type and file of each favicon
// Chrome loaded) and hashes each file. Guest-supplied: sizes are capped and only the four
// expected file names are read.
func favicons(runDir string) []*reportv0.Favicon {
	b, err := os.ReadFile(filepath.Join(runDir, "guest", "favicons.json"))
	if err != nil || len(b) > 16<<10 {
		return nil
	}
	var list []struct {
		URL  string `json:"url"`
		Mime string `json:"mime"`
		File string `json:"file"`
	}
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	var out []*reportv0.Favicon
	seen := map[string]bool{}
	for _, f := range list {
		if !faviconFile.MatchString(f.File) || seen[f.File] || len(out) >= 4 {
			continue
		}
		seen[f.File] = true
		fh, err := os.Open(filepath.Join(runDir, "guest", f.File))
		if err != nil {
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(fh, 256<<10+1))
		fh.Close()
		if err != nil || n == 0 || n > 256<<10 {
			continue
		}
		out = append(out, &reportv0.Favicon{
			Url: clipString(f.URL, maxActionLen), MimeType: clipString(f.Mime, 100), Size: uint32(n),
			Sha256: hex.EncodeToString(h.Sum(nil)), File: f.File, Source: guestCDP,
		})
	}
	return out
}
