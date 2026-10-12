// Package image reads guest image directories built by images/*/build.sh.
package image

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest is an image's manifest.json.
type Manifest struct {
	Name    string `json:"name"`
	BuiltAt string `json:"built_at"`
	Urljail string `json:"urljail"`
	Base    string `json:"base"`
	Browser struct {
		Package string `json:"package"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	} `json:"browser"`
	Kernel struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"kernel"`
	Init         string `json:"init"`
	RootfsSHA256 string `json:"rootfs_sha256"`
}

// Image is a resolved image directory.
type Image struct {
	Dir      string
	Kernel   string
	Rootfs   string
	Manifest Manifest
}

// Load resolves dir (following symlinks such as images/default) and reads its manifest.
func Load(dir string) (*Image, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("image: %w", err)
	}
	b, err := os.ReadFile(filepath.Join(real, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("image %s: %w (build it with images/debian-chrome/build.sh)", real, err)
	}
	img := &Image{Dir: real}
	if err := json.Unmarshal(b, &img.Manifest); err != nil {
		return nil, fmt.Errorf("image %s: manifest: %w", real, err)
	}
	if img.Manifest.Init == "" {
		return nil, fmt.Errorf("image %s: manifest has no init (urljaild needs an image with the guest agent)", real)
	}
	if img.Kernel, err = filepath.EvalSymlinks(filepath.Join(real, "vmlinux")); err != nil {
		return nil, fmt.Errorf("image %s: kernel: %w", real, err)
	}
	img.Rootfs = filepath.Join(real, "rootfs.ext4")
	if _, err := os.Stat(img.Rootfs); err != nil {
		return nil, fmt.Errorf("image %s: %w", real, err)
	}
	return img, nil
}
