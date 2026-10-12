// Package paths holds the default locations shared by urljaild and the CLI.
package paths

import (
	"errors"
	"os"
	"path/filepath"
)

// Socket is the daemon's gRPC socket: $XDG_RUNTIME_DIR/urljail/urljaild.sock.
// The daemon runs as the operator until P5; the socket moves to /run/urljail/ when it runs as root.
func Socket() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set; pass the socket path explicitly")
	}
	return filepath.Join(dir, "urljail", "urljaild.sock"), nil
}

// DataDir is where artifacts, images and runs live: $XDG_DATA_HOME/urljail (~/.local/share/urljail).
func DataDir() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "urljail"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "urljail"), nil
}
