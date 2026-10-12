// Package paths holds the default locations shared by urljaild and the CLI.
package paths

import "path/filepath"

// RunDir is urljaild's runtime directory. The daemon runs as root from P3, so it lives in /run.
const RunDir = "/run/urljail"

// Socket is the daemon's gRPC socket, owned by the operator so the CLI needs no privileges.
func Socket() string { return filepath.Join(RunDir, "urljaild.sock") }

// DataDir is where images, runs and caches live, under the operator's home:
// ~/.local/share/urljail.
func DataDir(home string) string { return filepath.Join(home, ".local", "share", "urljail") }
