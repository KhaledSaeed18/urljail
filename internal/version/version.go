// Package version reports urljail's build version.
package version

import "runtime/debug"

// Version can be set at build time:
//
//	go build -ldflags "-X github.com/KhaledSaeed18/urljail/internal/version.Version=v0.1.0"
var Version = ""

// String returns Version, or "dev-<commit>[-dirty]" from the build's VCS info.
func String() string {
	if Version != "" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return "dev-" + rev + dirty
}
