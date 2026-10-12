// Package guestinfo collects facts about the guest for the agent's Hello. Guest-side only.
package guestinfo

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ChromePackage is the Debian package the image installs (ADR 0012).
const ChromePackage = "google-chrome-stable"

// AgentPort is the vsock port the guest agent listens on; the host connects with "CONNECT 1024".
const AgentPort = 1024

// PackageVersion reads a package's version from dpkg's status file, without running anything.
func PackageVersion(pkg string) string {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	found := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			found = false
		case line == "Package: "+pkg:
			found = true
		case found && strings.HasPrefix(line, "Version: "):
			return strings.TrimPrefix(line, "Version: ")
		}
	}
	return ""
}

// Kernel returns uname -r.
func Kernel() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

// Uptime reads /proc/uptime.
func Uptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	s, _ := strconv.ParseFloat(f[0], 64)
	return time.Duration(s * float64(time.Second))
}
