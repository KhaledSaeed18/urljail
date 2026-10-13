package daemon

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SELinux confinement of the VMMs (P5): the urljail policy module puts jailed Firecracker in
// urljail_vmm_t. The daemon installs the module itself when it changes, and relabels its data.

const selinuxState = "/var/lib/urljail/selinux-module.sha256"

// CurrentDomain is the daemon's own SELinux type ("" when unknown).
func CurrentDomain() string {
	b, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return ""
	}
	return ctxType(bytes.TrimRight(b, "\x00\n"))
}

// SELinuxEnabled reports whether SELinux is on (enforcing or permissive).
func SELinuxEnabled() bool {
	_, err := os.Stat("/sys/fs/selinux/enforce")
	return err == nil
}

// EnsurePolicy installs the module at pp unless the same module is already loaded.
func EnsurePolicy(pp string) (installed bool, err error) {
	b, err := os.ReadFile(pp)
	if err != nil {
		return false, fmt.Errorf("SELinux policy module: %w (build it with `make selinux`)", err)
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	have, _ := os.ReadFile(selinuxState)
	if strings.TrimSpace(string(have)) == want && moduleLoaded("urljail") {
		return false, nil
	}
	if out, err := exec.Command("semodule", "-i", pp).CombinedOutput(); err != nil {
		return false, fmt.Errorf("semodule -i %s: %v: %s", pp, err, strings.TrimSpace(string(out)))
	}
	if err := os.MkdirAll(filepath.Dir(selinuxState), 0o700); err != nil {
		return true, err
	}
	return true, os.WriteFile(selinuxState, []byte(want+"\n"), 0o600)
}

func moduleLoaded(name string) bool {
	out, err := exec.Command("semodule", "-l").Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Fields(l + " ")[0] == name {
			return true
		}
	}
	return false
}

// Relabel resets paths to the labels the module's file contexts give them.
func Relabel(paths ...string) error {
	var existing []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		}
	}
	if len(existing) == 0 {
		return nil
	}
	if out, err := exec.Command("restorecon", append([]string{"-R", "-F"}, existing...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("restorecon: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// domainPermissive reports whether the module source next to pp marks the VMM domain
// permissive (development).
func domainPermissive(pp string) bool {
	te, err := os.ReadFile(strings.TrimSuffix(pp, ".pp") + ".te")
	return err == nil && regexp.MustCompile(`(?m)^\s*permissive\s+urljail_vmm_t\s*;`).Match(te)
}

var avcRe = regexp.MustCompile(`msg=audit\((\d+)\.\d+:\d+\): avc:\s+denied\s+\{ ([^}]+) \} for .*?scontext=(\S+) tcontext=(\S+) tclass=(\S+) permissive=(\d)`)

var nameRe = regexp.MustCompile(` (?:name|path)=("[^"]*"|\S+)`)

// ctxType is the type field of an SELinux context (user:role:type:range).
func ctxType(ctx []byte) string {
	if f := strings.SplitN(string(ctx), ":", 4); len(f) >= 3 {
		return f[2]
	}
	return string(ctx)
}

// urljailAVCs summarizes AVC records involving urljail types since t, most frequent first:
// "denied { read } urljail_vmm_t -> user_home_t:file (permissive) ×3".
func urljailAVCs(t time.Time) ([]string, error) {
	f, err := os.Open("/var/log/audit/audit.log")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		// urljail's own types, and named_t: the resolver's domain (Fedora's, shared with any
		// system resolver).
		if !bytes.Contains(line, []byte("avc:")) || !bytes.Contains(line, []byte("urljail_")) && !bytes.Contains(line, []byte(":named_t:")) {
			continue
		}
		m := avcRe.FindSubmatch(line)
		if m == nil {
			continue
		}
		if sec, _ := strconv.ParseInt(string(m[1]), 10, 64); sec < t.Unix() {
			continue
		}
		mode := "enforced"
		if string(m[6]) == "1" {
			mode = "permissive"
		}
		name := ""
		if n := nameRe.FindSubmatch(line); n != nil {
			name = " " + string(n[1])
		}
		counts[fmt.Sprintf("denied { %s } %s -> %s:%s%s (%s)", m[2], ctxType(m[3]), ctxType(m[4]), m[5], name, mode)]++
	}
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return counts[out[i]] > counts[out[j]] })
	for i, k := range out {
		out[i] = fmt.Sprintf("%s ×%d", k, counts[k])
	}
	return out, sc.Err()
}
