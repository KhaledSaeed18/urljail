// Package retention prunes what grows without bound in run directories (P7,
// docs/architecture.md#storage-layout-per-run): packet captures, with the TLS key logs that
// exist only to decrypt them, after a number of days and under a total size cap, oldest first.
// Reports, metadata and the other artifacts are kept. It runs as the operator, who owns the
// run directories; nothing here needs privileges.
package retention

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/KhaledSaeed18/urljail/internal/report"
)

// Policy says what to keep.
type Policy struct {
	PcapMaxAge time.Duration // delete captures of runs older than this (0: no age limit)
	PcapCap    int64         // and keep at most this many capture bytes in total (0: no cap)
	MinAge     time.Duration // never touch runs younger than this (they may still be running)
	Now        time.Time
	DryRun     bool
}

// DefaultPolicy keeps a week of captures and at most 10 GiB.
var DefaultPolicy = Policy{PcapMaxAge: 7 * 24 * time.Hour, PcapCap: 10 << 30, MinAge: 15 * time.Minute}

// Pruned is one run whose capture was (or, in a dry run, would be) deleted.
type Pruned struct {
	Run    string
	Bytes  int64
	Reason string
}

// Result sums up a pass.
type Result struct {
	Pruned   []Pruned
	Freed    int64
	Kept     int64    // capture bytes left
	KeptRuns int      // runs with a capture left
	Skipped  []string // runs that couldn't be pruned (not ours, errors)
}

// Pruned files, relative to a run directory.
var prunedFiles = []string{"host/capture.pcap", "guest/sslkeys.log"}

type run struct {
	dir   string
	start time.Time
	pcap  int64
}

// Prune applies p to every run directory in runsDir.
func Prune(runsDir string, p Policy) (Result, error) {
	var res Result
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return res, err
	}
	var runs []run
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(runsDir, e.Name())
		fi, err := os.Stat(filepath.Join(dir, prunedFiles[0]))
		if err != nil {
			continue // no capture (never had one, or already pruned)
		}
		runs = append(runs, run{dir: dir, start: startOf(dir, e.Name()), pcap: fi.Size()})
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].start.Before(runs[j].start) })
	var total int64
	for _, r := range runs {
		total += r.pcap
	}
	for _, r := range runs {
		age := p.Now.Sub(r.start)
		reason := ""
		switch {
		case age < p.MinAge:
		case p.PcapMaxAge > 0 && age > p.PcapMaxAge:
			reason = fmt.Sprintf("older than %s", days(p.PcapMaxAge))
		case p.PcapCap > 0 && total > p.PcapCap:
			reason = fmt.Sprintf("captures above the %s cap", Size(p.PcapCap))
		}
		if reason == "" {
			res.Kept += r.pcap
			res.KeptRuns++
			continue
		}
		if !p.DryRun {
			if err := prune(r.dir, reason, p.Now); err != nil {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", filepath.Base(r.dir), err))
				res.Kept += r.pcap
				res.KeptRuns++
				continue
			}
		}
		total -= r.pcap
		res.Freed += r.pcap
		res.Pruned = append(res.Pruned, Pruned{Run: filepath.Base(r.dir), Bytes: r.pcap, Reason: reason})
	}
	return res, nil
}

func prune(dir, reason string, now time.Time) error {
	var removed []string
	for _, f := range prunedFiles {
		err := os.Remove(filepath.Join(dir, f))
		switch {
		case err == nil:
			removed = append(removed, f)
		case errors.Is(err, fs.ErrNotExist):
		default:
			return err
		}
	}
	if err := report.WriteRetention(dir, report.RetentionMeta{PrunedAt: now.UTC(), Files: removed, Reason: reason}); err != nil {
		return err
	}
	_, err := report.Write(dir) // the report now lists the gap
	return err
}

// startOf is the run's start: meta.json, else the UUIDv7 run ID's timestamp, else the mtime.
func startOf(dir, name string) time.Time {
	if m, err := report.ReadMeta(dir); err == nil && !m.StartedAt.IsZero() {
		return m.StartedAt
	}
	if id, err := uuid.Parse(name); err == nil && id.Version() == 7 {
		sec, nsec := id.Time().UnixTime()
		return time.Unix(sec, nsec)
	}
	if fi, err := os.Stat(dir); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func days(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	}
	return d.String()
}

// Size formats bytes as KiB/MiB/GiB.
func Size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ParseSize reads "10G", "500M", "2048K" or plain bytes.
func ParseSize(s string) (int64, error) {
	var n float64
	var unit string
	if _, err := fmt.Sscanf(s, "%f%s", &n, &unit); err != nil {
		if _, err := fmt.Sscanf(s, "%f", &n); err != nil {
			return 0, fmt.Errorf("size %q: %w", s, err)
		}
	}
	mult := map[string]float64{"": 1, "K": 1 << 10, "KB": 1 << 10, "KIB": 1 << 10, "M": 1 << 20, "MB": 1 << 20, "MIB": 1 << 20,
		"G": 1 << 30, "GB": 1 << 30, "GIB": 1 << 30, "T": 1 << 40, "TB": 1 << 40, "TIB": 1 << 40}
	m, ok := mult[toUpper(unit)]
	if !ok || n < 0 {
		return 0, fmt.Errorf("size %q: unknown unit", s)
	}
	return int64(n * m), nil
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// Summary is a one-line description of a result.
func (r Result) Summary(dry bool) string {
	verb := "deleted"
	if dry {
		verb = "would delete"
	}
	return fmt.Sprintf("%s %d captures (%s); kept %d (%s)", verb, len(r.Pruned), Size(r.Freed), r.KeptRuns, Size(r.Kept))
}
