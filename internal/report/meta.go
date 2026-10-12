// Package report derives report.json from a run directory's raw artifacts (ADR 0008).
// A report is a pure function of the run directory, so it can be regenerated at any time.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Meta is runs/<id>/meta.json: the inputs and outcome of a run, written by urljaild.
type Meta struct {
	RunID     string            `json:"run_id"`
	URL       string            `json:"url"`
	Profile   string            `json:"profile"`
	Egress    string            `json:"egress"`
	Timeout   string            `json:"timeout"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at,omitzero"`
	Status    string            `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Versions  map[string]string `json:"versions"`
	Clone     *Clone            `json:"clone,omitempty"`
	// Lifecycle steps, cumulative ms since the request: preflight, disk, netns, ebpf, capture,
	// vmm, agent, navigate (restore-to-navigation), done.
	TimingsMs map[string]int64 `json:"timings_ms,omitempty"`
	// Host-side limits hit during the run (e.g. a capped packet capture).
	HostGaps []string `json:"host_gaps,omitempty"`
}

// Clone records how a VM restored from a snapshot started (P4 clone safety).
type Clone struct {
	Snapshot         string `json:"snapshot"`
	GuestClockSkewMs int64  `json:"guest_clock_skew_ms"`
	// 16 bytes the guest read from getrandom(2) right after restore; must differ across clones.
	GuestRandom string `json:"guest_random"`
	// The guest kernel logged "crng reseeded due to virtual machine fork" (VMGenID).
	VMGenIDReseed bool `json:"vmgenid_reseed"`
}

// WriteMeta writes meta.json in runDir.
func WriteMeta(runDir string, m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, "meta.json"), append(b, '\n'), 0o600)
}

// ReadMeta reads meta.json from runDir.
func ReadMeta(runDir string) (Meta, error) {
	var m Meta
	b, err := os.ReadFile(filepath.Join(runDir, "meta.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}
