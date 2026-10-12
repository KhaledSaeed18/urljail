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
