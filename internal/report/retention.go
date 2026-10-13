package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RetentionFile records what retention deleted from a run (internal/retention), written by
// the operator's process.
const RetentionFile = "host/retention.json"

// RetentionMeta is the content of RetentionFile.
type RetentionMeta struct {
	PrunedAt time.Time `json:"pruned_at"`
	Files    []string  `json:"files"`
	Reason   string    `json:"reason"`
}

// WriteRetention records a retention pass in a run directory.
func WriteRetention(runDir string, m RetentionMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, RetentionFile), append(b, '\n'), 0o600)
}

// retentionGap describes what retention deleted, for the report's gaps ("" if nothing).
func retentionGap(runDir string) string {
	b, err := os.ReadFile(filepath.Join(runDir, RetentionFile))
	if err != nil || len(b) > 16<<10 {
		return ""
	}
	var m RetentionMeta
	if json.Unmarshal(b, &m) != nil || m.PrunedAt.IsZero() {
		return ""
	}
	what := "Packet capture"
	for _, f := range m.Files {
		if strings.HasSuffix(f, "sslkeys.log") {
			what = "Packet capture and TLS key log"
		}
	}
	return what + " deleted by retention on " + m.PrunedAt.Format("2006-01-02") + " (" + m.Reason + ")"
}
