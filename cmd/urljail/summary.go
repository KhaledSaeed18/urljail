package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/report"
)

func cmdReport(args []string) error {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: urljail report <run-dir>")
		return exitError(2)
	}
	if _, err := report.Write(args[0]); err != nil {
		return err
	}
	printSummary(args[0])
	return nil
}

// printSummary prints the essentials of a run's report.json.
func printSummary(runDir string) {
	b, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		fmt.Printf("\n  run dir   %s (no report: %v)\n", runDir, err)
		return
	}
	var r reportv0.Report
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, &r); err != nil {
		fmt.Printf("\n  run dir   %s (unreadable report: %v)\n", runDir, err)
		return
	}
	n, net := r.GetNavigation(), r.GetNetwork()

	fmt.Println()
	row := func(k, v string) {
		if v != "" {
			fmt.Printf("  %-9s %s\n", k, v)
		}
	}
	row("final", n.GetFinalUrl())
	if n.GetTitle() != "" {
		row("title", fmt.Sprintf("%q", n.GetTitle()))
	}
	if n.GetError() != "" {
		row("nav error", n.GetError())
	}
	for i, h := range n.GetRedirectChain() {
		k := ""
		if i == 0 {
			k = "chain"
		}
		row(k, fmt.Sprintf("%d. %-7s %3d  %s", i+1, h.GetKind(), h.GetStatus(), h.GetUrl()))
	}
	failed := 0
	for _, q := range net.GetRequests() {
		if q.GetError() != "" {
			failed++
		}
	}
	if len(net.GetRequests()) > 0 {
		row("requests", fmt.Sprintf("%d (%d failed), %d TLS hosts", len(net.GetRequests()), failed, len(net.GetTls())))
	}
	var regs []string
	for _, d := range net.GetDomains() {
		regs = append(regs, d.GetRegistrable())
	}
	row("domains", strings.Join(regs, ", "))
	if d := r.GetPage().GetDialogs(); len(d) > 0 {
		row("dialogs", fmt.Sprint(len(d)))
	}
	if d := r.GetPage().GetDownloads(); len(d) > 0 {
		row("downloads", fmt.Sprint(len(d)))
	}
	host := fmt.Sprintf("%d flows, %d DNS replies, %d blocked destinations", len(net.GetFlows()), len(net.GetDns()), len(net.GetBlocked()))
	if rec := r.GetReconciliation(); rec != nil {
		if rec.GetConsistent() {
			host += "; consistent with the guest"
		} else {
			var parts []string
			for _, f := range rec.GetUnexplainedFlows() {
				parts = append(parts, "flow "+f)
			}
			for _, d := range rec.GetUnexplainedDns() {
				parts = append(parts, "dns "+d)
			}
			for _, g := range rec.GetGuestOnlyRequests() {
				parts = append(parts, "guest-only "+g)
			}
			host += "; NOT consistent: " + strings.Join(parts, ", ")
		}
		row("host", host)
	}
	if n.GetDwellMs() > 0 {
		row("dwell", fmt.Sprintf("%d ms (%s)", n.GetDwellMs(), n.GetDwellReason()))
	}
	row("status", r.GetRun().GetStatus())
	if s := r.GetArtifacts().GetScreenshot(); s != "" {
		row("screenshot", filepath.Join(runDir, s))
	}
	row("report", filepath.Join(runDir, "report.json"))
	row("gaps", fmt.Sprintf("%d stated in the report", len(r.GetGaps())))
}

var passwordInput = regexp.MustCompile(`(?i)<input[^>]+type=["']?password`)

// oneLine summarizes a run in one line for side-by-side profile comparison.
func oneLine(runDir string, runErr error) string {
	b, err := os.ReadFile(filepath.Join(runDir, "report.json"))
	if err != nil {
		return fmt.Sprintf("no report (%v)", runErr)
	}
	var r reportv0.Report
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, &r); err != nil {
		return "unreadable report"
	}
	n := r.GetNavigation()
	final := n.GetFinalUrl()
	if u, err := url.Parse(final); err == nil && u.Host != "" {
		final = u.Host
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("%-40.40s", final))
	if n.GetError() != "" {
		parts = append(parts, n.GetError())
	} else {
		parts = append(parts, fmt.Sprintf("%q", truncate(n.GetTitle(), 40)))
	}
	if dom, err := os.ReadFile(filepath.Join(runDir, "guest", "dom.html")); err == nil && passwordInput.Match(dom) {
		parts = append(parts, "PASSWORD FIELD")
	}
	if rec := r.GetReconciliation(); rec != nil && !rec.GetConsistent() {
		parts = append(parts, "host≠guest")
	}
	if runErr != nil {
		parts = append(parts, "error: "+runErr.Error())
	}
	return strings.Join(parts, "  ") + "  " + filepath.Base(runDir)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
