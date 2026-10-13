package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KhaledSaeed18/urljail/internal/paths"
	"github.com/KhaledSaeed18/urljail/internal/retention"
)

// cmdGC applies the retention policy to the operator's run directories.
func cmdGC(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	days := fs.Int("pcap-days", 7, "delete packet captures of runs older than this many days (0: no age limit)")
	capStr := fs.String("pcap-cap", "10G", `keep at most this much capture data in total, oldest deleted first ("0": no cap)`)
	dry := fs.Bool("dry-run", false, "list what would be deleted")
	verbose := fs.Bool("v", false, "list every pruned run")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	limit, err := retention.ParseSize(*capStr)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	p := retention.DefaultPolicy
	p.PcapMaxAge, p.PcapCap, p.Now, p.DryRun = time.Duration(*days)*24*time.Hour, limit, time.Now(), *dry
	res, err := retention.Prune(filepath.Join(paths.DataDir(home), "runs"), p)
	if err != nil {
		return err
	}
	if *verbose {
		for _, r := range res.Pruned {
			fmt.Printf("  %s  %9s  %s\n", r.Run, retention.Size(r.Bytes), r.Reason)
		}
	}
	for _, s := range res.Skipped {
		fmt.Fprintln(os.Stderr, "skipped:", s)
	}
	fmt.Println(res.Summary(*dry))
	return nil
}
