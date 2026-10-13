# P7: control plane

Status: **in progress** (started 2026-10-13)

## M1: retention

Before: 1,410 run directories, 3.9 GB, of which packet captures 3.1 GB (1,379 files); snapshots 13 GB (six profiles, all in use).

- `urljail gc [-pcap-days 7] [-pcap-cap 10G] [-dry-run] [-v]` (`internal/retention`), unprivileged: deletes `host/capture.pcap` and `guest/sslkeys.log` (the keys only decrypt that capture, and are the sensitive part) of runs older than N days, then oldest first while the total is above the cap. Runs younger than 15 min are left alone (they may be running). Each pruned run gets `host/retention.json` and its report is rebuilt: `artifacts.pcap` is empty and a gap says "Packet capture and TLS key log deleted by retention on <date> (<reason>)". Reports, metadata and the other artifacts are kept.
- First pass on the real data: nothing to delete under the default policy (everything is under a week old, 3.0 GiB < 10 GiB); with a 1 GiB cap it would delete the 905 oldest.
- Automatic: `deploy/urljail-gc.{service,timer}`, a systemd **user** timer (daily, as the operator, `NoNewPrivileges`, idle I/O), installed without root by `scripts/install-user.sh` (also puts the CLI in `~/.local/bin`). Lingering is on, so it runs while logged out.
- **Found:** two run directories were still root's: the run interrupted by the crash test and an older one. The daemon hands a run directory over only at the end of the run, so a crash leaves it root-owned, with no status and no report, and retention can't touch it. The daemon now recovers such runs at startup: status `interrupted`, handed to the operator, report built by the unprivileged helper.
