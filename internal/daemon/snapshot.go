package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	guestv1 "github.com/KhaledSaeed18/urljail/gen/urljail/guest/v1"
	"github.com/KhaledSaeed18/urljail/internal/netns"
	"github.com/KhaledSaeed18/urljail/internal/vm"
)

// snapshotSettle is how long Chrome runs after Prepare before the VM is paused, so its
// startup work is done and not captured half-way.
const snapshotSettle = 2 * time.Second

// snapshotManifest is snapshots/<name>/manifest.json.
type snapshotManifest struct {
	Name              string    `json:"name"`
	Profile           string    `json:"profile"`
	Browser           string    `json:"browser"` // describe() of the profile
	Image             string    `json:"image"`
	ImageRootfsSHA256 string    `json:"image_rootfs_sha256"`
	Firecracker       string    `json:"firecracker"`
	VCPUs             int       `json:"vcpus"`
	MemMiB            int       `json:"mem_mib"`
	BootArgs          string    `json:"boot_args"`
	Layout            string    `json:"layout"`
	Created           time.Time `json:"created"`
	BuildTook         string    `json:"build_took"`
	PrepareTook       string    `json:"prepare_took"`
	// Packets the guest sent on its TAP while the snapshot was built. The build namespace has
	// no route out, so none of them went anywhere; this records that nothing did.
	GuestPacketsDuringBuild string `json:"guest_packets_during_build"`
}

// snapshot is a built snapshot: Chrome launched and set up, network never used (P4).
type snapshot struct {
	dir      string
	files    vm.Snapshot
	rootfs   string // the disk as it was at snapshot time; every clone gets a reflink of it
	manifest snapshotManifest
}

// snapshotLayout versions how snapshots are built and laid out; a mismatch means a rebuild.
// "jail-v1": built inside the jailer, files group-readable by jailGID (P5).
// "jail-v2": also with network and disk rate limits, which clones inherit.
const snapshotLayout = "jail-v2"

func (s *Server) snapshotDir(p browserProfile) string {
	return filepath.Join(s.cfg.SnapshotsDir, s.cfg.Image.Manifest.Name+"-"+p.name)
}

// EnsureSnapshots loads a snapshot for every browser profile, building those that are missing
// or were made from a different image, Firecracker, VM size or profile.
func (s *Server) EnsureSnapshots(ctx context.Context) error {
	snaps := map[string]*snapshot{}
	for _, p := range s.profiles {
		dir := s.snapshotDir(p)
		if snap, err := loadSnapshot(dir); err == nil && s.snapshotFresh(snap.manifest, p) {
			snaps[p.name] = snap
			s.log.Info("snapshot ready", "name", snap.manifest.Name, "created", snap.manifest.Created)
			continue
		} else if err == nil {
			s.log.Info("snapshot is stale; rebuilding", "name", snap.manifest.Name)
		}
		tmp, err := s.buildSnapshot(ctx, p)
		if err != nil {
			return fmt.Errorf("building snapshot %s: %w", p.name, err)
		}
		snap, err := s.installSnapshot(tmp, dir)
		if err != nil {
			return fmt.Errorf("installing snapshot %s: %w", p.name, err)
		}
		snaps[p.name] = snap
	}
	s.snaps = snaps
	return nil
}

func (s *Server) snapshotFresh(m snapshotManifest, p browserProfile) bool {
	img := s.cfg.Image.Manifest
	return m.Profile == p.name && m.Browser == describe(p.browser) &&
		m.Image == img.Name && m.ImageRootfsSHA256 == img.RootfsSHA256 &&
		m.Firecracker == s.cfg.FirecrackerVersion && m.VCPUs == s.cfg.VCPUs && m.MemMiB == s.cfg.MemMiB &&
		m.BootArgs == s.bootArgs() && m.Layout == snapshotLayout && !s.snapshotOld(m)
}

// snapshotOld: built longer ago than SnapshotMaxAge.
func (s *Server) snapshotOld(m snapshotManifest) bool {
	return s.cfg.SnapshotMaxAge > 0 && time.Since(m.Created) > s.cfg.SnapshotMaxAge
}

// snapshotRefreshPoll is how often RefreshSnapshots looks for old snapshots and, when it has
// one, for a moment without runs.
const snapshotRefreshPoll = time.Minute

// RefreshSnapshots rebuilds snapshots once they're older than SnapshotMaxAge, one at a time,
// while no run is active (a build is a cold boot: it would compete with clones for memory),
// until ctx ends. The old snapshot keeps serving until the new one replaces it; a failed
// build is logged and tried again later.
func (s *Server) RefreshSnapshots(ctx context.Context) {
	if s.cfg.SnapshotMaxAge <= 0 || s.snaps == nil {
		return
	}
	t := time.NewTicker(snapshotRefreshPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, p := range s.profiles {
			s.snapMu.RLock()
			old := s.snaps[p.name]
			s.snapMu.RUnlock()
			if old == nil || !s.snapshotOld(old.manifest) || s.slots.inUse() > 0 {
				continue
			}
			s.log.Info("snapshot is older than the maximum age; rebuilding", "name", old.manifest.Name,
				"created", old.manifest.Created, "max_age", s.cfg.SnapshotMaxAge)
			tmp, err := s.buildSnapshot(ctx, p)
			if err != nil {
				s.log.Warn("snapshot rebuild failed; the old one stays", "name", old.manifest.Name, "err", err)
				break
			}
			s.snapMu.Lock()
			snap, err := s.installSnapshot(tmp, s.snapshotDir(p))
			if err == nil {
				s.snaps[p.name] = snap
			}
			s.snapMu.Unlock()
			if err != nil {
				// The old snapshot's directory may be gone: runs of this profile fail until a
				// rebuild succeeds.
				s.log.Error("installing a rebuilt snapshot failed", "name", old.manifest.Name, "err", err)
			}
			break // one per poll: runs get the slots in between
		}
	}
}

func loadSnapshot(dir string) (*snapshot, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	snap := &snapshot{dir: dir, rootfs: filepath.Join(dir, "rootfs.ext4"),
		files: vm.Snapshot{VMState: filepath.Join(dir, "vmstate"), Mem: filepath.Join(dir, "mem")}}
	if err := json.Unmarshal(b, &snap.manifest); err != nil {
		return nil, err
	}
	for _, f := range []string{snap.rootfs, snap.files.VMState, snap.files.Mem} {
		if _, err := os.Stat(f); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// buildSnapshot boots the image in an isolated namespace, has the agent prepare Chrome, waits
// for it to settle, then pauses the VM and takes a full snapshot
// (docs/guest-image.md#snapshot-procedure-phase-4). It returns the directory it was built in,
// for installSnapshot.
func (s *Server) buildSnapshot(ctx context.Context, p browserProfile) (string, error) {
	start := time.Now()
	op, img := s.cfg.Operator, s.cfg.Image
	final := s.snapshotDir(p)
	tmp := final + ".build"
	_ = os.RemoveAll(tmp)
	if err := op.MkdirAll(tmp, 0o700); err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	s.log.Info("building snapshot", "image", img.Manifest.Name, "profile", p.name, "dir", final)

	// The builder is jailed like every VMM. Relative paths: the snapshot records them, and
	// each clone's jail has its own root where they resolve to its own disk and socket.
	const rootfs, vsock = "rootfs.ext4", "v.sock"
	jail := s.jailFor("build", buildSlot, netns.BuildNS)
	if err := jail.Prepare(); err != nil {
		return "", err
	}
	defer jail.Remove()
	if err := vm.CloneFile(img.Rootfs, jail.Path(rootfs)); err != nil {
		return "", err
	}
	if err := os.Chown(jail.Path(rootfs), jail.UID, jail.GID); err != nil {
		return "", err
	}
	ns, err := netns.AddIsolated(ctx, netns.BuildNS, jail.UID, jail.GID)
	if err != nil {
		return "", err
	}
	defer netns.RemoveIsolated(context.WithoutCancel(ctx), ns)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Build logs go with the run logs (urljail_run_t), not into the snapshot (read-only to VMMs).
	logDir := filepath.Join(s.cfg.DataDir, "logs", "snapshot-build")
	if err := op.MkdirAll(logDir, 0o700); err != nil {
		return "", err
	}
	if s.cfg.SELinuxModule != "" {
		if err := Relabel(logDir); err != nil {
			return "", err
		}
	}
	m, err := vm.Start(ctx, vm.Config{
		Jail:     jail,
		LogDir:   logDir,
		Kernel:   img.Kernel,
		BootArgs: s.bootArgs(),
		Rootfs:   rootfs,
		TapName:  netns.TapName,
		GuestMAC: netns.GuestMAC,
		VsockUDS: vsock,
		VCPUs:    s.cfg.VCPUs,
		MemMiB:   s.cfg.MemMiB,
		NetRx:    netRxLimit,
		NetTx:    netTxLimit,
		Disk:     diskLimit,
	})
	if err != nil {
		return "", err
	}
	defer m.Kill()

	conn, err := dialAgent(jail.Path(vsock))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	agent := guestv1.NewGuestAgentServiceClient(conn)
	if _, err := waitAgent(ctx, m, agent); err != nil {
		return "", err
	}
	prep, err := agent.Prepare(ctx, &guestv1.PrepareRequest{Profile: p.browser})
	if err != nil {
		return "", fmt.Errorf("preparing the browser: %w", err)
	}
	time.Sleep(snapshotSettle)
	conn.Close() // vsock connections don't survive a snapshot anyway

	if err := m.Pause(ctx); err != nil {
		return "", err
	}
	if err := m.TakeSnapshot(ctx, vm.Snapshot{VMState: "vmstate", Mem: "mem"}); err != nil { // inside the jail
		return "", err
	}
	// Move the snapshot and its disk out before the VMM's exit removes the jail.
	for _, f := range []string{"vmstate", "mem", rootfs} {
		if err := os.Rename(jail.Path(f), filepath.Join(tmp, f)); err != nil {
			return "", err
		}
	}
	m.Kill()
	files := vm.Snapshot{VMState: filepath.Join(tmp, "vmstate"), Mem: filepath.Join(tmp, "mem")}

	man := snapshotManifest{
		Name: filepath.Base(final), Profile: p.name, Browser: describe(p.browser),
		Image: img.Manifest.Name, ImageRootfsSHA256: img.Manifest.RootfsSHA256,
		Firecracker: s.cfg.FirecrackerVersion, VCPUs: s.cfg.VCPUs, MemMiB: s.cfg.MemMiB, BootArgs: s.bootArgs(),
		Layout: snapshotLayout, Created: time.Now().UTC(), BuildTook: time.Since(start).Round(time.Millisecond).String(),
		PrepareTook:             prep.GetTook().AsDuration().Round(time.Millisecond).String(),
		GuestPacketsDuringBuild: tapRX(ns.NS),
	}
	b, _ := json.MarshalIndent(man, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), append(b, '\n'), 0o644); err != nil {
		return "", err
	}
	if err := op.ChownTree(tmp); err != nil {
		return "", err
	}
	if err := op.ChownTree(logDir); err != nil {
		return "", err
	}
	// Clones link the snapshot into their jails and run as jail uids in jailGID: they may read
	// it, not change it. The disk is only ever reflinked, by the daemon.
	for _, f := range []string{files.VMState, files.Mem, filepath.Join(tmp, rootfs)} {
		if err := os.Chown(f, op.UID, jailGID); err != nil {
			return "", err
		}
		if err := os.Chmod(f, 0o640); err != nil {
			return "", err
		}
	}
	_ = os.Chmod(filepath.Join(tmp, "manifest.json"), 0o600)
	ok = true
	s.log.Info("snapshot built", "name", man.Name, "took", man.BuildTook, "guest_packets", man.GuestPacketsDuringBuild)
	return tmp, nil
}

// installSnapshot moves a snapshot built in tmp to final, replacing what was there. The
// caller holds snapMu for writing when runs may be restoring from final.
func (s *Server) installSnapshot(tmp, final string) (*snapshot, error) {
	if err := os.RemoveAll(final); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	// The files were created in the jail (urljail_jail_t); snapshots are read-only to VMMs.
	if s.cfg.SELinuxModule != "" {
		if err := Relabel(final); err != nil {
			return nil, err
		}
	}
	return loadSnapshot(final)
}

// tapRX is the number of packets the guest sent on tap0 in ns (the TAP's receive counter).
func tapRX(ns string) string {
	b, err := exec.Command("ip", "netns", "exec", ns, "cat", "/sys/class/net/tap0/statistics/rx_packets").Output()
	if err != nil {
		return "unknown"
	}
	return string(trimNL(b))
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
