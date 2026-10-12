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
	Image             string    `json:"image"`
	ImageRootfsSHA256 string    `json:"image_rootfs_sha256"`
	Firecracker       string    `json:"firecracker"`
	VCPUs             int       `json:"vcpus"`
	MemMiB            int       `json:"mem_mib"`
	BootArgs          string    `json:"boot_args"`
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

const snapshotProfile = "baseline"

func (s *Server) snapshotDir() string {
	return filepath.Join(s.cfg.SnapshotsDir, s.cfg.Image.Manifest.Name+"-"+snapshotProfile)
}

// EnsureSnapshot loads the snapshot for the current image, building it if it's missing or
// was made from a different image, Firecracker or VM size.
func (s *Server) EnsureSnapshot(ctx context.Context) error {
	dir := s.snapshotDir()
	if snap, err := loadSnapshot(dir); err == nil && s.snapshotFresh(snap.manifest) {
		s.snap = snap
		s.log.Info("snapshot ready", "name", snap.manifest.Name, "created", snap.manifest.Created)
		return nil
	} else if err == nil {
		s.log.Info("snapshot is stale; rebuilding", "name", snap.manifest.Name)
	}
	snap, err := s.buildSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("building snapshot: %w", err)
	}
	s.snap = snap
	return nil
}

func (s *Server) snapshotFresh(m snapshotManifest) bool {
	img := s.cfg.Image.Manifest
	return m.Image == img.Name && m.ImageRootfsSHA256 == img.RootfsSHA256 &&
		m.Firecracker == s.cfg.FirecrackerVersion && m.VCPUs == s.cfg.VCPUs && m.MemMiB == s.cfg.MemMiB &&
		m.BootArgs == s.bootArgs()
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
// (docs/guest-image.md#snapshot-procedure-phase-4).
func (s *Server) buildSnapshot(ctx context.Context) (*snapshot, error) {
	start := time.Now()
	op, img := s.cfg.Operator, s.cfg.Image
	final := s.snapshotDir()
	tmp := final + ".build"
	_ = os.RemoveAll(tmp)
	if err := op.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	s.log.Info("building snapshot", "image", img.Manifest.Name, "dir", final)

	// Relative paths: the snapshot records them, and each clone resolves them in its own
	// working directory, where its private copy of the disk is.
	const rootfs, vsock = "rootfs.ext4", "v.sock"
	if err := vm.CloneFile(img.Rootfs, filepath.Join(tmp, rootfs)); err != nil {
		return nil, err
	}
	if err := op.Chown(filepath.Join(tmp, rootfs)); err != nil {
		return nil, err
	}
	ns, err := netns.AddIsolated(ctx, netns.BuildNS, op.UID, op.GID)
	if err != nil {
		return nil, err
	}
	defer netns.RemoveIsolated(context.WithoutCancel(ctx), ns)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	m, err := vm.Start(ctx, vm.Config{
		Firecracker: s.cfg.Firecracker,
		Socket:      filepath.Join(s.cfg.SocketDir, "build.sock"),
		LogDir:      tmp,
		Dir:         tmp,
		Kernel:      img.Kernel,
		BootArgs:    s.bootArgs(),
		Rootfs:      rootfs,
		NetNS:       ns.NS,
		RunAs:       &vm.Credential{UID: op.UID, GID: op.GID},
		TapName:     netns.TapName,
		GuestMAC:    netns.GuestMAC,
		VsockUDS:    vsock,
		VCPUs:       s.cfg.VCPUs,
		MemMiB:      s.cfg.MemMiB,
	})
	if err != nil {
		return nil, err
	}
	defer m.Kill()

	conn, err := dialAgent(filepath.Join(tmp, vsock))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	agent := guestv1.NewGuestAgentServiceClient(conn)
	if _, err := waitAgent(ctx, m, agent); err != nil {
		return nil, err
	}
	prep, err := agent.Prepare(ctx, &guestv1.PrepareRequest{})
	if err != nil {
		return nil, fmt.Errorf("preparing the browser: %w", err)
	}
	time.Sleep(snapshotSettle)
	conn.Close() // vsock connections don't survive a snapshot anyway

	if err := m.Pause(ctx); err != nil {
		return nil, err
	}
	files := vm.Snapshot{VMState: filepath.Join(tmp, "vmstate"), Mem: filepath.Join(tmp, "mem")}
	if err := m.TakeSnapshot(ctx, files); err != nil {
		return nil, err
	}
	m.Kill()

	man := snapshotManifest{
		Name: filepath.Base(final), Profile: snapshotProfile,
		Image: img.Manifest.Name, ImageRootfsSHA256: img.Manifest.RootfsSHA256,
		Firecracker: s.cfg.FirecrackerVersion, VCPUs: s.cfg.VCPUs, MemMiB: s.cfg.MemMiB, BootArgs: s.bootArgs(),
		Created: time.Now().UTC(), BuildTook: time.Since(start).Round(time.Millisecond).String(),
		PrepareTook:             prep.GetTook().AsDuration().Round(time.Millisecond).String(),
		GuestPacketsDuringBuild: tapRX(ns.NS),
	}
	b, _ := json.MarshalIndent(man, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), append(b, '\n'), 0o644); err != nil {
		return nil, err
	}
	if err := op.ChownTree(tmp); err != nil {
		return nil, err
	}
	for _, f := range []string{files.VMState, files.Mem, filepath.Join(tmp, "manifest.json")} {
		_ = os.Chmod(f, 0o600) // Firecracker writes them 0644; snapshots are the operator's alone
	}
	if err := os.RemoveAll(final); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	ok = true
	s.log.Info("snapshot built", "name", man.Name, "took", man.BuildTook, "guest_packets", man.GuestPacketsDuringBuild)
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
