package netns

import (
	"context"
	"fmt"
	"strconv"
)

// VM is one VM's namespace.
type VM struct {
	Slot int
	NS   string
}

// AddVM creates slot n's namespace: tap0 (owned by uid/gid, so an unprivileged Firecracker can
// open it), the link to the egress namespace, and the VM ruleset.
func (e *Egress) AddVM(ctx context.Context, n, uid, gid int) (*VM, error) {
	ns, veth := VMNS(n), egressVeth(n)
	// The slot is ours, so a namespace with its name is a leftover.
	if err := deleteNS(ctx, ns); err == nil {
		e.log.Warn("removed stale VM namespace", "netns", ns)
	}
	vm := &VM{Slot: n, NS: ns}
	steps := [][]string{
		{"netns", "add", ns},
		{"-n", ns, "link", "set", "lo", "up"},
		{"-n", ns, "tuntap", "add", "dev", TapName, "mode", "tap", "user", strconv.Itoa(uid), "group", strconv.Itoa(gid)},
		{"-n", ns, "link", "set", TapName, "address", TapMAC},
		{"-n", ns, "addr", "add", TapIP + "/30", "dev", TapName},
		{"-n", ns, "link", "set", TapName, "up"},
		{"-n", ns, "link", "add", vmVeth, "type", "veth", "peer", "name", veth, "netns", EgressNS},
		{"-n", ns, "addr", "add", VMOutsideIP(n) + "/30", "dev", vmVeth},
		{"-n", ns, "link", "set", vmVeth, "up"},
		{"-n", ns, "route", "add", "default", "via", ResolverIP(n)},
		{"-n", EgressNS, "addr", "add", ResolverIP(n) + "/30", "dev", veth},
		{"-n", EgressNS, "link", "set", veth, "up"},
	}
	for _, s := range steps {
		if err := ip(ctx, s...); err != nil {
			e.RemoveVM(ctx, vm)
			return nil, err
		}
	}
	if err := sysctls(ctx, ns, "net.ipv4.ip_forward=1",
		"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"); err != nil {
		e.RemoveVM(ctx, vm)
		return nil, err
	}
	hash, err := loadRules(ctx, ns, vmRules, struct{ Tap, Veth, Resolver string }{TapName, vmVeth, ResolverIP(n)})
	if err != nil {
		e.RemoveVM(ctx, vm)
		return nil, err
	}
	e.mu.Lock()
	e.vmHashes[n] = hash
	e.mu.Unlock()
	return vm, nil
}

// VerifyVM checks the VM namespace's ruleset is still exactly what AddVM loaded.
func (e *Egress) VerifyVM(ctx context.Context, vm *VM) error {
	e.mu.Lock()
	want := e.vmHashes[vm.Slot]
	e.mu.Unlock()
	if h, err := rulesHash(ctx, vm.NS); err != nil || h != want {
		return fmt.Errorf("VM ruleset in %s changed or unreadable: %v", vm.NS, err)
	}
	return nil
}

// RemoveVM deletes the VM's namespace, which destroys its TAP and both ends of its veth.
// Call it after the VMM has exited.
func (e *Egress) RemoveVM(ctx context.Context, vm *VM) {
	e.mu.Lock()
	delete(e.vmHashes, vm.Slot)
	e.mu.Unlock()
	if pids := killAll(ctx, vm.NS); len(pids) > 0 {
		e.log.Warn("killed processes left in the VM namespace", "netns", vm.NS, "pids", pids)
	}
	if err := ip(ctx, "netns", "del", vm.NS); err != nil {
		e.log.Warn("deleting VM namespace", "netns", vm.NS, "err", err)
	}
}

// BuildNS is the namespace snapshots are built in.
const BuildNS = VMPrefix + "build"

// AddIsolated creates a VM namespace with tap0 configured exactly like AddVM's, but with no link
// to the egress namespace: whatever the guest sends goes nowhere. Snapshots are built in it,
// so the snapshot holds no network state (docs/guest-image.md#snapshot-procedure-phase-4).
func AddIsolated(ctx context.Context, ns string, uid, gid int) (*VM, error) {
	_ = deleteNS(ctx, ns)
	vm := &VM{Slot: -1, NS: ns}
	for _, s := range [][]string{
		{"netns", "add", ns},
		{"-n", ns, "link", "set", "lo", "up"},
		{"-n", ns, "tuntap", "add", "dev", TapName, "mode", "tap", "user", strconv.Itoa(uid), "group", strconv.Itoa(gid)},
		{"-n", ns, "link", "set", TapName, "address", TapMAC},
		{"-n", ns, "addr", "add", TapIP + "/30", "dev", TapName},
		{"-n", ns, "link", "set", TapName, "up"},
	} {
		if err := ip(ctx, s...); err != nil {
			_ = deleteNS(ctx, ns)
			return nil, err
		}
	}
	return vm, nil
}

// RemoveIsolated deletes a namespace made by AddIsolated.
func RemoveIsolated(ctx context.Context, vm *VM) error { return deleteNS(ctx, vm.NS) }
