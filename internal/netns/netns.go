// Package netns builds urljail's network (docs/network.md): one namespace per VM, identical
// inside for every VM, and one shared egress namespace holding the firewall, the resolver and
// the only route out. It replaces P2's host networking. Runs as root (ADR 0014).
package netns

import "fmt"

const (
	// EgressNS holds the policy, the resolver and the exit.
	EgressNS = "uj-egress"
	// VMPrefix names per-VM namespaces: uj-vm-<slot>.
	VMPrefix = "uj-vm-"

	// Inside every VM namespace (so snapshot clones work unchanged in P4).
	TapName  = "tap0"
	TapIP    = "172.16.0.1"
	GuestIP  = "172.16.0.2"
	GuestMAC = "06:00:AC:10:00:02"
	vmVeth   = "veth-vm"

	// Dev-mode exit: a veth from the egress namespace to the host, which NATs it out.
	hostVeth   = "uj-host"
	exitVeth   = "eg-host"
	hostSideIP = "10.199.0.1"
	exitIP     = "10.199.0.2"

	tag = "urljaild" // comment on host nft rules
)

// VMNS is the namespace of VM slot n.
func VMNS(n int) string { return fmt.Sprintf("%s%d", VMPrefix, n) }

func egressVeth(n int) string { return fmt.Sprintf("veth-eg-%d", n) }

// ResolverIP is the egress-side address of slot n's link, where the VM's DNS is DNAT'd.
func ResolverIP(n int) string { return fmt.Sprintf("10.200.%d.1", n) }

// VMOutsideIP is the address slot n's traffic has once it leaves its VM namespace.
func VMOutsideIP(n int) string { return fmt.Sprintf("10.200.%d.2", n) }

// GuestBootArgs is the kernel ip= argument: the guest's address, gateway, and DNS server
// (the TAP address; the VM namespace DNATs any port-53 traffic to the resolver anyway).
func GuestBootArgs() string {
	return fmt.Sprintf("ip=%s::%s:255.255.255.252::eth0:off:%s", GuestIP, TapIP, TapIP)
}
