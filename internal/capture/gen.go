// Package capture loads urljail's eBPF program onto a VM's TAP: flow records and the TLS
// ClientHello's SNI and ALPN, observed outside the guest (host-attested).
package capture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror -mcpu=v3" -target bpfel -type flow_key -type flow_val -type segment flow bpf/flow.c
