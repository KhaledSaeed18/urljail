// SPDX-License-Identifier: GPL-2.0
// Flow accounting and TLS ClientHello capture on a VM's TAP (docs/network.md#host-side-capture).
// Attached with TCX to tap0 inside the VM's namespace: ingress = packets the guest sends,
// egress = packets delivered to the guest. It only observes: every packet continues (TCX_NEXT),
// and the namespace's nftables rules stay the only thing that decides.
//
//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOWS 16384
// Chrome's post-quantum ClientHello is ~1.75 KB, and with TSO/GSO the guest hands it to the
// TAP as one packet larger than the MTU (found in P3 M4), so copy well beyond one segment.
#define PAYLOAD_MAX 4096
#define HELLO_SEGMENTS 4   // data segments per outgoing TCP flow sent to userspace

// Oriented from the guest: saddr/sport are always the guest's side.
struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct flow_val {
	__u64 pkts_out;
	__u64 bytes_out;
	__u64 pkts_in;
	__u64 bytes_in;
	__u64 first_ns;
	__u64 last_ns;
	__u32 data_segs_out; // outgoing TCP segments with payload, for the ClientHello capture
	__u8 tcp_flags_out;  // OR of flags seen, each direction
	__u8 tcp_flags_in;
	__u8 pad[2];
};

// An outgoing TCP segment's payload (the start of a flow: the TLS ClientHello).
struct segment {
	struct flow_key key;
	__u64 ts_ns;
	__u32 seq;
	__u16 len;
	__u8 pad[2];
	__u8 data[PAYLOAD_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_FLOWS);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB
} segments SEC(".maps");

// Lets bpf2go generate Go types for the ring buffer records.
const struct segment *unused_segment __attribute__((unused));

static __always_inline void account(struct __sk_buff *skb, int out)
{
	struct ethhdr eth;
	struct iphdr ip;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0 || eth.h_proto != bpf_htons(ETH_P_IP))
		return;
	if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0 || ip.version != 4)
		return;
	__u32 ihl = ip.ihl * 4;
	if (ihl < sizeof(ip))
		return;
	__u32 l4 = sizeof(eth) + ihl;

	struct flow_key key = {.proto = ip.protocol};
	__u16 sport = 0, dport = 0;
	__u8 flags = 0;
	__u32 seq = 0, payload_off = 0, payload_len = 0;
	// A non-first IP fragment carries no L4 header: its bytes there are payload, not ports
	// (found in P3 follow-up: fragments showed up as flows to random ports). Account it with
	// ports 0 under its protocol.
	int fragment = (bpf_ntohs(ip.frag_off) & 0x1fff) != 0;

	if (fragment) {
		// no ports, no payload capture
	} else if (ip.protocol == IPPROTO_TCP) {
		struct tcphdr tcp;
		if (bpf_skb_load_bytes(skb, l4, &tcp, sizeof(tcp)) < 0)
			return;
		sport = tcp.source;
		dport = tcp.dest;
		flags = ((__u8 *)&tcp)[13];
		seq = bpf_ntohl(tcp.seq);
		__u32 doff = tcp.doff * 4;
		__u32 total = bpf_ntohs(ip.tot_len);
		payload_off = l4 + doff;
		if (total > ihl + doff)
			payload_len = total - ihl - doff;
	} else if (ip.protocol == IPPROTO_UDP) {
		struct udphdr udp;
		if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)) < 0)
			return;
		sport = udp.source;
		dport = udp.dest;
	}

	if (out) {
		key.saddr = ip.saddr;
		key.daddr = ip.daddr;
		key.sport = bpf_ntohs(sport);
		key.dport = bpf_ntohs(dport);
	} else {
		key.saddr = ip.daddr;
		key.daddr = ip.saddr;
		key.sport = bpf_ntohs(dport);
		key.dport = bpf_ntohs(sport);
	}

	__u64 now = bpf_ktime_get_ns();
	struct flow_val *v = bpf_map_lookup_elem(&flows, &key);
	if (!v) {
		struct flow_val init = {.first_ns = now};
		bpf_map_update_elem(&flows, &key, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&flows, &key);
		if (!v)
			return;
	}
	v->last_ns = now;
	if (out) {
		__sync_fetch_and_add(&v->pkts_out, 1);
		__sync_fetch_and_add(&v->bytes_out, skb->len);
		v->tcp_flags_out |= flags;
	} else {
		__sync_fetch_and_add(&v->pkts_in, 1);
		__sync_fetch_and_add(&v->bytes_in, skb->len);
		v->tcp_flags_in |= flags;
	}

	// The first data segments the guest sends on a TCP flow carry the TLS ClientHello.
	if (!out || ip.protocol != IPPROTO_TCP || payload_len == 0)
		return;
	if (__sync_fetch_and_add(&v->data_segs_out, 1) >= HELLO_SEGMENTS)
		return;
	struct segment *s = bpf_ringbuf_reserve(&segments, sizeof(*s), 0);
	if (!s)
		return;
	__u32 n = payload_len;
	if (n > PAYLOAD_MAX)
		n = PAYLOAD_MAX;
	if (n == 0 || bpf_skb_load_bytes(skb, payload_off, s->data, n) < 0) {
		bpf_ringbuf_discard(s, 0);
		return;
	}
	s->key = key;
	s->ts_ns = now;
	s->seq = seq;
	s->len = n;
	bpf_ringbuf_submit(s, 0);
}

SEC("tcx/ingress")
int tap_ingress(struct __sk_buff *skb)
{
	account(skb, 1);
	return TCX_NEXT;
}

SEC("tcx/egress")
int tap_egress(struct __sk_buff *skb)
{
	account(skb, 0);
	return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
