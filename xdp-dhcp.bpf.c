// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "config.h"

static int memcmp(const volatile __u8 *x1, const volatile __u8 *x2, int n)
{
	for (int i = 0; i < n; i++)
		if (x1[i] != x2[i])
			return (x1[i] - x2[i]);

	return 0;
}

static __always_inline int is_broadcast(void *mac_address)
{
	static __u8 broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	return !__builtin_memcpy(mac_address, broadcast, 6);
}

const volatile struct dhcp_opts opts;

struct dhcp_head {
	__u8 op;
	__u8 htype;
	__u8 hlen;
	__u8 hops;
	__u32 xid;
	__u16 secs;
	__u16 flags;
	__u32 ciaddr; /* (Client IP address) */
	__u32 yiaddr; /* (Your IP address) */
	__u32 siaddr; /* (Server IP address) */
	__u32 giaddr; /* (Gateway IP address) */
	__u8 hwaddress[16];
	__u8 opts_overflow[192];
	__u32 magic;
	__u8 opts[0]; /* variable length */
} __attribute__((packed));

struct dhcp_offer {
	struct dhcp_head head;
	__u8 opt_offer[3];
	__u8 opt_mask[6];
	__u8 opt_lease_time[6];
	__u8 opt_ff[1];
} __attribute__((packed));

static __always_inline void set_netmask(struct dhcp_offer *offer)
{
	offer->opt_mask[0] = 1;
	offer->opt_mask[1] = 4;
	offer->opt_mask[2] = opts.netmask[0];
	offer->opt_mask[3] = opts.netmask[1];
	offer->opt_mask[4] = opts.netmask[2];
	offer->opt_mask[5] = opts.netmask[3];
}

static __always_inline void set_lease_time(struct dhcp_offer *offer)
{
	offer->opt_lease_time[0] = 51;
	offer->opt_lease_time[1] = 4;
	offer->opt_lease_time[2] = opts.lease_time[0];
	offer->opt_lease_time[3] = opts.lease_time[1];
	offer->opt_lease_time[4] = opts.lease_time[2];
	offer->opt_lease_time[5] = opts.lease_time[3];
}

static int process_dhcp_discover(void *payload, void *data_end)
{
	struct dhcp_offer *offer = payload;

	if (offer + 1 > data_end) {
		return -1;
	}

	// set offer option
	offer->opt_offer[0] = 53; // opt
	offer->opt_offer[1] = 1;  // len
	offer->opt_offer[2] = 2;  // 2 = offer

	// set mask option
	set_netmask(offer);

	// set time lease option
	set_lease_time(offer);

	// terminate
	offer->opt_ff[0] = 0xff;

	offer->head.op = 0x02;
	offer->head.yiaddr = opts.yiaddr;

	return 0;
}

static int process_dhcp_request(void *payload, void *data_end)
{
	struct dhcp_offer *offer = payload;

	if (offer + 1 > data_end) {
		return -1;
	}

	// set offer option
	offer->opt_offer[0] = 53; // opt
	offer->opt_offer[1] = 1;  // len
	offer->opt_offer[2] = 5;  // 5 = ack

	set_netmask(offer);
	set_lease_time(offer);

	// terminate
	offer->opt_ff[0] = 0xff;

	offer->head.op = 0x02;
	offer->head.yiaddr = opts.yiaddr;

	return 0;
}

SEC("xdp") int dhcp_server(struct xdp_md *xdp_ctx)
{
	void *data_end = (void *)(long)xdp_ctx->data_end;
	void *data = (void *)(long)xdp_ctx->data;
	struct dhcp_head *dhcp;
	struct ethhdr *eth;
	struct udphdr *udp;
	struct iphdr *ip;

	eth = (struct ethhdr *) data;
	if (eth + 1 > data_end)
		return XDP_ABORTED;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	ip =  (struct iphdr *) (eth + 1);
	if (ip + 1 > data_end)
		return XDP_ABORTED;

	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udp = (struct udphdr *)((void *) ip + ip->ihl * 4);
	if (udp + 1 > data_end)
		return XDP_ABORTED;

	if (bpf_ntohs(udp->source) != 68 || bpf_ntohs(udp->dest) != 67) {
		/* XXX: complain about a strange packet if any of ports matches? */
		return XDP_PASS;
	}

	// XXX: do we need this? Do we care? May some clients use the learned
	// MAC from the discovery message?
	if (!is_broadcast(eth->h_dest))
		return XDP_PASS;

	// XXX this is the mac source filter, btw, we can make this optional if
	// there are filters
	if (memcmp(eth->h_source, opts.mac, 6))
		return XDP_PASS;

	dhcp = (void *) udp + 8;
	if (dhcp + 1 > data_end)
		return XDP_PASS;

	if (dhcp->op != 1)
		return XDP_PASS;
	if (dhcp->htype != 1)
		return XDP_PASS;
	if (dhcp->hlen != 6)
		return XDP_PASS;
	if (dhcp->hops != 0)
		return XDP_PASS;
	if (bpf_ntohl(dhcp->magic) != 0x63825363)
		return XDP_PASS;

	__u8 *opts = dhcp->opts;
	if (opts + 1 > data_end)
		return XDP_PASS;

	// DHCP options, we accept only 1 and 2 and ignore others
	// TBD: we assume that the message starts from the DHCP option
	if (*opts++ == 0x35) {
		if (opts + 2 > data_end)
			return XDP_PASS;
		if (opts[0] != 0x01)
			return XDP_PASS;
		if (opts[1] == 0x01) {
			if (process_dhcp_discover(dhcp, data_end) < 0)
				return XDP_PASS;
			goto tx;
		} else if (opts[1] == 0x03) {
			if (process_dhcp_request(dhcp, data_end) < 0)
				return XDP_PASS;
			goto tx;
		}
	}

	return XDP_PASS;

tx:
	udp->source = bpf_htons(67);
	udp->dest = bpf_htons(68);
	udp->check = 0;
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
