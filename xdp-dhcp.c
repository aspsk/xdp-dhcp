// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov

#include <sys/resource.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <time.h>
#include <argp.h>

#include "config.h"

enum bpf_stats_type { x = 0 };

#include <bpf/bpf.h>
#include "xdp-dhcp.skel.h"

enum bpf_stats_type;
#define warn(...) fprintf(stderr, __VA_ARGS__)

struct {
	unsigned int ifindex;
	int xdp_mode;
	int verbose;
	int dryrun;
} opts = {
	.ifindex = 5,
	.verbose = 1,
	.xdp_mode = XDP_FLAGS_SKB_MODE,
};

struct dhcp_opts dhcp_opts = {
	.lease_time = DEF_TIME_LEASE,
};

static __u8 hex_to_int(char x)
{
	/* we know that @x is xdigit */
	return (x >= '0' && x <= '9') ? x - '0' : tolower(x) - 'a';
}

static int __parse_mac(const char *s, __u8 mac[6])
{
	char x1, x0;

	if (strlen(s) != 17)
		return -1;

	/* allow random separators: 01:02:03:04:05:06, 01-02-03-04-05-06,... */
	for (int i = 0; i < 6; i++) {
		x1 = s[i*3];
		x0 = s[i*3+1];
		if (!isxdigit(x1) || !isxdigit(x0))
			return -1;
		mac[i] = (hex_to_int(x1) << 4) + hex_to_int(x0);
	}

	return 0;
}

/*
 * Parse interface name or interface index.
 *
 * Example:
 *
 *  --dev 1      // maps to lo, ifindex=1
 *  --dev eth0   // maps to eth0, ifindex=3
 */
static int __parse_dev(const char *opt, unsigned int *ifindexp)
{
	const int n = strlen(opt);
	unsigned int ifindex;
	char *end;

	if (n == 0)
		return -1;

	if (isdigit(opt[0])) {
		errno = 0;
		ifindex = strtoul(opt, &end, 10);
		if (errno || *end != '\0')
			return -1;
	} else {
		ifindex = if_nametoindex(opt);
		if (!ifindex) {
			warn("if_nametoindex: %s: %s", opt, strerror(errno));
			return -1;
		}
	}

	if (ifindexp)
		*ifindexp = ifindex;
	return 0;
}

static void parse_dev(const char *prog_name, const char *opt)
{
	if (__parse_dev(opt, &opts.ifindex)) {
		warn("bad dev: '%s'\n", opt);
		exit(1);
	}
}

static void parse_mac(const char *prog_name, const char *opt)
{
	if (__parse_mac(opt, dhcp_opts.mac)) {
		warn("bad mac: '%s'\n", opt);
		exit(1);
	}
}

/* "10.2.3.4/21" */
static int __parse_ipv4_cidr(const char *s, __u32 *ip, __u8 *netmask)
{
	struct in_addr addr;
	char *d, *end;
	__u32 net;

	d = strchr(s, '/');
	if (!d || d != strrchr(s, '/'))
		return -1;

	errno = 0;
	net = strtoul(d+1, &end, 10);
	if (errno || *end != '\0' || net > 32)
		return -1;

	*d = 0;
	if (!inet_aton(s, &addr))
		return -1;

	if (ip)
		*ip = addr.s_addr;
	if (netmask) {
		if (net)
			net = (0xffffffff << (32 - net)) & 0xffffffff;
		netmask[3] =  net & 0xff;
		netmask[2] = (net & 0xff00) >> 8;
		netmask[1] = (net & 0xff0000) >> 16;
		netmask[0] = (net & 0xff000000) >> 24;
	}

	return 0;
}

static void parse_ipv4_cidr(const char *prog_name, const char *opt)
{
	char *s;
	int err;

	s = strdup(opt);
	if (!s) {
		warn("strdup: %s", strerror(errno));
		exit(1);
	}

	err = __parse_ipv4_cidr(s, &dhcp_opts.yiaddr, dhcp_opts.netmask);
	free(s);

	if (err) {
		warn("bad ip cidr: '%s'\n", opt);
		exit(1);
	}
}

/*
 * Examples:
 *
 *   --lease 60s
 *   --lease 60m
 *   --lease 24h
 */
static int __parse_lease_time_to_seconds(const char *s, __u32 *seconds)
{
	int n = strlen(s);
	char *end;
	int mul;
	long x;

	if (n < 2)
		return -1;

	switch (s[n-1]) {
	case 's':
		mul = 1;
		break;
	case 'd':
		mul = 24 * 60 * 60;
		break;
	case 'h':
		mul = 60 * 60;
		break;
	case 'm':
		mul = 60;
		break;
	default:
		return -1;
	}

	errno = 0;
	x = strtol(s, &end, 10) * mul;
	if (errno || end != s+(n-1) || x <= 0 || x > UINT_MAX)
		return -1;

	if (seconds)
		*seconds = (__u32) x;
	return 0;
}

static void parse_lease_time(const char *prog_name, const char *opt)
{
	__u32 seconds;

	if (__parse_lease_time_to_seconds(opt, &seconds)) {
		warn("bad lease time: '%s'\n", opt);
		exit(1);
	}

	dhcp_opts.lease_time[3] = seconds & 0xff;
	dhcp_opts.lease_time[2] = (seconds & 0xff00) >> 8;
	dhcp_opts.lease_time[1] = (seconds & 0xff0000) >> 16;
	dhcp_opts.lease_time[0] = (seconds & 0xff000000) >> 24;
}

#define DUMP_PFX "  "

static void opts_dump_dryrun()
{
	warn("%sdry run:  %s\n", DUMP_PFX, opts.dryrun ? "yes" : "no");
}

static void opts_dump_ifname()
{
	char buf[16];

	warn("%sifname:   %s\n", DUMP_PFX, if_indextoname(opts.ifindex, buf));
	warn("%sifindex:  %d\n", DUMP_PFX, opts.ifindex);
}

static void opts_dump_xdp_mode()
{
	warn("%sxdp mode: %s\n", DUMP_PFX,
	     opts.xdp_mode == XDP_FLAGS_SKB_MODE ?  "xdpgeneric" : "xdpdrv");
}

static void opts_dump_mac()
{
	char buf[sizeof(dhcp_opts.mac) * 3 + 1];

	for (size_t i = 0; i < sizeof(dhcp_opts.mac); i++)
		snprintf(buf + 3 * i, 3 + 1, "%02x:", dhcp_opts.mac[i]);
	buf[sizeof(buf) - 2] = '\0';

	warn("%sMAC addr: %s\n", DUMP_PFX, buf);
}

static int netmask_to_prefix_len(__u8 x[4])
{
	static const __u8 n4[16] = {
		0, 1, 1, 2,
		1, 2, 2, 3,
		1, 2, 2, 3,
		2, 3, 3, 4
	};

	return n4[x[0] >> 4] + n4[x[0] & 15] + n4[x[1] >> 4] + n4[x[1] & 15] +
	       n4[x[2] >> 4] + n4[x[2] & 15] + n4[x[3] >> 4] + n4[x[3] & 15];
}

static void opts_dump_addr()
{
	int prefix_len = netmask_to_prefix_len(dhcp_opts.netmask);
	struct in_addr addr = { .s_addr = dhcp_opts.yiaddr };

	warn("%sIP addr:  %s/%d\n", DUMP_PFX, inet_ntoa(addr), prefix_len);
}

static void opts_dump_lease_time()
{
	const __u8 *x = dhcp_opts.lease_time;
	long s = (x[0] << 24) + (x[1] << 16) + (x[2] << 8) + x[3];
	int days, hours, minutes;

	days = s / 60 / 60 / 24;
	s %= 60 * 60 * 24;

	hours = s / 60 / 60;
	s %= 60 * 60;

	minutes = s / 60;
	s %= 60;

	warn("%sLease:    %d days %d hours %d minutes\n",
	     DUMP_PFX, days, hours, minutes);
}

static void parse_options(int argc, char **argv)
{
	int c;
	int option = 0;
	const char *argv0 = *argv;
	static struct option long_options[] = {
		{"verbose",	no_argument,       0, 'v'},
		{"dry-run",	no_argument,       0, 'n'},
		{"native-xdp",	no_argument,       0, 'X'},
		{"mac",		required_argument, 0, 'm'},
		{"addr",	required_argument, 0, 'a'},
		{"lease",	required_argument, 0, 't'},
		{"dev",		required_argument, 0, 'd'},
		{0, 0, 0, 0 }
	};

	for ( ;; ) {
		c = getopt_long(argc, argv, "vnXm:a:t:d:", long_options, &option);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			opts.verbose = 1;
			break;
		case 'n':
			opts.dryrun = 1;
			break;
		case 'm':
			parse_mac(argv0, optarg);
			break;
		case 'a':
			parse_ipv4_cidr(argv0, optarg);
			break;
		case 't':
			parse_lease_time(argv0, optarg);
			break;
		case 'd':
			parse_dev(argv0, optarg);
			break;
		case 'X':
			opts.xdp_mode = XDP_FLAGS_DRV_MODE;
			break;
		default:
			warn("getopt returned character code %d\n", c);
			break;
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (opts.verbose) {
		warn("Running with the following settings:\n");

		/* controls */
		opts_dump_dryrun();
		opts_dump_ifname();
		opts_dump_xdp_mode();

		/* dhcp-related options */
		opts_dump_mac();
		opts_dump_addr();
		opts_dump_lease_time();
	}
}

static void check_mandatory_options(const char *prog_name)
{
	static const __u8 zero_netmask[sizeof(dhcp_opts.netmask)];
	static const __u8 zero_mac[sizeof(dhcp_opts.mac)];
	int err = 0;

	if (!opts.ifindex) {
		warn("--dev is mandatory\n");
		err = 1;
	}

	if (!memcmp(dhcp_opts.mac, zero_mac, sizeof(zero_mac))) {
		warn("--mac is mandatory\n");
		err = 1;
	}

	if (!dhcp_opts.yiaddr) {
		warn("--addr is mandatory\n");
		err = 1;
	}

	if (!memcmp(dhcp_opts.netmask, zero_netmask, sizeof(zero_netmask))) {
		warn("--addr is mandatory\n");
		err = 1;
	}

	if (err)
		exit(1);
}

static int xdp_attach(int prog_fd)
{
	__u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST | opts.xdp_mode;
	struct xdp_link_info info;

	/* Detach the current XDP program, if needed */
	if (!bpf_get_link_xdp_info(opts.ifindex, &info, sizeof(info), flags))
		bpf_set_link_xdp_fd(opts.ifindex, -1, flags);

	return bpf_set_link_xdp_fd(opts.ifindex, prog_fd, flags);
}

int main(int argc, char **argv)
{
	struct xdp_dhcp_bpf *obj;
	int err;

	parse_options(argc, argv);
	if (opts.dryrun)
		return 0;
	check_mandatory_options(argv[0]);

	obj = xdp_dhcp_bpf__open();
	if (!obj) {
		warn("failed to open and/or load BPF object\n");
		return -1;
	}

	memcpy(&obj->rodata->opts, &dhcp_opts, sizeof(obj->rodata->opts));

	err = xdp_dhcp_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup_obj;
	}

	err = xdp_attach(bpf_program__fd(obj->progs.dhcp_server));
	if (err) {
		warn("failed to attach BPF object: %s\n", strerror(-err));
		goto cleanup_obj;
	}

cleanup_obj:
	xdp_dhcp_bpf__destroy(obj);

	return !!err;
}
