#ifndef CONFIG_H
#define CONFIG_H

struct dhcp_opts {
	__u8 mac[6];
	__u32 yiaddr;
	__u8 netmask[4];
	__u8 lease_time[4];
};

#define DEF_TIME_LEASE { 0, 0, 1, 0, } /* 256 seconds */

#endif /* CONFIG_H */
