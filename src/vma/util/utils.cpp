/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include "utils.h"

#include <errno.h>
#include <sys/resource.h>
#include <string.h>
#include <iostream>
#include "vma/util/if.h"
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <math.h>
#include <linux/ip.h>  //IP  header (struct  iphdr) definition

#include "vlogger/vlogger.h"
#include "vma/util/sys_vars.h"
#include "vma/util/sock_addr.h"
#include "vma/sock/sock-redirect.h"
#include "vma/util/vtypes.h"
#include "vma/util/bullseye.h"

using namespace std;

#undef  MODULE_NAME
#define MODULE_NAME 		"utils:"


int check_if_regular_file(char *path)
{
	static struct stat __sys_st;

	if (stat(path, &__sys_st)== 0)
	{
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!S_ISREG(__sys_st.st_mode))
			return -1;
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	return 0;
}

int get_sys_max_fd_num(int def_max_fd /*=1024*/)
{
	struct rlimit rlim;
	BULLSEYE_EXCLUDE_BLOCK_START
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0)
		return rlim.rlim_cur;
	BULLSEYE_EXCLUDE_BLOCK_END
	return def_max_fd;
}

int get_base_interface_name(const char *if_name, char *base_ifname, size_t sz_base_ifname)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((!if_name) || (!base_ifname)) {
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	memset(base_ifname, 0, sz_base_ifname);

	if (get_vlan_base_name_from_ifname(if_name, base_ifname, sz_base_ifname)) {
		return 0;
	}

	//Am I already the base (not virtual, not alias, can be bond)
	if ((!check_device_exist(if_name, VIRTUAL_DEVICE_FOLDER) ||
		check_device_exist(if_name, BOND_DEVICE_FILE)) && !strstr(if_name, ":")) {
		snprintf(base_ifname, sz_base_ifname, "%s" ,if_name);
		return 0;
	}

	unsigned char vlan_if_address[MAX_L2_ADDR_LEN];
	const size_t ADDR_LEN = get_local_ll_addr(if_name, vlan_if_address, MAX_L2_ADDR_LEN, false);
	if (ADDR_LEN > 0) {
		struct ifaddrs *ifaddr, *ifa;
		int rc = getifaddrs(&ifaddr);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (rc == -1) {
			__log_err("getifaddrs failed");
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (!strcmp(ifa->ifa_name, if_name)) {
				continue;
			}
			if (ifa->ifa_flags & IFF_SLAVE) {
				//bond slave
				continue;
			}

			if (strstr(ifa->ifa_name, ":")) {
				//alias
				continue;
			}

			if (check_device_exist(ifa->ifa_name, VIRTUAL_DEVICE_FOLDER)) {
				//virtual
				if (!check_device_exist(ifa->ifa_name, BOND_DEVICE_FILE)) {
					continue;
				}
			}

			unsigned char tmp_mac[ADDR_LEN];
			if (ADDR_LEN == get_local_ll_addr(ifa->ifa_name, tmp_mac, ADDR_LEN, false)) {
				int size_to_compare;
				if (ADDR_LEN == ETH_ALEN) size_to_compare = ETH_ALEN;
				else size_to_compare = IPOIB_HW_ADDR_GID_LEN;
				int offset = ADDR_LEN - size_to_compare;
				if (0 == memcmp(vlan_if_address + offset, tmp_mac + offset, size_to_compare)) {
					snprintf(base_ifname, sz_base_ifname, "%s" ,ifa->ifa_name);
					freeifaddrs(ifaddr);
					__log_dbg("Found base_ifname %s for interface %s", base_ifname, if_name);
					return 0;
				}
			}
		}

		freeifaddrs(ifaddr);
	}
	snprintf(base_ifname, sz_base_ifname, "%s" ,if_name);
	__log_dbg("no base for %s", base_ifname, if_name);
	return 0;
}

unsigned short csum(const unsigned short *buf, unsigned int nshort_words)
{
	unsigned long sum = 0;

	while (nshort_words--) {
		sum += *buf;
		buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/*
 * get tcp checksum: given IP header and tcp segment (assume checksum field in TCP header contains zero)
 * matches RFC 793
 *
 * This code borrows from other places and their ideas.
 * */
unsigned short compute_tcp_checksum(const struct iphdr *p_iphdr, const uint16_t *p_ip_payload) {
    register unsigned long sum = 0;
    uint16_t tcpLen = ntohs(p_iphdr->tot_len) - (p_iphdr->ihl<<2); // shift left 2 will multiply by 4 for converting to octets

    //add the pseudo header
    //the source ip
    sum += (p_iphdr->saddr>>16)&0xFFFF;
    sum += (p_iphdr->saddr)&0xFFFF;
    //the dest ip
    sum += (p_iphdr->daddr>>16)&0xFFFF;
    sum += (p_iphdr->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    while (tcpLen > 1) {
        sum += * p_ip_payload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*p_ip_payload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //computation result
      return (unsigned short)sum;
}

/**
 * Copy iovec to buffer 
 * Returns total bytes copyed
 */
int memcpy_fromiovec(u_int8_t* p_dst, const struct iovec* p_iov, size_t sz_iov, size_t sz_src_start_offset, size_t sz_data)
{
	/* Skip to start offset  */
	int n_iovpos = 0;
	while (n_iovpos < (int)sz_iov && sz_src_start_offset >= p_iov[n_iovpos].iov_len) {
		sz_src_start_offset -= p_iov[n_iovpos].iov_len;
		n_iovpos++;
	}

	/* Copy len size into pBuf */
	int n_total = 0;
	while (n_iovpos < (int)sz_iov && sz_data > 0) {
		if (p_iov[n_iovpos].iov_len)
		{
			u_int8_t* p_src = ((u_int8_t*)(p_iov[n_iovpos].iov_base)) + sz_src_start_offset;
			int sz_data_block_to_copy = min(sz_data, p_iov[n_iovpos].iov_len - sz_src_start_offset);
			sz_src_start_offset = 0;

			memcpy(p_dst, p_src, sz_data_block_to_copy);

			p_dst += sz_data_block_to_copy;
			sz_data -= sz_data_block_to_copy;
			n_total += sz_data_block_to_copy;
		}
		n_iovpos++;
	}
	return n_total;
}

int netmask_bitcount(uint32_t netmask)
{
	// Sparse Ones runs in time proportional to the number of 1 bits.
	// The mystical line n &= (n - 1) simply sets the rightmost 1 bit in n to 0.
	int cnt = 0;
	while (netmask) {
		cnt++;
		netmask &= (netmask - 1);
	}
	return cnt;
}

void set_fd_block_mode(int fd, bool b_block)
{
	__log_dbg("fd[%d]: setting to %sblocking mode (%d)", fd, b_block?"":"non-", b_block);

	int flags = orig_os_api.fcntl(fd, F_GETFL);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (flags < 0) {
		__log_err("failed reading fd[%d] flag (rc=%d errno=%d %m)", fd, flags, errno);
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (b_block)
		flags &= ~O_NONBLOCK;
	else
		flags |=  O_NONBLOCK;

	int ret = orig_os_api.fcntl(fd, F_SETFL, flags);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		__log_err("failed changing fd[%d] to %sblocking mode (rc=%d errno=%d %m)", fd, b_block?"":"non-", flags, ret, errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return;
}

const char* iphdr_protocol_type_to_str(const int type)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	switch (type) {
	case IPPROTO_TCP:	return "TCP";
	case IPPROTO_UDP:	return "UDP";
	default:		break;
	}
	return "Not supported";
	BULLSEYE_EXCLUDE_BLOCK_END
}

int priv_read_file(const char *path, char *buf, size_t size, vlog_levels_t log_level /*= VLOG_ERROR*/)
{
	int len = -1;
	int fd = open(path, O_RDONLY);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (fd < 0) {
		VLOG_PRINTF(log_level, "ERROR while opening file %s (errno %d %m)", path, errno);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	len = read(fd, buf, size);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (len < 0) {
		VLOG_PRINTF(log_level, "ERROR while reading from file %s (errno %d %m)", path, errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	close(fd);
	return len;
}

int read_file_to_int(const char *path, int default_value){
	char buf[25];
	int rc = priv_safe_read_file(path, buf, sizeof buf);
	if (rc < 0) {
		__log_warn("ERROR while getting int from from file %s, we'll use default %d", path, default_value);
	}
	return (rc < 0) ? default_value : atoi(buf);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int is_local_addr(in_addr_t peer_ip)
{       

	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifaphead = NULL;
	in_addr_t l_ip;
	int rv = 0;

	if (!getifaddrs(&ifaphead)) {
		for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
			l_ip = get_sa_ipv4_addr(ifap->ifa_addr);
			__log_func("Examine %d.%d.%d.%d", NIPQUAD(l_ip));
			if (l_ip == peer_ip) {
				rv = 1;
				break;
			}
		}
	}
	if (ifaphead)
		freeifaddrs(ifaphead);
	return rv;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int get_ifinfo_from_ip(const struct sockaddr& addr, char* ifname, uint32_t& ifflags)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifaphead = NULL;

	__log_func("checking local interface: %d.%d.%d.%d", NIPQUAD(get_sa_ipv4_addr(addr)));

	// Get interface list info
	if (!getifaddrs(&ifaphead)) {

		// Find our interface
		for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
			if (ifap->ifa_netmask == NULL)
				continue;
			__log_func("interface '%s': %d.%d.%d.%d/%d%s%s%s%s%s%s%s%s%s%s",
					ifap->ifa_name,
					NIPQUAD(get_sa_ipv4_addr(ifap->ifa_addr)),
					netmask_bitcount(get_sa_ipv4_addr(ifap->ifa_netmask)),
					(ifap->ifa_flags & IFF_UP ? " UP":""),
					(ifap->ifa_flags & IFF_RUNNING ? " RUNNING":""),
					(ifap->ifa_flags & IFF_NOARP ? " NO_ARP":""),
					(ifap->ifa_flags & IFF_LOOPBACK ? " LOOPBACK":""),
					(ifap->ifa_flags & IFF_BROADCAST ? " BROADCAST":""),
					(ifap->ifa_flags & IFF_MULTICAST ? " MULTICAST":""),
					(ifap->ifa_flags & IFF_MASTER ? " MASTER":""),
					(ifap->ifa_flags & IFF_SLAVE ? " SLAVE":""),
					(ifap->ifa_flags & IFF_DEBUG ? " IFF_DEBUG":""),
					(ifap->ifa_flags & IFF_PROMISC ? " IFF_PROMISC":"")
			);

			if (get_sa_ipv4_addr(ifap->ifa_addr) == get_sa_ipv4_addr(addr)) {

				// Found match to users request
				// Copy specific ifaddrs info to user
				ifflags = ifap->ifa_flags;
				strncpy(ifname, ifap->ifa_name, IFNAMSIZ);
				__log_dbg("matching device found for ip '%d.%d.%d.%d' on '%s' (flags=%#X)", 
						NIPQUAD(get_sa_ipv4_addr(addr)), ifname, ifflags);
				__log_dbg("interface '%s': %d.%d.%d.%d/%d%s%s%s%s%s%s%s%s%s%s",
						ifap->ifa_name,
						NIPQUAD(get_sa_ipv4_addr(ifap->ifa_addr)),
						netmask_bitcount(get_sa_ipv4_addr(ifap->ifa_netmask)),
						(ifap->ifa_flags & IFF_UP ? " UP":""),
						(ifap->ifa_flags & IFF_RUNNING ? " RUNNING":""),
						(ifap->ifa_flags & IFF_NOARP ? " NO_ARP":""),
						(ifap->ifa_flags & IFF_LOOPBACK ? " LOOPBACK":""),
						(ifap->ifa_flags & IFF_BROADCAST ? " BROADCAST":""),
						(ifap->ifa_flags & IFF_MULTICAST ? " MULTICAST":""),
						(ifap->ifa_flags & IFF_MASTER ? " MASTER":""),
						(ifap->ifa_flags & IFF_SLAVE ? " SLAVE":""),
						(ifap->ifa_flags & IFF_DEBUG ? " IFF_DEBUG":""),
						(ifap->ifa_flags & IFF_PROMISC ? " IFF_PROMISC":"")
				);

				freeifaddrs(ifaphead);
				return 0;
			}
		}
	}
	else {
		__log_dbg("ERROR from getifaddrs() (errno=%d %m)", errno);
	}

	__log_dbg("can't find local if address %d.%d.%d.%d in ifaddr list", NIPQUAD(get_sa_ipv4_addr(addr)));

	if (ifaphead)
		freeifaddrs(ifaphead);

	return -1;
}

int get_iftype_from_ifname(const char* ifname)
{
	__log_func("find interface type for ifname '%s'", ifname);

	char iftype_filename[100];
	char iftype_value_str[32];
	char base_ifname[32];
	char iftype_value = -1;

	get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
	sprintf(iftype_filename, IFTYPE_PARAM_FILE, base_ifname);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(iftype_filename, iftype_value_str, sizeof(iftype_value_str)) > 0) {
		iftype_value = atoi(iftype_value_str);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return iftype_value;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int get_ifaddr_len_from_ifname(const char* ifname)
{
	__log_func("find interface address length for ifname '%s'", ifname);

	char ifaddr_len_filename[100];
	char ifaddr_len_value_str[32];
	char base_ifname[32];
	char ifaddr_len_value = 0;

	get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
	sprintf(ifaddr_len_filename, IFADDR_LEN_PARAM_FILE, base_ifname);
	if (priv_read_file(ifaddr_len_filename, ifaddr_len_value_str, sizeof(ifaddr_len_value_str)) > 0) {
		ifaddr_len_value = atoi(ifaddr_len_value_str);
	}
	return ifaddr_len_value;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int get_if_mtu_from_ifname(const char* ifname)
{
	__log_func("find interface mtu for ifname '%s'", ifname);

	char if_mtu_len_filename[100];
	char if_mtu_value_str[32];
	char base_ifname[32];
	int if_mtu_value = 0;

	/* initially try reading MTU from ifname. In case of failure (expected in alias ifnames) - try reading MTU from base ifname */
	sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, ifname);

	if (priv_try_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) > 0) {
		if_mtu_value = atoi(if_mtu_value_str);
	}
	else {
		get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
		sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, base_ifname);
		if (priv_try_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) > 0) {
			if_mtu_value = atoi(if_mtu_value_str);
		}
	}
	return if_mtu_value;
}

int get_igmp_max_membership()
{
	__log_func("find OS igmp_max_membership");

	char igmp_max_membership_str[32];
	int igmp_max_membership_value = 0;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(IGMP_MAX_MEMBERSHIP_FILE, igmp_max_membership_str, sizeof(igmp_max_membership_str)) > 0) {
		igmp_max_membership_value = atoi(igmp_max_membership_str);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return igmp_max_membership_value;
}

int get_window_scaling_factor(int tcp_rmem_max, int core_rmem_max)
{
	__log_func("calculate OS tcp scaling window factor");

	int scaling_factor = 0;
	int space = MAX(tcp_rmem_max, core_rmem_max);

	while (space > 0xffff && scaling_factor < MAX_WINDOW_SCALING) {
		space >>= 1;
		scaling_factor++;
	}

	__log_dbg("TCP scaling window factor is set to %d", scaling_factor);
	return scaling_factor;
}

int get_ipv4_from_ifname(char *ifname, struct sockaddr_in *addr)
{
	int ret = -1;
	__log_func("find ip addr for ifname '%s'", ifname);

	int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (fd < 0) {
		__log_err("ERROR from socket() (errno=%d %m)", errno);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, ifname, IFNAMSIZ-1);
	ret = orig_os_api.ioctl(fd, SIOCGIFADDR, &req);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		if (errno != ENODEV) {
			__log_err("Failed getting ipv4 from interface '%s' (errno=%d %m)", ifname, errno);
		}
		else {
			// Log in DEBUG (Maybe there is a better way to catch IPv6 only interfaces and not to get to this point?)
			__log_dbg("Failed getting ipv4 from interface '%s' (errno=%d %m)", ifname, errno);
		}
		orig_os_api.close(fd);
		return -1;
	}

	if (req.ifr_addr.sa_family != AF_INET) {
		__log_err("%s: address family %d is not supported", ifname, req.ifr_addr.sa_family);
		orig_os_api.close(fd);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	memcpy(addr, &req.ifr_addr, sizeof(*addr));
	orig_os_api.close(fd);
	return 0;
}

int get_ipv4_from_ifindex(int ifindex, struct sockaddr_in *addr)
{
	char if_name[IFNAMSIZ];
	//todo should we use get_base_interface after getting the name?
	BULLSEYE_EXCLUDE_BLOCK_START
	if (if_indextoname(ifindex, if_name) && get_ipv4_from_ifname(if_name, addr) == 0) {
		return 0;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return -1;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int get_mac_from_ifname(const char* ifname, unsigned char* ether_addr)
{
	__log_func("find mac addr for interface '%s'", ifname);

	int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		__log_err("ERROR from socket() (errno=%d %m)", errno);
		return -1;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	//BULLSEYE_EXCLUDE_BLOCK_START
	if (orig_os_api.ioctl(fd, SIOCGIFHWADDR, &ifr) ) {
		__log_err("ERROR from ioctl(SIOCGIFHWADDR) for interface '%s' (errno=%d %m)", ifname, errno);
		orig_os_api.close(fd);
		return -1;
	}
	//BULLSEYE_EXCLUDE_BLOCK_END

	for (int i = 0; i < ETH_ALEN; i++)
		ether_addr[i] = (uint8_t)ifr.ifr_hwaddr.sa_data[i];
	__log_dbg("found mac '%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X' for interface '%s'", 
			ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3],
			ether_addr[4], ether_addr[5], ifname);

#if 0
	// This is working but just not relevant for MAC fetch
	if (orig_os_api.ioctl(fd, SIOCGIFMTU, &ifr) ) {
		__log_err("ERROR from ioctl(SIOCGIFMTU) for interface '%s' (errno=%d %m)", ifname, errno);
		orig_os_api.close(fd);
		return -1;
	}
	__log_dbg("found mtu '%d' for interface '%s'", ifr.ifr_mtu, ifname);
#endif

	orig_os_api.close(fd);
	return 0;
}


int get_netmask_from_ifname(const char* ifname, in_addr_t *netmask)
{
	__log_func("find netmask  for interface '%s'", ifname);

	int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		__log_err("ERROR from socket() (errno=%d %m)", errno);
		return -1;
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	//BULLSEYE_EXCLUDE_BLOCK_START
	if (orig_os_api.ioctl(fd, SIOCGIFNETMASK, &ifr) ) {
		__log_err("ERROR from ioctl(SIOCGIFNETMASK) for interface '%s' (errno=%d %m)", ifname, errno);
		orig_os_api.close(fd);
		return -1;
	}
	//BULLSEYE_EXCLUDE_BLOCK_END
	*netmask = get_sa_ipv4_addr(&ifr.ifr_ifru.ifru_netmask);
	__log_dbg("found netmask '%d.%d.%d.%d' for interface '%s'", NIPQUAD(*netmask), ifname);

	orig_os_api.close(fd);
	return 0;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

uint16_t get_vlan_id_from_ifname(const char* ifname)
{
        // find vlan id from interface name
        struct vlan_ioctl_args ifr;
        int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);

        memset(&ifr,0, sizeof(ifr));
        ifr.cmd = GET_VLAN_VID_CMD;
        strncpy(ifr.device1, ifname, sizeof(ifr.device1));

        if (orig_os_api.ioctl(fd, SIOCGIFVLAN, &ifr) < 0)
        {
            __log_dbg("Failure in ioctl(SIOCGIFVLAN, cmd=GET_VLAN_VID_CMD) for interface '%s' (errno=%d %m)", ifname, errno);
            orig_os_api.close(fd);
            return 0;
        }

        orig_os_api.close(fd);

        __log_dbg("found vlan id '%d' for interface '%s'", ifr.u.VID, ifname);

        return ifr.u.VID;
}

size_t get_vlan_base_name_from_ifname(const char* ifname, char* base_ifname, size_t sz_base_ifname)
{
        // find vlan base name from interface name
        struct vlan_ioctl_args ifr;
        int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);

        memset(&ifr,0, sizeof(ifr));
        ifr.cmd = GET_VLAN_REALDEV_NAME_CMD;
        strncpy(ifr.device1, ifname, sizeof(ifr.device1));

        if (orig_os_api.ioctl(fd, SIOCGIFVLAN, &ifr) < 0)
        {
            __log_dbg("Failure in ioctl(SIOCGIFVLAN, cmd=GET_VLAN_REALDEV_NAME_CMD) for interface '%s' (errno=%d %m)", ifname, errno);
            orig_os_api.close(fd);
            return 0;
        }

        orig_os_api.close(fd);

        size_t name_len = strlen(ifr.u.device2);
        if (base_ifname && name_len > 0) {
        	__log_dbg("found vlan base name '%s' for interface '%s'", ifr.u.device2, ifname);
        	strncpy(base_ifname, ifr.u.device2, sz_base_ifname);
        	return name_len;
        }

        __log_dbg("did not find vlan base name for interface '%s'", ifname);

        return 0;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int get_peer_unicast_mac(const in_addr_t p_peer_addr, unsigned char peer_mac[ETH_ALEN])
{
	char *peer_mac_str = NULL;
	char buff[4096];
	char peer_ip_str[20];
	int bytes_read = 0;
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(p_peer_addr));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	// coverity[check_return]
	if ((bytes_read = read(fd, buff, 4095)) < 0) {
		__log_err("error reading arp table, errno %d %m", errno);
		buff[0] = '\0';
	} else {
		buff[bytes_read] = '\0';
	}
	peer_mac_str = (char *)strstr((const char*)buff, (const char*)peer_ip_str);
	if (!peer_mac_str)
		goto out;
	peer_mac_str = (char *)strstr((const char*)peer_mac_str,":");
	if (!peer_mac_str)
		goto out;
	peer_mac_str =  peer_mac_str - 2;
	peer_mac_str[17] = '\0';
	__log_dbg("resolved peer_mac=%s", peer_mac_str);
	for (int i = 0; i < ETH_ALEN; ++i)
		if (1 != sscanf(peer_mac_str + 3*i, "%2hhx", &peer_mac[i]))
			goto out;
	ret_val = 0;
out:
	if (fp)
		fclose(fp);
	return ret_val;
}

int get_peer_ipoib_qpn(const struct sockaddr* p_peer_addr, uint32_t & remote_qpn)
{
	__log_func("find neighbor info for dst ip: %d.%d.%d.%d", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));

	char peer_ip_str[20];
	char buff[4096];
	char rem_qpn_str[7] = "";
	char* p_ch = NULL;
	char* str = NULL;
	int bytes_read = 0;
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	// coverity[check_return]
	if ((bytes_read = read(fd, buff, 4095)) < 0) {
		__log_err("error reading arp table, errno %d %m", errno);
		buff[0] = '\0';
	} else {
		buff[bytes_read] = '\0';
	}
	str = (char *)strstr((const char*)buff, peer_ip_str);
	if (!str)
		goto out;
	str = (char *)strstr((const char*)str,"80:");
	if (!str)
		goto out;
	str =  str + 3;

	p_ch = strtok(str, ":");
	for (int i = 0; (i < 3 && p_ch); i++) {
		strcpy((rem_qpn_str + (i * 2)), p_ch);
		p_ch = strtok(NULL, ":");
	}
	if (sscanf(rem_qpn_str, "%x", & remote_qpn) >= 0)
		ret_val = 0;
out:
	if (fp)
		fclose(fp);
	return ret_val;
}

int get_peer_ipoib_address(const struct sockaddr* p_peer_addr, unsigned char peer_l2[20])
{
	__log_func("find neighbor info for dst ip: %d.%d.%d.%d", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));

	char peer_ip_str[20];
	char buff[4096];
	int bytes_read = 0;
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	// coverity[check_return]
	if ((bytes_read = read(fd, buff, 4095)) < 0) {
		__log_err("error reading arp table, errno %d %m", errno);
		buff[0] = '\0';
	} else {
		buff[bytes_read] = '\0';
	}
	peer_l2 = (unsigned char *)strstr((const char*)buff, peer_ip_str);
	if (!peer_l2)
		goto out;
	peer_l2 = (unsigned char *)strstr((const char*)peer_l2,"80:");
	if (!peer_l2)
		goto out;

out:
	if (fp)
		fclose(fp);
	return ret_val;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int run_and_retreive_system_command(const char* cmd_line, char* return_str, int return_str_len)
{
	// TODO: NOTICE the current code will change the environment for all threads of our process

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!cmd_line) return -1;
	if (return_str_len < 0) return_str_len = 0;
	BULLSEYE_EXCLUDE_BLOCK_END

	// 29West may load vma dynamically (like sockperf with --load-vma)
	for (int i=0; environ[i]; i++ ) {
		if ( strstr(environ[i],"LD_PRELOAD=") ) {
			environ[i][0] = '_';
		}
	}

	// run system command and get response from FILE*
	int rc = -1;

	FILE* file = popen(cmd_line, "r");
	if (file) {
		int fd = fileno(file);
		if (fd > 0) {
			int actual_len = read(fd, return_str, return_str_len);
			if (actual_len)
				return_str[min(return_str_len - 1, actual_len)] = '\0';
		}
		// Check exit status code
		rc = pclose(file);

		for (int i = 0; environ[i]; i++) {
			if (strstr(environ[i], "_D_PRELOAD=")) {
				environ[i][0] = 'L';
			}
		}
	}
	return ((!rc && return_str) ? 0 : -1);
}

bool get_local_if_info(in_addr_t local_if, char* ifname, unsigned int &ifflags)
{
	bool ret_val = true;

	sock_addr sa_if(AF_INET, local_if, INPORT_ANY);
	__log_dbg("checking local interface: %s", sa_if.to_str_in_addr());
	BULLSEYE_EXCLUDE_BLOCK_START
	if (get_ifinfo_from_ip(*sa_if.get_p_sa(), ifname, ifflags)) {
		__log_dbg("ERROR from get_ifaddrs_from_ip() (errno=%d %m)", errno);
		ret_val = false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	if (ifflags & IFF_MASTER) {
		__log_dbg("matching ip found on local device '%s' acting as bonding master", ifname);
	}
	else {
		__log_dbg("matching ip found on local device '%s'", ifname);
	}
	return ret_val;
}

size_t get_local_ll_addr(IN const char * ifname, OUT unsigned char* addr, IN int addr_len, bool is_broadcast)
{
	char l2_addr_path[256] = {0};
	char buf[256] = {0};

	// In case of alias (ib0/eth0:xx) take only the device name for that interface (ib0/eth0)
	size_t ifname_len = strcspn(ifname, ":"); // TODO: this is temp code till we get base interface for any alias format of an interface
	const char * l2_addr_path_fmt = is_broadcast ? L2_BR_ADDR_FILE_FMT : L2_ADDR_FILE_FMT;
	snprintf(l2_addr_path, sizeof(l2_addr_path)-1, l2_addr_path_fmt, ifname_len, ifname);

	int len = priv_read_file(l2_addr_path, buf, sizeof(buf));
	int bytes_len = (len + 1) / 3; // convert len from semantic of hex format L2 address with ':' delimiter (and optional newline character) into semantic of byte array
	__log_dbg("ifname=%s un-aliased-ifname=%.*s l2_addr_path=%s l2-addr=%s (addr-bytes_len=%d)", ifname, ifname_len, ifname, l2_addr_path, buf, bytes_len);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (len < 0) return 0; // failure in priv_read_file
	if (addr_len < bytes_len) return 0; // error not enough room was provided by caller
	BULLSEYE_EXCLUDE_BLOCK_END

	if (bytes_len == IPOIB_HW_ADDR_LEN && addr_len >= IPOIB_HW_ADDR_LEN) { // addr_len >= IPOIB_HW_ADDR_LEN is just for silencing coverity
		sscanf(buf, IPOIB_HW_ADDR_SSCAN_FMT, IPOIB_HW_ADDR_SSCAN(addr));
		__log_dbg("found IB %s address " IPOIB_HW_ADDR_PRINT_FMT " for interface %s", is_broadcast?"BR":"UC", IPOIB_HW_ADDR_PRINT_ADDR(addr), ifname);
	}
	else if (bytes_len == ETH_ALEN) {
		sscanf(buf, ETH_HW_ADDR_SSCAN_FMT, ETH_HW_ADDR_SSCAN(addr));
		__log_dbg("found ETH %s address" ETH_HW_ADDR_PRINT_FMT " for interface %s", is_broadcast?"BR":"UC", ETH_HW_ADDR_PRINT_ADDR(addr), ifname);
	}
	else {
		return 0; // error
	}

	return bytes_len; // success
}

bool get_bond_active_slave_name(IN const char* bond_name, OUT char* active_slave_name, IN int sz)
{
	char active_slave_path[256] = {0};
	sprintf(active_slave_path, BONDING_ACTIVE_SLAVE_PARAM_FILE, bond_name);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(active_slave_path, active_slave_name, sz) < 0)
		return false;
	if (strlen(active_slave_name) == 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(active_slave_name, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

/*
 * this function will work only for kernel  > 3.14 or RH7.2 and higher
 */
bool get_bond_slave_state(IN const char* slave_name, OUT char* curr_state, IN int sz)
{
	char bond_slave_state_path[256] = {0};
	sprintf(bond_slave_state_path, BONDING_SLAVE_STATE_PARAM_FILE, slave_name);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_safe_try_read_file(bond_slave_state_path, curr_state, sz) < 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(curr_state, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

bool get_bond_slaves_name_list(IN const char* bond_name, OUT char* slaves_list, IN int sz)
{
	char slaves_list_path[256] = {0};
	sprintf(slaves_list_path, BONDING_SLAVES_PARAM_FILE, bond_name);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(slaves_list_path, slaves_list, sz) < 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(slaves_list, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

bool check_device_exist(const char* ifname, const char *path) {
	char device_path[256] = {0};
	sprintf(device_path, path, ifname);
	int fd = orig_os_api.open(device_path, O_RDONLY);
	orig_os_api.close(fd);
	if (fd < 0 && errno == EMFILE) {
		__log_warn("There are no free fds in the system. This may cause unexpected behavior");
	}
	return (fd > 0);
}

bool get_interface_oper_state(IN const char* interface_name, OUT char* curr_state, IN int sz)
{
	char interface_state_path[256] = {0};
	sprintf(interface_state_path, OPER_STATE_PARAM_FILE, interface_name);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_safe_read_file(interface_state_path, curr_state, sz) < 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(curr_state, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

int validate_ipoib_prop(const char* ifname, unsigned int ifflags,
		const char prop_file[], const char *expected_val,
		int val_size, OUT char *filename, OUT char* base_ifname)
{
	char mode[10];
	char ifname_tmp[IFNAMSIZ];
	char active_slave_name[IFNAMSIZ];

	// In case of alias (ib0:xx) take only the device name for that interface (ib0)
	strcpy(ifname_tmp, ifname);
	base_ifname = strtok(ifname_tmp, ":");

	if (ifflags & IFF_MASTER) {
		// this is a bond interface, let find the slave
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!get_bond_active_slave_name(base_ifname, active_slave_name, IFNAMSIZ)) {
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		sprintf(filename, prop_file, active_slave_name);
	} else {
		sprintf(filename, prop_file, base_ifname);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(filename, mode, val_size) <= 0) {
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	if (strncmp(mode, expected_val, val_size)) {
		return 1;
	} else {
		return 0;
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
// convert hw address to string.
// We assume that the buff is long enough.
void convert_hw_addr_to_str(char *buf, uint8_t hw_addr_len, uint8_t *hw_addr)
{
	if (hw_addr_len > 0) {
		sprintf(buf,"%02X",hw_addr[0]);
		for(int i = 1;i <= hw_addr_len;i++){
			sprintf(buf, "%s:%02X", buf, hw_addr[i]);
		}
	}
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

//NOTE RAW_QP_PRIVLIGES_PARAM_FILE does not exist on upstream drivers
int validate_raw_qp_privliges()
{
	// RAW_QP_PRIVLIGES_PARAM_FILE: "/sys/module/ib_uverbs/parameters/disable_raw_qp_enforcement"
	char raw_qp_privliges_value = 0;
	if (priv_read_file((const char*)RAW_QP_PRIVLIGES_PARAM_FILE, &raw_qp_privliges_value, 1, VLOG_DEBUG) <= 0) {
		return -1;
	}
	if (raw_qp_privliges_value != '1') {
		return 0;
	}
	return 1;
}

loops_timer::loops_timer()
{
	m_timeout_msec = -1;
	m_timer_countdown = 0;
	m_interval_it = 2048;
	ts_clear(&m_start);
	ts_clear(&m_elapsed);
	ts_clear(&m_current);
}

void loops_timer::start()
{
	ts_clear(&m_start);
	// set to 1 so the first loop is fast and only after it m_start will be initialized
	m_timer_countdown = 1;
}

int loops_timer::time_left_msec()
{
	if ( m_timeout_msec == -1 )
		return -1;

	if (!ts_isset(&m_start)) { //VMA_RX_POLL==0
		gettime(&m_start);
	}
	timespec current;
	gettime(&current);
	ts_sub(&current, &m_start, &m_elapsed);

	//cover the case of left<0
	return (m_timeout_msec-ts_to_msec(&m_elapsed))>0 ? m_timeout_msec-ts_to_msec(&m_elapsed) : 0;
}

///////////////////////////////////////////
uint32_t fd2inode(int fd)
{
	struct stat buf;
	int rc = fstat(fd, &buf);
	return rc==0 ? buf.st_ino : 0; // no inode is 0
}

///////////////////////////////////////////
vma_error::vma_error(const char* _message, const char* _function, const char* _filename, int _lineno, int _errnum) throw()
	: message(_message), function(_function), filename(_filename), lineno(_lineno), errnum(_errnum)
{
	snprintf(formatted_message, sizeof(formatted_message), "vma_error <%s> (errno=%d %s) in %s:%d", message, errnum, strerror(errnum), filename, lineno);
	formatted_message[ sizeof(formatted_message)-1 ] = '\0';
}

vma_error::~vma_error() throw()
{
}

const char* vma_error::what() const throw()
{
	return formatted_message;
}

///////////////////////////////////////////
