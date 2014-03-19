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
#include <net/if.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <math.h>

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
	if ((!if_name) || (!base_ifname))
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END
	memset(base_ifname, 0, sz_base_ifname);

	//Check whether interface name is "vlan#ID"  (Usually used in SLES)
	if (strstr(if_name, "vlan")) {
		unsigned char vlan_if_address[ETH_ALEN];
		get_local_ll_addr(if_name, vlan_if_address, ETH_ALEN, false);
		struct ifaddrs *ifaddr, *ifa;

		BULLSEYE_EXCLUDE_BLOCK_START
		if (getifaddrs(&ifaddr) == -1) {
			__log_err("getifaddrs failed");
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_flags & IFF_SLAVE) {
				continue;
			}
			unsigned char tmp_mac[ETH_ALEN];
			get_local_ll_addr(ifa->ifa_name, tmp_mac, ETH_ALEN, false);
			if (!memcmp((const void*) vlan_if_address, (const void*) tmp_mac, ETH_ALEN)) {
				strcpy(base_ifname, ifa->ifa_name);
				freeifaddrs(ifaddr);
				__log_dbg("Found base_ifname %s for vlan interface %s", base_ifname, if_name);
				return 0;
			}
		}
		__log_err("Failed to find base_ifname for vlan interface %s", if_name);
		freeifaddrs(ifaddr);
		return -1;
	}
	size_t pos = strcspn(if_name,":");
	if (pos == strlen(if_name))
		pos = strcspn(if_name,".");
	if (pos >= sz_base_ifname)
		return -1;
	strncpy(base_ifname, if_name, pos);
	if (strcmp(base_ifname,if_name))
		__log_dbg("Found base_ifname %s for if_name =%s", base_ifname, if_name);
	return 0;
}

unsigned short csum(unsigned short *buf, unsigned int nwords)
{
	unsigned long sum = 0;

	while (nwords--) {
		sum += *buf;
		buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
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
		__log_panic("failed reading fd[%d] flag (rc=%d errno=%d %m)", fd, flags, errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (b_block)
		flags &= ~O_NONBLOCK;
	else
		flags |=  O_NONBLOCK;

	int ret = orig_os_api.fcntl(fd, F_SETFL, flags);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		__log_panic("failed changing fd[%d] to %sblocking mode (rc=%d errno=%d %m)", fd, b_block?"":"non-", flags, ret, errno);
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

const char* priv_vma_transport_type_str(transport_type_t transport_type)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	switch (transport_type) {
	case VMA_TRANSPORT_IB: 			return "IB";
	case VMA_TRANSPORT_ETH: 		return "ETH";
	case VMA_TRANSPORT_UNKNOWN:
	default:				break;
	}
	return "UNKNOWN";
	BULLSEYE_EXCLUDE_BLOCK_END
}

int priv_read_file(const char *path, char *buf, size_t size)
{
	int len = -1;
	int fd = orig_os_api.open(path, O_RDONLY);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (fd < 0) {
		__log_err("ERROR while opening file %s", path);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	len = orig_os_api.read(fd, buf, size);
	orig_os_api.close(fd);
	return len;
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

int get_if_mtu_from_ifname(const char* ifname, bool use_base_if)
{
	__log_func("find interface mtu for ifname '%s'", ifname);

	char if_mtu_len_filename[100];
	char if_mtu_value_str[32];
	char base_ifname[32];
	int if_mtu_value = 0;

	if (use_base_if) {
		get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
		sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, base_ifname);
	} else {
		sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, ifname);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) > 0) {
		if_mtu_value = atoi(if_mtu_value_str);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
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

int get_window_scaling_factor()
{
	__log_func("find OS tcp scaling window factor");

	char window_scaling_filename[100];
	char rmem_max_filename[100];
	char window_scaling_value_str[32];
	char rmem_max_value_str[32];
	int rmem_max_value = 0;
	int window_scaling_value = 0;
	int scaling_factor = 0;

	sprintf(window_scaling_filename, TCP_SCALING_WINDOW_FILE);
	if (priv_read_file(window_scaling_filename, window_scaling_value_str, sizeof(window_scaling_value_str)) > 0) {
		window_scaling_value = atoi(window_scaling_value_str);
		if (window_scaling_value <= 0){
			__log_dbg("TCP scaling window factor is set to -1 (disabled)");
			return -1;
		}
	} else {
		__log_dbg("Could not read tcp scaling window file = %s, disabling tcp window scaling",window_scaling_filename);
		return -1;
	}
	sprintf(rmem_max_filename, TCP_SCALING_WINDOW_MAX_RECV_MEM_FILE);
	if (priv_read_file(rmem_max_filename, rmem_max_value_str, sizeof(rmem_max_value_str)) > 0) {
		rmem_max_value = atoi(rmem_max_value_str);
		if (rmem_max_value <= 0xffff) {
			__log_dbg("TCP scaling window factor is set to 0");
			return 0;
		} else {
			scaling_factor = MIN((int)log2((double)(rmem_max_value/0xffff)) + 1, 14);
		}
	} else {
		__log_dbg("Could not read max recv memory file = %s for tcp scaling window factor. Setting tcp window scaling factor to 0.",rmem_max_filename);
		return 0;
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
	memcpy(addr, &req.ifr_addr, sizeof(struct sockaddr_in));
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
	char ifname_tmp[IFNAMSIZ];

	strcpy(ifname_tmp, ifname);
	strtok(ifname_tmp, ".");
	char * vid = strtok(NULL, ".");
	//There is no "." in an interface name
	if (vid == NULL) {
		//Check whether interface name includes "vlan"
		if(strstr(ifname, "vlan")) {
			strcpy(ifname_tmp, ifname);
			vid = (char *)strtok(ifname_tmp, "vlan");
			BULLSEYE_EXCLUDE_BLOCK_START
			if(vid == NULL){
				//No vlan!
				__log_err("Not a vlan interface '%s'", ifname);
				return 0;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
		else {
			//No vlan!
			__log_dbg("Not a vlan interface '%s'", ifname);
			return 0;
		}
	}
	uint16_t vlan_id = (uint16_t)atoi(vid);
	__log_dbg("found vlan id '%d' for interface '%s'", vlan_id, ifname);
	return vlan_id;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int get_peer_unicast_mac(const in_addr_t p_peer_addr, unsigned char peer_mac[ETH_ALEN])
{
	char *peer_mac_str = NULL;
	char buff[4096];
	char peer_ip_str[20];
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(p_peer_addr));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	read(fd, buff, 4096);
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
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	read(fd, buff, 4096);
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
	int fd = 0;
	int ret_val = -1;

	sprintf(peer_ip_str, "%d.%d.%d.%d ", NIPQUAD(get_sa_ipv4_addr(p_peer_addr)));
	FILE* fp = fopen(ARP_TABLE_FILE, "r");
	if (!fp)
		goto out;
	fd = fileno(fp);

	read(fd, buff, 4096);
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

bool get_local_ll_addr(IN const char * ifname, OUT unsigned char* addr, IN int addr_len, bool is_broadcast)
{
	char l2_addr_path[256] = {0};
	char buf[256] = {0};
	char ifname_tmp[IFNAMSIZ];
	char *base_ifname;

	// In case of alias (ib0/eth0:xx) take only the device name for that interface (ib0/eth0)
	strcpy(ifname_tmp, ifname);
	base_ifname = strtok(ifname_tmp, ":");

	if (is_broadcast) {
		sprintf(l2_addr_path, L2_BR_ADDR_FILE, base_ifname);
	} else {
		sprintf(l2_addr_path, L2_ADDR_FILE, base_ifname);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(l2_addr_path, buf, sizeof(buf)) < 0) {
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (addr_len == IPOIB_HW_ADDR_LEN) {
		sscanf(buf, IPOIB_HW_ADDR_SSCAN_FMT, IPOIB_HW_ADDR_SSCAN(addr));
		__log_dbg("found IB %s address " IPOIB_HW_ADDR_PRINT_FMT " for interface %s", is_broadcast?"BR":"UC", IPOIB_HW_ADDR_PRINT_ADDR(addr), ifname);
	}
	else if (addr_len == ETH_ALEN) {
		sscanf(buf, ETH_HW_ADDR_SSCAN_FMT, ETH_HW_ADDR_SSCAN(addr));
		__log_dbg("found ETH %s address" ETH_HW_ADDR_PRINT_FMT " for interface %s", is_broadcast?"BR":"UC", ETH_HW_ADDR_PRINT_ADDR(addr), ifname);
	}
	else {
		return false;
	}

	return true;
}

bool get_bond_active_slave_name(IN const char* bond_name, OUT char* active_slave_name, IN int sz)
{
	char active_slave_path[256] = {0};
	sprintf(active_slave_path, BONDING_ACTIVE_SLAVE_PARAM_FILE, bond_name);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (priv_read_file(active_slave_path, active_slave_name, sz) < 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(active_slave_name, '\n');
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

