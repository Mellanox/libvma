/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
#include <limits>
#include <math.h>
#include <linux/ip.h>  //IP  header (struct  iphdr) definition
#ifdef HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h> // ioctl(SIOCETHTOOL)
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/sys_vars.h"
#include "vma/util/sock_addr.h"
#include "vma/sock/sock-redirect.h"
#include "vma/util/vtypes.h"
#include "vma/ib/base/verbs_extra.h"

#ifdef HAVE_SYS_CAPABILITY_H
	#include <sys/capability.h>
#endif

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
				if (0 == memcmp(vlan_if_address + offset, tmp_mac + offset, size_to_compare) && 0 == (ifa->ifa_flags & IFF_MASTER)) {
					// A bond name cannot be a base name of an interface even if both have the same MAC(ethernet) or GID(IB) addresses
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

void print_roce_lag_warnings(char* interface, char* disable_path /* = NULL */, const char* port1 /* = NULL */, const char* port2 /* = NULL */)
{
	vlog_printf(VLOG_WARNING,"******************************************************************************************************\n");

	if (port1 && port2) {
		vlog_printf(VLOG_WARNING,"* Bond %s has two slaves of the same device while RoCE LAG is enabled (%s, %s).\n", interface, port1, port2);
		vlog_printf(VLOG_WARNING,"* Unexpected behaviour may occur during runtime.\n");
	} else {
		vlog_printf(VLOG_WARNING,"* Interface %s will not be offloaded.\n", interface);
		vlog_printf(VLOG_WARNING,"* VMA cannot offload the device while RoCE LAG is enabled.\n");
	}

	vlog_printf(VLOG_WARNING,"* Please refer to VMA Release Notes for more info\n");

	if (disable_path) {
		vlog_printf(VLOG_WARNING,"* In order to disable RoCE LAG please use:\n");
		vlog_printf(VLOG_WARNING,"* echo 0 > %s\n", disable_path);
	}
	vlog_printf(VLOG_WARNING,"******************************************************************************************************\n");
}

void compute_tx_checksum(mem_buf_desc_t* p_mem_buf_desc, bool l3_csum, bool l4_csum)
{
	// L3
	if (l3_csum) {
		struct iphdr* ip_hdr = p_mem_buf_desc->tx.p_ip_h;
		ip_hdr->check = 0; // use 0 at csum calculation time
		ip_hdr->check = compute_ip_checksum((unsigned short *)ip_hdr, ip_hdr->ihl * 2);

		// L4
		if (l4_csum) {
			if (ip_hdr->protocol == IPPROTO_UDP) {
				struct udphdr* udp_hdr = p_mem_buf_desc->tx.p_udp_h;
				udp_hdr->check = 0;
				__log_entry_func("using SW checksum calculation: ip_hdr->check=%d, udp_hdr->check=%d", ip_hdr->check, udp_hdr->check);
			} else if (ip_hdr->protocol == IPPROTO_TCP) {
				struct tcphdr* tcp_hdr = p_mem_buf_desc->tx.p_tcp_h;
				tcp_hdr->check = 0;
				tcp_hdr->check = compute_tcp_checksum(ip_hdr, (const uint16_t *)tcp_hdr);
				__log_entry_func("using SW checksum calculation: ip_hdr->check=%d, tcp_hdr->check=%d", ip_hdr->check, tcp_hdr->check);
			}
		}
	}
}

unsigned short compute_ip_checksum(const unsigned short *buf, unsigned int nshort_words)
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
unsigned short compute_tcp_checksum(const struct iphdr *p_iphdr, const uint16_t *p_ip_payload)
{
    register unsigned long sum = 0;
    uint16_t tcpLen = ntohs(p_iphdr->tot_len) - (p_iphdr->ihl<<2); // shift left 2 will multiply by 4 for converting to octets

    //add the pseudo header
    //the source ip
    sum += (p_iphdr->saddr >> 16) & 0xFFFF;
    sum += (p_iphdr->saddr) & 0xFFFF;
    //the dest ip
    sum += (p_iphdr->daddr >> 16) & 0xFFFF;
    sum += (p_iphdr->daddr) & 0xFFFF;
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

/* set udp checksum: given IP header and UDP datagram
 *
 * (assume checksum field in UDP header contains zero)
 * This code borrows from other places and their ideas.
 * Although according to rfc 768, If the computed checksum is zero, it is transmitted as all ones -
 * this method will return the original value.
 */
unsigned short compute_udp_checksum_rx(const struct iphdr *p_iphdr, const struct udphdr *udphdrp, mem_buf_desc_t* p_rx_wc_buf_desc)
{
    register unsigned long sum = 0;
    unsigned short udp_len = htons(udphdrp->len);
    const uint16_t *p_ip_payload = (const uint16_t *) udphdrp;
    mem_buf_desc_t *p_ip_frag = p_rx_wc_buf_desc;
    unsigned short ip_frag_len = p_ip_frag->rx.frag.iov_len + sizeof(struct udphdr);
    unsigned short ip_frag_remainder = ip_frag_len;

    //add the pseudo header
    sum += (p_iphdr->saddr >> 16) & 0xFFFF;
    sum += (p_iphdr->saddr) & 0xFFFF;
    //the dest ip
    sum += (p_iphdr->daddr >> 16) & 0xFFFF;
    sum += (p_iphdr->daddr) & 0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;

    //add the IP payload
    while (udp_len > 1) {
        // Each packet but the last must contain a payload length that is a multiple of 8
        if (!ip_frag_remainder && p_ip_frag->p_next_desc) {
            p_ip_frag = p_ip_frag->p_next_desc;
            p_ip_payload = (const uint16_t *) p_ip_frag->rx.frag.iov_base;
            ip_frag_remainder = ip_frag_len = p_ip_frag->rx.frag.iov_len;
        }

        while (ip_frag_remainder > 1) {
            sum += * p_ip_payload++;
            ip_frag_remainder -= 2;
        }

        udp_len -= (ip_frag_len - ip_frag_remainder);
    }

    //if any bytes left, pad the bytes and add
    if(udp_len > 0) {
        sum += ((*p_ip_payload)&htons(0xFF00));
    }

    //Fold sum to 16 bits: add carrier to result
    while (sum >> 16) {
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

bool compare_double(double a, double b)
{
	return fabs(a - b) < std::numeric_limits<double>::epsilon();
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

int read_file_to_int(const char *path, int default_value)
{
	char buf[25];
	int rc = priv_safe_read_file(path, buf, sizeof buf);
	if (rc < 0) {
		__log_warn("ERROR while getting int from from file %s, we'll use default %d", path, default_value);
	}
	return (rc < 0) ? default_value : atoi(buf);
}

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

int get_port_from_ifname(const char* ifname)
{
	int port_num, dev_id = -1, dev_port = -1;
	// Depending of kernel version and OFED stack the files containing dev_id and dev_port may not exist.
	// if file reading fails *dev_id or *dev_port may remain unmodified
	char num_buf[24] = {0};
	char dev_path[256] = {0};
	snprintf(dev_path, sizeof(dev_path), VERBS_DEVICE_PORT_PARAM_FILE, ifname);
	if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
		dev_port = strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
		__log_dbg("dev_port file=%s dev_port str=%s dev_port val=%d", dev_path, num_buf, dev_port);
	}
	snprintf(dev_path, sizeof(dev_path), VERBS_DEVICE_ID_PARAM_FILE, ifname);
	if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
		dev_id = strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
		__log_dbg("dev_id file= %s dev_id str=%s dev_id val=%d", dev_path, num_buf, dev_id);
	}

	// take the max between dev_port and dev_id as port number
	port_num = (dev_port > dev_id) ? dev_port : dev_id;
	return ++port_num;
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

int get_if_mtu_from_ifname(const char* ifname)
{
	__log_func("find interface mtu for ifname '%s'", ifname);

	char if_mtu_len_filename[100];
	char if_mtu_value_str[32];
	char base_ifname[32];
	int if_mtu_value = 0;

	/* initially try reading MTU from ifname. In case of failure (expected in alias ifnames) - try reading MTU from base ifname */
	sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, ifname);

	if (priv_safe_try_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) > 0) {
		if_mtu_value = atoi(if_mtu_value_str);
	}
	else {
		get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
		sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, base_ifname);
		if (priv_safe_try_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) > 0) {
			if_mtu_value = atoi(if_mtu_value_str);
		}
	}
	return if_mtu_value;
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
			__log_dbg("Failed getting ipv4 from interface '%s' (errno=%d %m)", ifname, errno);
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

uint16_t get_vlan_id_from_ifname(const char* ifname)
{
        // find vlan id from interface name
        struct vlan_ioctl_args ifr;
        int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0) {
            __log_err("ERROR from socket() (errno=%d %m)", errno);
            return -1;
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.cmd = GET_VLAN_VID_CMD;
        strncpy(ifr.device1, ifname, sizeof(ifr.device1) - 1);

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
        if (fd < 0) {
            __log_err("ERROR from socket() (errno=%d %m)", errno);
            return -1;
        }
        memset(&ifr,0, sizeof(ifr));
        ifr.cmd = GET_VLAN_REALDEV_NAME_CMD;
        strncpy(ifr.device1, ifname, sizeof(ifr.device1) - 1);

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

int run_and_retreive_system_command(const char* cmd_line, char* return_str, int return_str_len)
{
	// TODO: NOTICE the current code will change the environment for all threads of our process

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!cmd_line) return -1;
	if (return_str_len <= 0) return -1;
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
			int actual_len = read(fd, return_str, return_str_len - 1);
			if (actual_len > 0) {
				return_str[actual_len] = '\0';
			} else {
				return_str[0] = '\0';
			}
		}

		// Check exit status code
		rc = pclose(file);
		if (rc == -1 && errno == ECHILD) {
			/* suppress a case when termination status can be unavailable to pclose() */
			rc = 0;
		}

		for (int i = 0; environ[i]; i++) {
			if (strstr(environ[i], "_D_PRELOAD=")) {
				environ[i][0] = 'L';
			}
		}
	}
	return ((!rc && return_str) ? 0 : -1);
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
	if (priv_safe_read_file(active_slave_path, active_slave_name, sz) < 0)
		return false;
	if (strlen(active_slave_name) == 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(active_slave_name, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

bool check_bond_roce_lag_exist(OUT char* bond_roce_lag_path, int sz, IN const char* slave_name)
{
	char sys_res[1024] = {0};
	snprintf(bond_roce_lag_path, sz, BONDING_ROCE_LAG_FILE, slave_name);
	if (priv_read_file(bond_roce_lag_path, sys_res, 1024, VLOG_FUNC) > 0) {
		if (strtol(sys_res, NULL,10) > 0 && errno != ERANGE) {
			return true;
		}
	}

	return false;
}

bool get_netvsc_slave(IN const char* ifname, OUT char* slave_name, OUT unsigned int &slave_flags)
{
	char netvsc_path[256];
	char base_ifname[IFNAMSIZ];
	get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
	struct ifaddrs *ifaddr, *ifa;
	bool ret = false;

	if (getifaddrs(&ifaddr) == -1) {
		__log_err("getifaddrs() failed (errno = %d %m)", errno);
		return ret;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		snprintf(netvsc_path, sizeof(netvsc_path), NETVSC_DEVICE_LOWER_FILE, base_ifname, ifa->ifa_name);
		int fd = open(netvsc_path, O_RDONLY);
		if (fd >= 0) {
			close(fd);
			memcpy(slave_name, ifa->ifa_name, IFNAMSIZ);
			slave_flags = ifa->ifa_flags;
			__log_dbg("Found slave_name = %s, slave_flags = %u", slave_name, slave_flags);
			ret = true;
			break;
		}
	}

	freeifaddrs(ifaddr);

	return ret;
}

bool check_netvsc_device_exist(const char* ifname)
{
	char device_path[256] = {0};
	char base_ifname[IFNAMSIZ];
	get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
	sprintf(device_path, NETVSC_DEVICE_CLASS_FILE, base_ifname);
	char sys_res[1024] = {0};
	if (priv_read_file(device_path, sys_res, 1024, VLOG_FUNC) > 0) {
		if (strcmp(sys_res, NETVSC_ID) == 0) {
			return true;
		}
	}

	return false;
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
	if (priv_safe_read_file(slaves_list_path, slaves_list, sz) < 0)
		return false;
	BULLSEYE_EXCLUDE_BLOCK_END
	char* p = strchr(slaves_list, '\n');
	if (p) *p = '\0'; // Remove the tailing 'new line" char
	return true;
}

bool check_device_exist(const char* ifname, const char *path)
{
	char device_path[256] = {0};
	sprintf(device_path, path, ifname);
	int fd = orig_os_api.open(device_path, O_RDONLY);
	if (fd >= 0)
		orig_os_api.close(fd);
	if (fd < 0 && errno == EMFILE) {
		__log_warn("There are no free fds in the system. This may cause unexpected behavior");
	}
	return (fd > 0);
}

bool check_device_name_ib_name(const char* ifname, const char* ibname)
{
	int n = -1;
	int fd = -1;
	char ib_path[IBV_SYSFS_PATH_MAX]= {0};

	n = snprintf(ib_path, sizeof(ib_path), "/sys/class/infiniband/%s/device/net/%s/ifindex",
			ibname, ifname);
	if (likely((0 < n) && (n < (int)sizeof(ib_path)))) {
		fd = open(ib_path, O_RDONLY);
		if (fd >= 0) {
			close(fd);
			return true;
		}
	}

	return false;
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
	strncpy(ifname_tmp, ifname, sizeof(ifname_tmp) - 1);
	ifname_tmp[sizeof(ifname_tmp) - 1] = '\0';
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

bool validate_user_has_cap_net_raw_privliges()
{
#ifdef HAVE_SYS_CAPABILITY_H
	struct __user_cap_header_struct cap_header;
	cap_user_header_t cap_header_ptr = &cap_header;
	struct __user_cap_data_struct cap_data;
	cap_user_data_t cap_data_ptr = &cap_data;
	cap_header_ptr->pid = getpid();
	cap_header_ptr->version = _LINUX_CAPABILITY_VERSION;
	 if(capget(cap_header_ptr, cap_data_ptr)  < 0) {
		 __log_dbg("error getting cap_net_raw permissions (%d %m)", errno);
		 return false;
	 } else {
		 __log_dbg("successfully got cap_net_raw permissions. Effective=%X Permitted=%X", cap_data_ptr->effective, cap_data_ptr->permitted);
	 }
	 return ((cap_data_ptr->effective & CAP_TO_MASK(CAP_NET_RAW)) != 0);
#else
	 __log_dbg("libcap-devel library is not installed, skipping cap_net_raw permission checks");
	 return false;
#endif
}

int validate_tso(int if_index)
{
#ifdef HAVE_LINUX_ETHTOOL_H
	int ret = -1;
	int fd = -1;
	struct ifreq req;
	struct ethtool_value eval;

 	fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		__log_err("ERROR from socket() (errno=%d %m)", errno);
		return -1;
	}
 	memset(&req, 0, sizeof(req));
	eval.cmd = ETHTOOL_GTSO;
	req.ifr_ifindex = if_index;
	if_indextoname(if_index, req.ifr_name);
	req.ifr_data = (char *)&eval;
	ret = orig_os_api.ioctl(fd, SIOCETHTOOL, &req);
	if (ret < 0) {
		__log_dbg("ioctl(SIOCETHTOOL) cmd=ETHTOOL_GTSO (errno=%d %m)", errno);
	} else {
		ret = eval.data;
	}
 	orig_os_api.close(fd);
	return ret;
#else
	NOT_IN_USE(if_index);
	return -1;
#endif
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
