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


#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <string>
#include <string.h>
#include <ifaddrs.h>

#include "sys_vars.h"
#include <vma/util/rdtsc.h>
#include <linux/if_ether.h>
#include <vlogger/vlogger.h>

/**
* Check if file type is regular
**/
int check_if_regular_file (char *path);

/**
 * Check Sum extensions
 */
unsigned short csum(unsigned short *buf, unsigned int nwords);

/**
 * get user space max number of open fd's using getrlimit, default parameter equals to 1024
 */

int get_sys_max_fd_num(int def_max_fd=1024);

/**
 * iovec extensions
 * Returns total bytes copyed
 */
int memcpy_fromiovec(u_int8_t* p_dst, const struct iovec* p_iov, size_t sz_iov, size_t sz_src_start_offset, size_t sz_data);

/**
 * get base interface from an aliased/vlan tagged one. i.e. eth2:1 --> eth2 / eth2.1 --> eth2
 * Functions gets:interface name,output variable for base interface,output size; and returns the base interface
 */
int get_base_interface_name(const char *if_name, char *base_ifname, size_t sz_base_ifname);

/**
 * Count bitmark set bits
 */
int netmask_bitcount(uint32_t netmask);


/** 
 * Set the fd blocking mode 
 * @param fd the file descriptor on which to operate 
 * @param block 'true' to set to block 
 *              'false' to set to non-blocking
 */
void set_fd_block_mode(int fd, bool block);


/** 
 * Run a system command while bypassing LD_PRELOADed with VMA 
 * @param cmd_line to be exceuted wiout VMA in process space
 * @param return_str is the output of the system call
 */
#define MAX_CMD_LINE_LEN		512
int run_and_retreive_system_command(const char* cmd_line, char* return_str, int return_str_len);

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
/**
 * Copy buffer to iovec
 * Returns total bytes copyed
 */
static inline int memcpy_toiovec(u_int8_t* p_src, iovec* p_iov, size_t sz_iov,
                                 size_t sz_dst_start_offset, size_t sz_data)
{
	/* Skip to start offset  */
	int n_iovpos = 0;
	while (n_iovpos < (int)sz_iov && sz_dst_start_offset >= p_iov[n_iovpos].iov_len) {
		sz_dst_start_offset -= p_iov[n_iovpos].iov_len;
		n_iovpos++;
	}

	/* Copy len size into iovec */
	int n_total = 0;
	while (n_iovpos < (int)sz_iov && sz_data > 0) {
		if (p_iov[n_iovpos].iov_len)
		{
			u_int8_t* p_dst = ((u_int8_t*)(p_iov[n_iovpos].iov_base)) + sz_dst_start_offset;
			int sz_data_block_to_copy = std::min(sz_data, p_iov[n_iovpos].iov_len - sz_dst_start_offset);
			sz_dst_start_offset = 0;

			memcpy(p_dst, p_src, sz_data_block_to_copy);

			p_src += sz_data_block_to_copy;
			sz_data -= sz_data_block_to_copy;
			n_total += sz_data_block_to_copy;
		}
		n_iovpos++;
	}
	return n_total;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

const char* iphdr_protocol_type_to_str(const int type);
const char* priv_vma_transport_type_str(transport_type_t trans_type);

/** 
 * Read a sysfs param from file detailed in 'path' and read the 
 * value stored in the file into the 'buf' up to 'size' 
 * @return length of data stored in buf
 */
int priv_read_file(const char *path, char *buf, size_t size);





/** 
 * Return true if peer_ip is one of the local IPs
 * 
 * @in_addr_t peer_ip 
 *  
 * @return non zero on success
 */
int is_local_addr(in_addr_t peer_ip);


/** 
 * Get interface name and flags from local address
 * 
 * @char ifname[IFNAMSIZ]; 
 * @unsigned int ifflags; Flags as from SIOCGIFFLAGS ioctl. 
 *  
 * @return zero on success
 */
int get_ifinfo_from_ip(const struct sockaddr& local_addr, char* ifname, uint32_t &ifflags);

/** 
 * Get interface type value from interface name
 * 
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return if type on success or -1 on failure
 */
int get_iftype_from_ifname(const char* ifname);

/** 
 * Get interface address length from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 * should be of size IFNAMSIZ
 * @return address length zero on failure
 */
int get_ifaddr_len_from_ifname(const char* ifname);

/**
 * Get interface mtu from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return mtu length zero on failure
 */
int get_if_mtu_from_ifname(const char* ifname, bool use_base_if);

/**
 * Get the OS max IGMP membership per socket.
 *
 * @return the OS max IGMP membership per socket, or -1 for disabled or failures
 */
int get_igmp_max_membership();

/**
 * Get the OS TCP window scaling factor.
 * The value is calculated from the maximum receive buffer value.
 *
 * @return TCP window scaling factor, or -1 for disabled or failures
 */
int get_window_scaling_factor();

/**
 * Get Ethernet ipv4 address from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @param sockaddr_in output interface inet address
 *
 * @return -1 on failure
 */
int get_ipv4_from_ifname(char *ifname, struct sockaddr_in *addr);

/**
 * Get Ethernet ipv4 address from interface index
 *
 * @param ifindex input interface index of device
 * @param sockaddr_in output interface inet address
 *
 * @return -1 on failure
 */
int get_ipv4_from_ifindex(int ifindex, struct sockaddr_in *addr);

/**
 * Get Ethernet mac address from interface name
 * 
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @param ether_addr output interface ether mac address 
 *  should be of size ETH_ALEN
 * @return zero on success
 */
int get_mac_from_ifname(const char* ifname, uint8_t* ether_addr);

/**
 * Get Ethernet netmask of the if name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @param ip_addr_t output interface netmask
 *
 * @return zero on success -1 on failure
 */
int get_netmask_from_ifname(const char* ifname, in_addr_t *netmask);

/** 
 * Get Ethernet mac address from interface name
 * 
 * @param ifname input interface name of device (e.g. eth2, eth2.5)
 * @return the vlan id or 0 if not a vlan
 */
uint16_t get_vlan_id_from_ifname(const char* ifname);

/** 
 * Get peer node IPoIB QP number (remote_qpn) from the peer's IP
 * address 
 * 
 * @param peer_addr is the ip address of the remote host
 * @return the remote_qpn which is taken from the nieghbor HW 
 *  address string taken from the system's neighbor list)
 *  (using: "#ip neigh show")
 */
int get_peer_ipoib_qpn(const struct sockaddr* p_peer_addr, uint32_t & remote_qpn);

int get_peer_unicast_mac(const in_addr_t p_peer_addr, unsigned char peer_mac[ETH_ALEN]);

int get_peer_ipoib_address(const struct sockaddr* p_peer_addr, unsigned char peer_l2[IPOIB_HW_ADDR_LEN]);

bool get_local_ll_addr(const char* ifname, unsigned char* addr, int addr_len,  bool is_broadcast);

// This function translates the interface ipv4 address to IF name and queries the IF
// Input params:
// 	1. address of ib_con_mgr local if
// Output params:
//	1. name of ib_con_mgr local if
//	2. if flags
// Return Value
// Type: boolean
// Val:  if translation of ipv4 address fails return false otherwise true
bool get_local_if_info(in_addr_t local_if, char* ifname, unsigned int &ifflags);

bool get_bond_active_slave_name(IN const char* bond_name, OUT char* active_slave_name, IN int sz);
bool get_bond_slaves_name_list(IN const char* bond_name, OUT char* slaves_list, IN int sz);

int validate_ipoib_prop(const char* ifname, unsigned int ifflags,
		const char prop_file[], const char *expected_val,
		int val_size, char *filename, char* base_ifname);

void convert_hw_addr_to_str(char *buf, uint8_t hw_addr_len, uint8_t *hw_addr);

//Creates multicast MAC from multicast IP
//inline void create_multicast_mac_from_ip(uint8_t (& mc_mac) [6], in_addr_t ip)
inline void create_multicast_mac_from_ip(unsigned char* mc_mac, in_addr_t ip)
{
	if(mc_mac == NULL)
		return;

	mc_mac[0] = 0x01;
	mc_mac[1] = 0x00;
	mc_mac[2] = 0x5e;
	mc_mac[3] = (uint8_t)((ip>> 8)&0x7f);
	mc_mac[4] = (uint8_t)((ip>>16)&0xff);
	mc_mac[5] = (uint8_t)((ip>>24)&0xff);
}

static inline void create_mgid_from_ipv4_mc_ip(uint8_t *mgid, uint16_t pkey, uint32_t ip)
{

//  +--------+----+----+-----------------+---------+-------------------+
//  |   8    |  4 |  4 |     16 bits     | 16 bits |      80 bits      |
//  +--------+----+----+-----------------+---------+-------------------+
//  |11111111|0001|scop|<IPoIB signature>|< P_Key >|      group ID     |
//  +--------+----+----+-----------------+---------+-------------------+
//  |11111111|0001|0010|01000000000011011|         |      group ID     |
//  +--------+----+----+-----------------+---------+-------------------+

	//Fixed for multicast
	mgid[0] = 0xff;
	mgid[1] = 0x12;

	//IPoIB signature: 0x401b for ipv4, 0x601b for ipv6
	mgid[2] = 0x40;
	mgid[3] = 0x1b;

	//P_Key
	mgid[4] = (((unsigned char *)(&pkey))[0]);
	mgid[5] = (((unsigned char *)(&pkey))[1]);

	//group ID - relevant only for ipv4
	mgid[6] = 0x00;
	mgid[7] = 0x00;
	mgid[8] = 0x00;
	mgid[9] = 0x00;
	mgid[10] = 0x00;
	mgid[11] = 0x00;
	mgid[12] = (uint8_t)((ip)&0x0f);
	mgid[13] = (uint8_t)((ip>>8)&0xff);
	mgid[14] = (uint8_t)((ip>>16)&0xff);
	mgid[15] = (uint8_t)((ip>>24)&0xff);

	vlog_printf(VLOG_DEBUG, "Translated to mgid: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
			((unsigned char *)(mgid))[0],((unsigned char *)(mgid))[1],
			((unsigned char *)(mgid))[2],((unsigned char *)(mgid))[3],
			((unsigned char *)(mgid))[4],((unsigned char *)(mgid))[5],
			((unsigned char *)(mgid))[6],((unsigned char *)(mgid))[7],
			((unsigned char *)(mgid))[8],((unsigned char *)(mgid))[9],
			((unsigned char *)(mgid))[10],((unsigned char *)(mgid))[11],
			((unsigned char *)(mgid))[12],((unsigned char *)(mgid))[13],
			((unsigned char *)(mgid))[14],((unsigned char *)(mgid))[15]);
}

/**
 * special design for the rx loop. 
 */
class loops_timer {
        public:
                loops_timer();
                void start();
                int  time_left_msec();
                void set_timeout_msec(int timeout_msec) { m_timeout_msec = timeout_msec; }
                int  get_timeout_msec() { return m_timeout_msec; }
                inline bool is_timeout() {
                        if (m_timeout_msec == -1)
                                return false;

                        if (m_timer_countdown > 0) {
                                m_timer_countdown--;
                                return false;
                        }
                        //init counter
                        m_timer_countdown = m_interval_it;

                        if (!ts_isset(&m_start)) {
                                gettime(&m_start);
                        }
                        //update timer
                        gettime(&m_current);
                        ts_sub(&m_current, &m_start, &m_elapsed);
                        vlog_printf(VLOG_FUNC_ALL, "update loops_timer (elapsed time=%d sec %d usec \n", ts_to_sec(&m_elapsed), ts_to_usec(&m_elapsed));



                        // test for timeout 
                        if (m_timeout_msec <= ts_to_msec(&m_elapsed)) 
                                return true;

                        return false;
                }
        private:
                timespec m_start;
                timespec m_elapsed;
                timespec m_current;
                int m_interval_it;
                int m_timer_countdown;
                int m_timeout_msec;
};

#endif
