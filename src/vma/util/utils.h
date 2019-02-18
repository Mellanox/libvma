/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <string>
#include <string.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <exception>

#include "vtypes.h"
#include "utils/rdtsc.h"
#include "vlogger/vlogger.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/util/vma_stats.h"

struct iphdr; //forward declaration

#define VMA_ALIGN(x, y) ((((x) + (y) - 1) / (y)) * (y) )

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/**
* Check if file type is regular
**/
int check_if_regular_file (char *path);

/**
 * L3 and L4 Header Checksum Calculation
 */
void compute_tx_checksum(mem_buf_desc_t* p_mem_buf_desc, bool l3_csum, bool l4_csum);

/**
 * IP Header Checksum Calculation
 */
unsigned short compute_ip_checksum(const unsigned short *buf, unsigned int nshort_words);

/**
* get tcp checksum: given IP header and tcp segment (assume checksum field in TCP header contains zero)
* matches RFC 793
*/
unsigned short compute_tcp_checksum(const struct iphdr *p_iphdr, const uint16_t *p_ip_payload);

/**
* get udp checksum: given IP header and UDP datagram (assume checksum field in UDP header contains zero)
* matches RFC 793
*/
unsigned short compute_udp_checksum_rx(const struct iphdr *p_iphdr, const struct udphdr *udphdrp, mem_buf_desc_t* p_rx_wc_buf_desc);

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
 * @param a number
 * @param b number
 * @return true if 'a' and 'b' are equal. else false.
 */
bool compare_double(double a, double b);

/** 
 * Run a system command while bypassing LD_PRELOADed with VMA 
 * @param cmd_line to be exceuted wiout VMA in process space
 * @param return_str is the output of the system call
 */
int run_and_retreive_system_command(const char* cmd_line, char* return_str, int return_str_len);

const char* iphdr_protocol_type_to_str(const int type);

/**
 * Read content of file detailed in 'path' (usually a sysfs file) and
 * store the file content into the given 'buf' up to 'size' characters.
 * print log in case of failure according to the given 'log_level' argument.
 * @return length of content that was read, or -1 upon any error
 */
int priv_read_file(const char *path, char *buf, size_t size, vlog_levels_t log_level = VLOG_ERROR);

/**
 * like above 'priv_read_file' however make sure that upon success the result in buf is a null terminated string
 */
inline int priv_safe_read_file(const char *path, char *buf, size_t size, vlog_levels_t log_level = VLOG_ERROR){
	int ret = -1;
	if (size > 0) {
		ret = priv_read_file(path, buf, size - 1, log_level);
		if (0 <= ret) buf[ret] = '\0';
	}
	return ret;
}


/**
 * like above however make sure that upon success the result in buf is a null terminated string and VLOG_DEBUG
 */
inline int priv_safe_try_read_file(const char *path, char *buf, size_t size) {
	int ret = -1;
	if (size > 0) {
		ret = priv_read_file(path, buf, size - 1, VLOG_DEBUG);
		if (0 <= ret) buf[ret] = '\0';
	}
	return ret;
}

/**
 * Read content of file detailed in 'path' (usually a sysfs file)
 * upon failure print error
 * @return int value (atoi) of the file content, or 'default_value' upon failure
 */
int read_file_to_int(const char *path, int default_value);

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
 * Get port number from interface name
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return zero on failure, else port number
 */
int get_port_from_ifname(const char* ifname);

/** 
 * Get interface type value from interface name
 * 
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return if type on success or -1 on failure
 */
int get_iftype_from_ifname(const char* ifname);

/**
 * Get interface mtu from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return mtu length zero on failure
 */
int get_if_mtu_from_ifname(const char* ifname);

/**
 * Get the OS TCP window scaling factor when tcp_window_scaling is enabled.
 * The value is calculated from the maximum receive buffer value.
 *
 * @param tcp_rmem_max the maximum size of the receive buffer used by each TCP socket
 * @parma core_rmem_max contains the maximum socket receive buffer size in bytes which a user may set by using the SO_RCVBUF socket option.
 *
 * @return TCP window scaling factor
 */
int get_window_scaling_factor(int tcp_rmem_max, int core_rmem_max);

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
 * Get vlan id from interface name
 * 
 * @param ifname input interface name of device (e.g. eth2, eth2.5)
 * @return the vlan id or 0 if not a vlan
 */
uint16_t get_vlan_id_from_ifname(const char* ifname);

/** 
 * Get vlan base name from interface name
 *
 * @param ifname input interface name of device (e.g. eth2, eth2.5)
 * @param base_ifname output base interface name of device (e.g. eth2)
 * @param sz_base_ifname input the size of base_ifname param
 * @return the vlan base name length or 0 if not a vlan
 */
size_t get_vlan_base_name_from_ifname(const char* ifname, char* base_ifname, size_t sz_base_ifname);

/* Upon success - returns the actual address len in bytes; Upon error - returns zero*/
size_t get_local_ll_addr(const char* ifname, unsigned char* addr, int addr_len,  bool is_broadcast);

/* Print warning while RoCE Lag is enabled */
void print_roce_lag_warnings(char* interface, char* disable_path = NULL, const char* port1 = NULL, const char* port2 = NULL);

bool get_bond_active_slave_name(IN const char* bond_name, OUT char* active_slave_name, IN int sz);
bool get_bond_slave_state(IN const char* slave_name, OUT char* curr_state, IN int sz);
bool get_bond_slaves_name_list(IN const char* bond_name, OUT char* slaves_list, IN int sz);
bool check_bond_roce_lag_exist(OUT char* bond_roce_lag_path, int sz, IN const char* slave_name);
bool check_device_exist(const char* ifname, const char *path);
bool check_device_name_ib_name(const char* ifname, const char* ibname);
bool check_netvsc_device_exist(const char* ifname);
bool get_netvsc_slave(IN const char* ifname, OUT char* slave_name, OUT unsigned int &slave_flags);
bool get_interface_oper_state(IN const char* interface_name, OUT char* slaves_list, IN int sz);

int validate_ipoib_prop(const char* ifname, unsigned int ifflags,
		const char prop_file[], const char *expected_val,
		int val_size, char *filename, char* base_ifname);

int validate_raw_qp_privliges();

bool validate_user_has_cap_net_raw_privliges();

/**
 * Get TSO support using interface index
 *
 * @param if_index input interface index
 * @return 0/1 or -1 on failure
 */
int validate_tso(int if_index);

static inline int get_procname(int pid, char *proc, size_t size)
{
	char app_full_name[PATH_MAX] = {0};
	char proccess_proc_dir[FILE_NAME_MAX_SIZE] = {0};
	char* app_base_name = NULL;
	int n = -1;

	if (NULL == proc) {
		return -1;
	}

	n = snprintf(proccess_proc_dir, sizeof(proccess_proc_dir), "/proc/%d/exe", pid);
	if (likely((0 < n) && (n < (int)sizeof(proccess_proc_dir)))) {
		n = readlink(proccess_proc_dir, app_full_name, sizeof(app_full_name) - 1);
		if (n > 0) {
			app_full_name[n] = '\0';
			app_base_name = strrchr(app_full_name, '/');
			if (app_base_name) {
				strncpy(proc, app_base_name + 1, size - 1);
				proc[size - 1] = '\0';
				return 0;
			}
		}
	}

	return -1;
}

static inline in_addr_t prefix_to_netmask(int prefix_length)
{
    in_addr_t mask = 0;

    if (prefix_length <= 0 || prefix_length > 32) {
        return 0;
    }
    mask = ~mask << (32 - prefix_length);
    mask = htonl(mask);
    return mask;
}

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

// Returns the filesystem's inode number for the given 'fd' using 'fstat' system call that assumes 32 bit inodes
// This should be safe for 'proc' filesytem and for standard filesystems
uint32_t fd2inode(int fd);


/**
 * @class vma_error
 *
 * base class for vma exceptions classes.
 * Note: VMA code should NOT catch vma_error; VMA code should only catch exceptions of derived classes
 */
class vma_error : public std::exception {
	char formatted_message[512];
public:
	const char * const message;
	const char * const function;
	const char * const filename;
	const int lineno;
	const int errnum;

	/**
	 * Create an object that contains const members for all the given arguments, plus a formatted message that will be
	 * available thru the 'what()' method of base class.
	 *
	 * The formatted_message will look like this:
	 * 		"vma_error <create internal epoll> (errno=24 Too many open files) in sock/sockinfo.cpp:61"
	 * catcher can print it to log like this:
	 * 		fdcoll_loginfo("recovering from %s", e.what());
	 */
	vma_error(const char* _message, const char* _function, const char* _filename, int _lineno, int _errnum) throw();

	virtual ~vma_error() throw();

	virtual const char* what() const throw();

};

/**
 * @class vma_exception
 * NOTE: ALL exceptions that can be caught by VMA should be derived of this class
 */
class vma_exception : public vma_error {
public:
	vma_exception(const char* _message, const char* _function, const char* _filename, int _lineno, int _errnum) throw() :
		vma_error(_message, _function, _filename, _lineno, _errnum)
	{
	}
};


#define create_vma_exception_class(clsname, basecls) \
	class clsname : public basecls { \
	public: \
	clsname(const char* _message, const char* _function, const char* _filename, int _lineno, int _errnum) throw() : \
		basecls(_message, _function, _filename, _lineno, _errnum) {} \
	}

create_vma_exception_class(vma_unsupported_api, vma_error);

#define throw_vma_exception(msg) throw vma_exception(msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
// uses for throwing  something that is derived from vma_error and has similar CTOR; msg will automatically be class name
#define vma_throw_object(_class)  throw _class(#_class, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
#define vma_throw_object_with_msg(_class, _msg)  throw _class(_msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)

/* Rounding up to nearest power of 2 */
static inline uint32_t align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}


static inline int ilog_2(uint32_t n) {
	if (n == 0)
		return 0;

	uint32_t t = 0;
	while ((1 << t) < (int)n)
		++t;

	return (int)t;
}

#endif
