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


#include "sockinfo_udp.h"

#include <fcntl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/epoll.h>
#include <algorithm>

#include "vma/util/rdtsc.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/libvma.h"
#include "vma/sock/sock-redirect.h"
#include "vma/sock/fd_collection.h"
#include "vma/event/event_handler_manager.h"
#include "vma/dev/buffer_pool.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/proto/dst_entry_tcp.h"
#include "vma/proto/dst_entry_udp.h"
#include "vma/proto/dst_entry_udp_mc.h"
#include "vma/iomux/epfd_info.h"
#include "vma/iomux/io_mux_call.h"
#include "lwip/udp.h"
#include "vma/util/instrumentation.h"
#include "vma/util/bullseye.h"

#if DEFINED_MISSING_NET_TSTAMP
enum {
	SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
	SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
	SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
	SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
	SOF_TIMESTAMPING_SOFTWARE = (1<<4),
	SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
	SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
	SOF_TIMESTAMPING_MASK =
			(SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
			SOF_TIMESTAMPING_RAW_HARDWARE
};
#else
#include <linux/net_tstamp.h>
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS		35
#endif

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING		37
#endif

/* useful debugging macros */

#define MODULE_NAME 		"si_udp"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[fd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_fd

#define si_udp_logpanic		__log_info_panic
#define si_udp_logerr		__log_info_err
#define si_udp_logwarn		__log_info_warn
#define si_udp_loginfo		__log_info_info
#define si_udp_logdbg		__log_info_dbg
#define si_udp_logfunc		__log_info_func
#define si_udp_logfuncall	__log_info_funcall

#define si_logdbg_no_funcname(log_fmt, log_args...)	do { if (g_vlogger_level >= VLOG_DEBUG) 	vlog_printf(VLOG_DEBUG, MODULE_NAME "[fd=%d]:%d: " log_fmt "\n", m_fd, __LINE__, ##log_args); } while (0)

/* For MCD */
#define UDP_MAP_ADD             101
#define UDP_MAP_REMOVE          102

int g_n_os_igmp_max_membership;

const char * setsockopt_so_opt_to_str(int opt)
{
	switch (opt) {
	case SO_REUSEADDR: 		return "SO_REUSEADDR";
	case SO_BROADCAST:	 	return "SO_BROADCAST";
	case SO_RCVBUF:			return "SO_RCVBUF";
	case SO_SNDBUF:			return "SO_SNDBUF";
	case SO_TIMESTAMP:		return "SO_TIMESTAMP";
	case SO_TIMESTAMPNS:		return "SO_TIMESTAMPNS";
	default:			break;
	}
	return "UNKNOWN SO opt";
}


const char * setsockopt_ip_opt_to_str(int opt)
{
	switch (opt) {
	case IP_MULTICAST_IF:		return "IP_MULTICAST_IF";
	case IP_MULTICAST_TTL:		return "IP_MULTICAST_TTL";
	case IP_MULTICAST_LOOP: 	return "IP_MULTICAST_LOOP";
	case IP_ADD_MEMBERSHIP: 	return "IP_ADD_MEMBERSHIP";    
	case IP_DROP_MEMBERSHIP:	return "IP_DROP_MEMBERSHIP";
	default:			break;
	}
	return "UNKNOWN IP opt";
}



// Throttle the amount of ring polling we do (remember last time we check for receive packets)
tscval_t g_si_tscv_last_poll = 0;

sockinfo_udp::sockinfo_udp(int fd) :
	sockinfo(fd)
	,m_mc_tx_if(INADDR_ANY)
	,m_b_mc_tx_loop(mce_sys.tx_mc_loopback_default) // default value is 'true'. User can change this with config parameter SYS_VAR_TX_MC_LOOPBACK
	,m_n_mc_ttl(DEFAULT_MC_TTL)
	,m_loops_to_go(mce_sys.rx_poll_num_init) // Start up with a init polling loops value
	,m_rx_udp_poll_os_ratio_counter(0)
	,m_sock_offload(true)
	,m_rx_callback(NULL)
	,m_rx_callback_context(NULL)
	,m_port_map_lock("sockinfo_udp::m_ports_map_lock")
	,m_port_map_index(0)
	,m_b_pktinfo(false)
	,m_b_rcvtstamp(false)
	,m_b_rcvtstampns(false)
	,m_n_tsing_flags(0)
{
	si_udp_logfunc("");

	m_protocol = PROTO_UDP;
	m_p_socket_stats->socket_type = SOCK_DGRAM;

	// Update MC related stats (default values)
	m_p_socket_stats->mc_tx_if = m_mc_tx_if;
	m_p_socket_stats->b_mc_loop = m_b_mc_tx_loop;

	int n_so_rcvbuf_bytes = 0;
	socklen_t option_len = sizeof(n_so_rcvbuf_bytes);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(orig_os_api.getsockopt(m_fd, SOL_SOCKET, SO_RCVBUF, &n_so_rcvbuf_bytes, &option_len)))
		si_udp_logdbg("Failure in getsockopt (errno=%d %m)", errno);
	BULLSEYE_EXCLUDE_BLOCK_END
	si_udp_logdbg("Sockets RCVBUF = %d bytes", n_so_rcvbuf_bytes);
	rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);

	struct epoll_event ev;
	ev.events = EPOLLIN;

	// Add the user's orig fd to the rx epfd handle
	ev.data.fd = m_fd;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev)))
		si_udp_logpanic("failed to add user's fd to internal epfd errno=%d (%m)", errno);
	BULLSEYE_EXCLUDE_BLOCK_END


	si_udp_logfunc("done");
}

sockinfo_udp::~sockinfo_udp()
{
	si_udp_logfunc("");

	// Remove all RX ready queue buffers (Push into reuse queue per ring)
	si_udp_logdbg("Releasing %d ready rx packets (total of %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
	rx_ready_byte_count_limit_update(0);


	// Clear the dst_entry map
	dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
	while (dst_entry_iter != m_dst_entry_map.end()) {
		delete dst_entry_iter->second; // TODO ALEXR - should we check and delete the udp_mc in MC cases?
		m_dst_entry_map.erase(dst_entry_iter);
		dst_entry_iter = m_dst_entry_map.begin();
	}

/* AlexR:
   We don't have to be nice and delete the fd. close() will do that any way.
   This save us the problem when closing in the clean-up case - if we get closed be the nameserver socket 53.
	if (unlikely( orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_DEL, m_fd, NULL))) {
		if (errno == ENOENT)
			si_logfunc("failed to del users fd from internal epfd - probably clean up case (errno=%d %m)", errno);
		else
			si_logerr("failed to del users fd from internal epfd (errno=%d %m)", errno);
	}
*/
	m_lock_rcv.lock();
	do_wakeup();

	destructor_helper();

	m_lock_rcv.unlock();

	statistics_print();
	si_udp_logfunc("done");
}

int sockinfo_udp::bind(const struct sockaddr *__addr, socklen_t __addrlen)
{
	si_udp_logfunc("");

	// We always call the orig_bind which will check sanity of the user socket api
	// and the OS will also allocate a specific port that we can also use
	int ret = orig_os_api.bind(m_fd, __addr, __addrlen);
	if (ret) {
		si_udp_logdbg("orig bind failed (ret=%d %m)", ret);
		// TODO: Should we set errno again (maybe log write modified the orig.bind() errno)?
		return ret;
	}
	if (unlikely(m_b_closed) || unlikely(g_b_exit)) {
		errno = EBUSY;
		return -1; // zero returned from orig_bind()
	}

	// Call our getsockname (this will get us and save the bound info and then attach to offload flows)
	ret = getsockname();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret) {
		si_udp_logdbg("getsockname failed (ret=%d %m)", ret);
		return -1; 
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	si_udp_logdbg("bound to %s", m_bound.to_str());

	dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
	while (dst_entry_iter != m_dst_entry_map.end()) {
		if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
			dst_entry_iter->second->set_bound_addr(m_bound.get_in_addr());
		}
		dst_entry_iter++;
	}

	return 0;
}

int sockinfo_udp::connect(const struct sockaddr *__to, socklen_t __tolen)
{
	sock_addr connect_to((struct sockaddr*)__to);
	si_udp_logdbg("to %s", connect_to.to_str());

	// We always call the orig_connect which will check sanity of the user socket api
	// and the OS will also allocate a specific bound port that we can also use
	int ret = orig_os_api.connect(m_fd, __to, __tolen);
	if (ret) {
		si_udp_logdbg("orig connect failed (ret=%d, errno=%d %m)", ret, errno);
		return ret;
	}
	if (unlikely(m_b_closed) || unlikely(g_b_exit)) {
		errno = EBUSY;
		return -1; // zero returned from orig_connect()
	}

	auto_unlocker lock(m_lock_snd);

	// Dissolve the current connection setting if it's not AF_INET
	// (this also support the default dissolve by AF_UNSPEC)
	if (connect_to.get_sa_family() == AF_INET) {
		m_connected.set_in_addr(INADDR_ANY);
		m_p_socket_stats->connected_ip = m_connected.get_in_addr();

		m_connected.set_in_port(INPORT_ANY);
		m_p_socket_stats->connected_port = m_connected.get_in_port();

/* TODO ALEXR REMOVE ME - DONE IN DST_ENTRY

	if (ZERONET_N(connect_to.get_in_addr())) {
		si_udp_logdbg("VMA does not offload zero net IP address");
		si_udp_logdbg("'connect()' to zero net address [%s] will be handled by the OS", connect_to.to_str());
		return 0; // zero returned from orig_connect()
	}

	if (LOOPBACK_N(connect_to.get_in_addr())) {
		si_udp_logdbg("VMA does not offload local loopback IP address");
		si_udp_logdbg("'connect()' to local loopback address [%s] will be handled by the OS", connect_to.to_str());
		return 0; // zero returned from orig_connect()
	}
//*/

		in_addr_t dst_ip = connect_to.get_in_addr();
		in_port_t dst_port = connect_to.get_in_port();

		// Check & Save connect ip info
		if (dst_ip != INADDR_ANY && m_connected.get_in_addr() != dst_ip) {
			si_udp_logdbg("connected ip changed (%s -> %s)", m_connected.to_str_in_addr(), connect_to.to_str_in_addr());
		}
		m_connected.set_in_addr(dst_ip);
		m_p_socket_stats->connected_ip = dst_ip;

		// Check & Save connect port info
		if (dst_port != INPORT_ANY && m_connected.get_in_port() != dst_port) {
			si_udp_logdbg("connected port changed (%s -> %s)", m_connected.to_str_in_port(), connect_to.to_str_in_port());
		}
		m_connected.set_in_port(dst_port);
		m_p_socket_stats->connected_port = dst_port;


		// Connect can change the OS bound address,
		// lets check it and update our bound ip & port
		// Call our getsockname (this will also save the bind information and attach to unicast flow)
		ret = getsockname();
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret) {
			si_udp_logerr("getsockname failed (ret=%d %m)", ret);
			return 0; // zero returned from orig_connect()
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		si_udp_logdbg("bound to %s", m_bound.to_str());
		in_port_t src_port = m_bound.get_in_port();

		if (TRANS_VMA != find_target_family(ROLE_UDP_CONNECT, m_connected.get_p_sa(), m_bound.get_p_sa())) {
			setPassthrough();
			return 0;
		}

		// Create the new dst_entry
		if (IN_MULTICAST_N(dst_ip)) {
			m_p_connected_dst_entry = new dst_entry_udp_mc(dst_ip, dst_port, src_port,
					m_mc_tx_if ? m_mc_tx_if : m_bound.get_in_addr(), m_b_mc_tx_loop, m_n_mc_ttl, m_fd);
		}
		else {
			m_p_connected_dst_entry = new dst_entry_udp(dst_ip, dst_port, src_port, m_fd);
		}
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!m_p_connected_dst_entry) {
			si_udp_logpanic("Failed to create dst_entry(dst_ip:%s, dst_port:%d, src_port:%d)", NIPQUAD(dst_ip), ntohs(dst_port), ntohs(src_port));
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
			m_p_connected_dst_entry->set_bound_addr(m_bound.get_in_addr());
		}
		if (m_so_bindtodevice_ip) {
			m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
		}

		return 0;
	}
	return 0;
}

int sockinfo_udp::getsockname(struct sockaddr *__name /*=NULL*/, socklen_t *__namelen /*=NULL*/)
{
	si_udp_logdbg("");

	struct sockaddr_in bound_addr;
	socklen_t boundlen = sizeof(struct sockaddr_in);
	if (__name == NULL) {
		memset(&bound_addr, 0, boundlen);
		__name = (struct sockaddr*)&bound_addr;
		__namelen = &boundlen;
	}

	int ret = orig_os_api.getsockname(m_fd, __name, __namelen);
	if (ret) {
		return ret;
	}

	if (*__namelen < sizeof(struct sockaddr)) {
		si_udp_logerr("namelen too small (%d)", *__namelen);
		errno = EINVAL;
		return -1;
	}

	if (unlikely(m_b_closed) || unlikely(g_b_exit)) {
		errno = EINTR;
		return -1;
	}

	sock_addr bindname(__name);

	sa_family_t sin_family = bindname.get_sa_family();
	if (sin_family != AF_INET) {
		si_udp_logfunc("not AF_INET family (%d)", sin_family);
		return ret;
	}

	bool is_bound_modified = false;
	in_addr_t bound_if = bindname.get_in_addr();
	in_port_t bound_port = bindname.get_in_port();

	auto_unlocker lock(m_lock_rcv);

	// Check & Save bind port info
	if (m_bound.get_in_port() != bound_port) {
		si_udp_logdbg("bound port defined (%s -> %d)", m_bound.to_str_in_port(), ntohs(bound_port));
		m_bound.set_in_port(bound_port);
		m_p_socket_stats->bound_port = bound_port;
		is_bound_modified = true;
	}

	// Check & Save bind if info
	if (m_bound.get_in_addr() != bound_if) {
		si_udp_logdbg("bound if changed (%s -> %d.%d.%d.%d)", m_bound.to_str_in_addr(), NIPQUAD(bound_if));
		m_bound.set_in_addr(bound_if);
		m_p_socket_stats->bound_if = bound_if;
	}

	// Check if this is the new 'name' (local port) of the socket
	if (is_bound_modified && bound_port != INPORT_ANY) {

		// Attach UDP unicast port to offloaded interface
		// 1. Verify not binding to MC address in the UC case
		// 2. Check if local_if is offloadable OR is on INADDR_ANY which means attach to ALL
		if ((m_bound.is_anyaddr() || g_p_net_device_table_mgr->get_net_device_val(m_bound.get_in_addr()))) {
			attach_as_uc_receiver(ROLE_UDP_RECEIVER);
		}
		else {
			if (m_bound.is_mc()) {
				si_udp_logdbg("bound to MC address, no need to attach to UC address as offloaded");
			}
			else {
				si_udp_logdbg("will be passed to OS for handling - not offload interface (%s)", m_bound.to_str());
			}
		}

		// Attach UDP port pending MC groups to offloaded interface (set by ADD_MEMBERSHIP before bind() was called)
		handle_pending_mreq();
	}

	return ret;
}

int sockinfo_udp::setsockopt(int __level, int __optname, __const void *__optval, socklen_t __optlen)
{
	si_udp_logfunc("level=%d, optname=%d", __level, __optname);

	if (unlikely(m_b_closed) || unlikely(g_b_exit))
		return orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);

	auto_unlocker lock_tx(m_lock_snd);
	auto_unlocker lock_rx(m_lock_rcv);

	switch (__level) {

	case SOL_SOCKET:
		{
			switch (__optname) {

			case SO_REUSEADDR:
			case SO_BROADCAST:
				si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), ((bool*)__optval ? "true" : "false"));
				break;

			case SO_RCVBUF:
				{
					int n_so_rcvbuf_bytes = *(int*)__optval;
					// OS allocates double the size of memory requested by the application
					n_so_rcvbuf_bytes = n_so_rcvbuf_bytes * 2;

					si_udp_logdbg("SOL_SOCKET, %s=%d (x2)", setsockopt_so_opt_to_str(__optname), n_so_rcvbuf_bytes);
					rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);
				}
				break;

			case SO_SNDBUF:
				si_udp_logdbg("SOL_SOCKET, %s=%d", setsockopt_so_opt_to_str(__optname), *(int*)__optval);
				break;

                        case SO_RCVTIMEO:
                                if (__optval) {
                                    struct timeval* tv = (struct timeval*)__optval;
                                    if (tv->tv_sec || tv->tv_usec)
                                	    m_loops_timer.set_timeout_msec(tv->tv_sec*1000 + (tv->tv_usec ? tv->tv_usec/1000 : 0));
                                    else
                                	    m_loops_timer.set_timeout_msec(-1);
                                    si_udp_logdbg("SOL_SOCKET: SO_RCVTIMEO=%d", m_loops_timer.get_timeout_msec());

                                }
                                break;

			case SO_TIMESTAMP:
			case SO_TIMESTAMPNS:
				if (__optval) {
					m_b_rcvtstamp = *(bool*)__optval;
					if (__optname == SO_TIMESTAMPNS)
						m_b_rcvtstampns = m_b_rcvtstamp;
					si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), (m_b_rcvtstamp ? "true" : "false"));
				}
				break;

			case SO_TIMESTAMPING:
				if (__optval) {
					m_n_tsing_flags  = *(uint8_t*)__optval;
					si_udp_logdbg("SOL_SOCKET, SO_TIMESTAMPING=%u", m_n_tsing_flags);
				}
				break;

			case SO_BINDTODEVICE:
				if (__optval) {
					struct sockaddr_in sockaddr;
					if (__optlen == 0 || ((char*)__optval)[0] == '\0') {
						m_so_bindtodevice_ip = 0;
					} else if (get_ipv4_from_ifname((char*)__optval, &sockaddr)) {
						si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, cannot find if_name", setsockopt_so_opt_to_str(__optname));
						break;
					} else {
						m_so_bindtodevice_ip = sockaddr.sin_addr.s_addr;
					}
					// handle TX side
					if (m_p_connected_dst_entry) {
						m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
					} else {
						dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
						while (dst_entry_iter != m_dst_entry_map.end()) {
							dst_entry_iter->second->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
							dst_entry_iter++;
						}
					}
					// TODO handle RX side
				}
				else {
					si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
				}
				break;

			default:
				si_udp_logdbg("SOL_SOCKET, optname=%s (%d)", setsockopt_so_opt_to_str(__optname), __optname);
				break;
			}
		} // case SOL_SOCKET
		break;

	case IPPROTO_IP:
		{
			switch (__optname) {

			case IP_MULTICAST_IF:
				{
					//XXX -check udp tx vma/os
					if (!__optval || __optlen < sizeof(struct in_addr)) {
						si_udp_loginfo("IPPROTO_IP, %s=\"???\", optlen:%d", setsockopt_ip_opt_to_str(__optname), (int)__optlen);
						break;
					}

					struct ip_mreqn mreqn;

					if (__optlen >= sizeof(struct ip_mreqn)) {
						mreqn = *(struct ip_mreqn*)__optval;
					} else {
						memset(&mreqn, 0, sizeof(mreqn));
						if (__optlen >= sizeof(struct in_addr)) {
							mreqn.imr_address = *(struct in_addr*)__optval;
						}
					}

					if (mreqn.imr_ifindex) {
						net_dev_lst_t* p_ndv_val_lst = g_p_net_device_table_mgr->get_net_device_val_lst_from_index(mreqn.imr_ifindex);
						net_device_val* p_ndev = NULL;
						if (p_ndv_val_lst && (p_ndev = dynamic_cast <net_device_val *>(*(p_ndv_val_lst->begin())))) {
							mreqn.imr_address.s_addr = p_ndev->get_local_addr();
						} else {
							struct sockaddr_in src_addr;
							if (get_ipv4_from_ifindex(mreqn.imr_ifindex, &src_addr) == 0) {
								mreqn.imr_address.s_addr = src_addr.sin_addr.s_addr;
							} else {
								si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, can't get address of interface index %d ", setsockopt_ip_opt_to_str(__optname), mreqn.imr_ifindex);
								break;
							}
						}
					}

					m_mc_tx_if = mreqn.imr_address.s_addr;

					si_udp_logdbg("IPPROTO_IP, %s=%d.%d.%d.%d", setsockopt_ip_opt_to_str(__optname), NIPQUAD(m_mc_tx_if));
					m_p_socket_stats->mc_tx_if = m_mc_tx_if;
				}
				break;

			case IP_MULTICAST_TTL:
				{
					int n_mc_ttl = -1;
					if (__optlen == 1)
						n_mc_ttl = *(char*)__optval;
					else if (__optlen >= 1)
						n_mc_ttl = *(int*)__optval;

					if (__optval && (n_mc_ttl >= 0 && n_mc_ttl <= 255)) {
						m_n_mc_ttl = n_mc_ttl;
						si_udp_logdbg("IPPROTO_IP, %s=%d", setsockopt_ip_opt_to_str(__optname), m_n_mc_ttl);
					}
					else {
						si_udp_loginfo("IPPROTO_IP, %s=\"???\"", setsockopt_ip_opt_to_str(__optname));
					}
				}
				break;

			case IP_MULTICAST_LOOP:
				{
					if (__optval) {
						bool b_mc_loop = *(bool*)__optval;
						m_b_mc_tx_loop = b_mc_loop ? true : false;
						m_p_socket_stats->b_mc_loop = m_b_mc_tx_loop;
						si_udp_logdbg("IPPROTO_IP, %s=%s", setsockopt_ip_opt_to_str(__optname), (m_b_mc_tx_loop ? "true" : "false"));
					}
					else {
						si_udp_loginfo("IPPROTO_IP, %s=\"???\"", setsockopt_ip_opt_to_str(__optname));
					}
				}
				break;

			case IP_ADD_MEMBERSHIP:
			case IP_DROP_MEMBERSHIP:	
				{
				if (!m_sock_offload) {
					si_udp_logdbg("VMA Rx Offload is Disabled! calling OS setsockopt() for IPPROTO_IP, %s", setsockopt_ip_opt_to_str(__optname));
					break;
				}

				if (__optval == NULL || (__optlen < sizeof(struct ip_mreq))) {
					si_udp_logdbg("IPPROTO_IP, %s; Bad optval! calling OS setsockopt()", setsockopt_ip_opt_to_str(__optname));
					break;
				}

				struct ip_mreq mreq = *(struct ip_mreq*)__optval;
				if (__optlen >= sizeof(struct ip_mreqn)) {
					struct ip_mreqn* p_mreqn = (struct ip_mreqn*)__optval;
					if(p_mreqn->imr_ifindex) {
						net_dev_lst_t* p_ndv_val_lst = g_p_net_device_table_mgr->get_net_device_val_lst_from_index(p_mreqn->imr_ifindex);
						net_device_val* p_ndev = NULL;
						if (p_ndv_val_lst && (p_ndev = dynamic_cast <net_device_val *>(*(p_ndv_val_lst->begin())))) {
							mreq.imr_interface.s_addr = p_ndev->get_local_addr();
						} else {
							struct sockaddr_in src_addr;
							if (get_ipv4_from_ifindex(p_mreqn->imr_ifindex, &src_addr) == 0) {
								mreq.imr_interface.s_addr = src_addr.sin_addr.s_addr;
							} else {
								si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, can't get address of interface index %d ", setsockopt_ip_opt_to_str(__optname), p_mreqn->imr_ifindex);
								break;
							}
						}
					}
				}

				in_addr_t mc_grp = mreq.imr_multiaddr.s_addr;
				in_addr_t mc_if = mreq.imr_interface.s_addr;

				if(! IN_MULTICAST_N(mc_grp)) {
					si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, IP %d.%d.%d.%d is not MC ", setsockopt_ip_opt_to_str(__optname),  NIPQUAD(mc_grp));
					break;
				}
				if (mc_if == INADDR_ANY) {
					in_addr_t dst_ip	= mc_grp;
					in_addr_t src_ip	= 0;
					uint8_t tos		= 0;
					uint8_t table_id 	= 0;
					
					if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
						src_ip = m_bound.get_in_addr();
					}else if (m_so_bindtodevice_ip) {
						src_ip = m_so_bindtodevice_ip;
					}
					if (!g_p_rule_table_mgr->rule_resolve(rule_table_key(dst_ip, src_ip, tos), &table_id))
					{
						si_udp_logdbg("Unable to find table ID : No rule match destination Info");
					}
					// Find local if for this MC ADD/DROP
					g_p_route_table_mgr->route_resolve(mc_grp, table_id, &mc_if);
					si_udp_logdbg("IPPROTO_IP, %s=%d.%d.%d.%d, mc_if:INADDR_ANY (resolved to: %d.%d.%d.%d)", setsockopt_ip_opt_to_str(__optname), NIPQUAD(mc_grp), NIPQUAD(mc_if));
				}
				else {
					si_udp_logdbg("IPPROTO_IP, %s=%d.%d.%d.%d, mc_if:%d.%d.%d.%d", setsockopt_ip_opt_to_str(__optname), NIPQUAD(mc_grp), NIPQUAD(mc_if));
				}

				if (mc_change_membership_start_helper(mc_grp, __optname)) {
					return -1;
				}

				// MNY: TODO: Check rules for local_if (blacklist interface feature)
				/*sock_addr tmp_if_addr(AF_INET, mc_if, m_bound.get_in_port());
				if (__vma_match_udp_receiver(TRANS_VMA, tmp_if_addr.get_p_sa(), tmp_if_addr.get_socklen(), mce_sys.app_id) == TRANS_OS) {
					// Break so we call orig setsockopt() and don't try to offlaod
					si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(__optname));
					break;
				}*/

				bool goto_os = false;

				// Check MC rules for not offloading
				sock_addr tmp_grp_addr(AF_INET, mc_grp, m_bound.get_in_port());
				if (__vma_match_udp_receiver(TRANS_VMA, mce_sys.app_id, tmp_grp_addr.get_p_sa(), tmp_grp_addr.get_socklen()) == TRANS_OS) {
					// call orig setsockopt() and don't try to offlaod
					si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(__optname));
					goto_os = true;
				}
				// Check if local_if is not offloadable
				else if (!g_p_net_device_table_mgr->get_net_device_val(mc_if)) {
					// call orig setsockopt() and don't try to offlaod
					si_udp_logdbg("setsockopt(%s) will be passed to OS for handling - not offload interface (%d.%d.%d.%d)", setsockopt_ip_opt_to_str(__optname), NIPQUAD(mc_if));
					goto_os = true;
				}
				// offloaded, check if need to pend
				else if (m_bound.get_in_port() == INPORT_ANY) {
					// Delay attaching to this MC group until we have bound UDP port
					mc_change_pending_mreq(&mreq, __optname);
				}
				// Handle attach to this MC group now
				else if (mc_change_membership(&mreq, __optname)) {
					// Opps, failed in attaching??? call orig setsockopt()
					goto_os = true;
				}

				if (goto_os) {
					int ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
					if (ret) return ret;
				}

				mc_change_membership_end_helper(mc_grp, __optname);

				return 0;
				}
				break;

			case IP_PKTINFO:
				if (__optval) {
					if(*(int*)__optval)
						m_b_pktinfo = true;
					else
						m_b_pktinfo = false;
				}
				break;
			default:
				{
					si_udp_logdbg("IPPROTO_IP, optname=%s (%d)", setsockopt_ip_opt_to_str(__optname), __optname);
				}
				break;
			}
		} // case IPPROTO_IP
		break;

	case IPPROTO_UDP:
		switch (__optname) {
		case UDP_MAP_ADD:
			if (! __optval)
			{
				si_udp_loginfo("UDP_MAP_ADD __optval = NULL");
				break;
			}
			struct port_socket_t port_socket;
			port_socket.port = *(in_port_t *)__optval;
			m_port_map_lock.lock();
			if (std::find(m_port_map.begin(), m_port_map.end(), port_socket.port) == m_port_map.end()) {
				port_socket.fd = get_sock_by_L3_L4(PROTO_UDP, m_bound.get_in_addr(), port_socket.port);
				if (port_socket.fd == -1) {
					si_udp_logdbg("could not find UDP_MAP_ADD socket for port %d", ntohs(port_socket.port));
					m_port_map_lock.unlock();
					return -1;
				}
				si_udp_logdbg("found UDP_MAP_ADD socket fd for port %d. fd is %d", ntohs(port_socket.port), port_socket.fd);			
				m_port_map.push_back(port_socket);
			}
			m_port_map_lock.unlock();
			return 0;

		case UDP_MAP_REMOVE:
			if (! __optval)
			{
				si_udp_loginfo("UDP_MAP_REMOVE __optval = NULL");
				break;
			}
			in_port_t port = *(in_port_t *)__optval;
			si_udp_logdbg("stopping de-muxing packets to port %d", ntohs(port));
			m_port_map_lock.lock();
			m_port_map.erase(std::remove(m_port_map.begin(), m_port_map.end(), port), m_port_map.end());
			m_port_map_lock.unlock();
			return 0;
		} // case IPPROTO_UDP
		break;

	default:
		{
			si_udp_logdbg("level = %d, optname = %d", __level, __optname);
		}
		break;
	}

	return orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
}

int sockinfo_udp::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
	si_udp_logfunc("level=%d, optname=%d", __level, __optname);

	int ret = orig_os_api.getsockopt(m_fd, __level, __optname, __optval, __optlen);

	if (unlikely(m_b_closed) || unlikely(g_b_exit))
		return ret;

	auto_unlocker lock_tx(m_lock_snd);
	auto_unlocker lock_rx(m_lock_rcv);

	switch (__level) {

	case SOL_SOCKET:
		{
			switch (__optname) {

			case SO_RCVBUF:
				{
					uint32_t n_so_rcvbuf_bytes = *(int*)__optval;
					si_udp_logdbg("SOL_SOCKET, SO_RCVBUF=%d", n_so_rcvbuf_bytes);

					if (m_p_socket_stats->n_rx_ready_byte_count > n_so_rcvbuf_bytes)
						si_udp_logdbg("Releasing at least %d bytes from ready rx packets queue", m_p_socket_stats->n_rx_ready_byte_count - n_so_rcvbuf_bytes);

					rx_ready_byte_count_limit_update(n_so_rcvbuf_bytes);
				}
				break;

			case SO_SNDBUF:
				si_udp_logdbg("SOL_SOCKET, SO_SNDBUF=%d", *(int*)__optval);
				break;

			default:
				si_udp_logdbg("SOL_SOCKET, optname=%d", __optname);
				break;
			}

		} // case SOL_SOCKET
		break;

	default:
		{
			si_udp_logdbg("level = %d, optname = %d", __level, __optname);
		}
		break;
	}

	return ret;
}

// Drop rx ready packets from head of queue
void sockinfo_udp::rx_ready_byte_count_limit_update(size_t n_rx_ready_bytes_limit_new)
{
	si_udp_logfunc("new limit: %d Bytes (old: %d Bytes, min value %d Bytes)", n_rx_ready_bytes_limit_new, m_p_socket_stats->n_rx_ready_byte_limit, mce_sys.rx_ready_byte_min_limit);
	if (n_rx_ready_bytes_limit_new > 0 && n_rx_ready_bytes_limit_new < mce_sys.rx_ready_byte_min_limit)
		n_rx_ready_bytes_limit_new = mce_sys.rx_ready_byte_min_limit;
	m_p_socket_stats->n_rx_ready_byte_limit = n_rx_ready_bytes_limit_new;

	m_lock_rcv.lock();
	while (m_p_socket_stats->n_rx_ready_byte_count > m_p_socket_stats->n_rx_ready_byte_limit) {
		if (m_n_rx_pkt_ready_list_count) {
			mem_buf_desc_t* p_rx_pkt_desc = m_rx_pkt_ready_list.front();
			m_rx_pkt_ready_list.pop_front();
			m_n_rx_pkt_ready_list_count--;
			m_rx_ready_byte_count -= p_rx_pkt_desc->path.rx.sz_payload;
			m_p_socket_stats->n_rx_ready_pkt_count--;
			m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->path.rx.sz_payload;

			reuse_buffer(p_rx_pkt_desc);
		}
		else
			break;
	}
	m_lock_rcv.unlock();

	return;
}

inline int sockinfo_udp::rx_wait(bool blocking)
{
	ssize_t ret = 0;
	int32_t	loops = 0;
	int32_t loops_to_go = blocking ? m_loops_to_go : 1;
	epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
	uint64_t poll_sn;

        m_loops_timer.start();

	while (loops_to_go) {

		// Multi-thread polling support - let other threads have a go on this CPU
		if ((mce_sys.rx_poll_yield_loops > 0) && ((loops % mce_sys.rx_poll_yield_loops) == (mce_sys.rx_poll_yield_loops-1))) {
			sched_yield();
		}

		// Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in mce_sys.rx_udp_poll_os_ratio)
		if ((mce_sys.rx_udp_poll_os_ratio > 0) && (m_rx_udp_poll_os_ratio_counter >= mce_sys.rx_udp_poll_os_ratio)) {
			ret = poll_os();
			if ((ret == -1) || (ret == 1)) {
				return ret;
			}
		}

		// Poll cq for offloaded ready packets ...
		m_rx_udp_poll_os_ratio_counter++;
		if (is_readable(&poll_sn)) {
			m_p_socket_stats->counters.n_rx_poll_hit++;
			return 0;
		}

		loops++;
		if (!blocking || mce_sys.rx_poll_num != -1) {
			loops_to_go--;
		}
		if (m_loops_timer.is_timeout()) {
			errno = EAGAIN;
			return -1;
		}

		if (unlikely(m_b_closed)) {
			errno = EBADFD;
			si_udp_logdbg("returning with: EBADFD");
			return -1;
		}
		else if (unlikely(g_b_exit)) {
			errno = EINTR;
			si_udp_logdbg("returning with: EINTR");
			return -1;
		}
	} // End polling loop
	m_p_socket_stats->counters.n_rx_poll_miss++;

	while (blocking) {
		if (unlikely(m_b_closed)) {
			errno = EBADFD;
			si_udp_logdbg("returning with: EBADFD");
			return -1;
		}
		else if (unlikely(g_b_exit)) {
			errno = EINTR;
			si_udp_logdbg("returning with: EINTR");
			return -1;
		}

		if (rx_request_notification(poll_sn) > 0) {
			// Check if a wce became available while arming the cq's notification channel
			// A ready wce can be pending due to the drain logic
			if (is_readable(&poll_sn)) {
				return 0;
			}
			continue; // retry to arm cq notification channel in case there was no ready packet
		}
		else {
			//Check if we have a packet in receive queue before we go to sleep
			//(can happen if another thread was polling & processing the wce)
			//and update is_sleeping flag under the same lock to synchronize between
			//this code and wakeup mechanism.
			if (is_readable(NULL)) {
				return 0;
			}
		}


		// Block with epoll_wait()
		// on all rx_cq's notification channels and the socket's OS fd until we get an ip packet
		// release lock so other threads that wait on this socket will not consume CPU
		m_lock_rcv.lock();
		if (!m_n_rx_pkt_ready_list_count) {
			going_to_sleep();
			m_lock_rcv.unlock();
		} else {
			m_lock_rcv.unlock();
			continue;
		}

		ret = orig_os_api.epoll_wait(m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, m_loops_timer.time_left_msec());

		m_lock_rcv.lock();
		return_from_sleep();
		m_lock_rcv.unlock();

		if ( ret == 0 ) { //timeout
			errno = EAGAIN;
			return -1;
		}

		if (unlikely(ret == -1)) {
			if (errno == EINTR) {
				si_udp_logdbg("EINTR from blocked epoll_wait() (ret=%d, errno=%d %m)", ret, errno);
			}
			else {
				si_udp_logdbg("error from blocked epoll_wait() (ret=%d, errno=%d %m)", ret, errno);
			}

			m_p_socket_stats->counters.n_rx_os_errors++;
			return -1;
		}

		if (ret > 0) {

			/* Quick check for a ready rx datagram on this sockinfo
			* (if some other sockinfo::rx might have added a rx ready packet to our pool
			*
			* This is the classical case of wakeup, but we don't want to
			* waist time on removing wakeup fd, it will be done next time
			*/
			if (is_readable(NULL)) {
				return 0;
			}

			// Run through all ready fd's
			for (int event_idx = 0; event_idx < ret; ++event_idx) {
				int fd = rx_epfd_events[event_idx].data.fd;
				if (is_wakeup_fd(fd)) {
					m_lock_rcv.lock();
					remove_wakeup_fd();
					m_lock_rcv.unlock();
					continue;
				}

				// Check if OS fd is ready for reading
				if (fd == m_fd) {
					m_rx_udp_poll_os_ratio_counter = 0;
					return 1;
				}

				// All that is left is our CQ offloading channel fd's
				// poll cq. fd == cq channel fd.
				// Process one wce on the relevant CQ
				// The Rx CQ channel is non-blocking so this will always return quickly
				cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
				if (p_cq_ch_info) {
					ring* p_ring = p_cq_ch_info->get_ring();
					if (p_ring) {
						p_ring->wait_for_notification_and_process_element(CQT_RX, fd, &poll_sn);
					}
				}
			}
		}

		// Check for ready datagrams on this sockinfo
		// Our ring->poll_and_process_element might have got a ready rx datagram
		// ..or some other sockinfo::rx might have added a ready rx datagram to our list
		// In case of multiple frag we'de like to try and get all parts out of the corresponding
		// ring, so we do want to poll the cq besides the select notification
		if (is_readable(&poll_sn))
			return 0;

	} // while (blocking)

/*	ODEDS: No need for that as we always check if OS polling is needed in the first while loop
	// If not blocking and we did not find any ready datagrams in our
	// offloaded sockinfo then try the OS receive
	// But try to skip this to reduce OS calls by user param
	if (!blocking && unlikely(!m_b_closed)) {
		m_n_num_skip_os_read++;
		if (m_n_num_skip_os_read >= m_rx_skip_os_fd_check) {
			m_n_num_skip_os_read = 0;
			return 1;
		}
	}
*/
	errno = EAGAIN;
	si_udp_logfunc("returning with: EAGAIN");
	return -1;
}

ssize_t sockinfo_udp::rx(const rx_call_t call_type, iovec* p_iov,ssize_t sz_iov, 
                     int* p_flags, sockaddr *__from ,socklen_t *__fromlen, struct msghdr *__msg)
{
	int ret;
	uint64_t poll_sn;

	si_udp_logfunc("");
	
	m_lock_rcv.lock();

	if (unlikely(m_b_closed)) {
		errno = EBADFD;
		ret = -1;
		goto out;
	}
	else if (unlikely(g_b_exit)) {
		errno = EINTR;
		ret = -1;
		goto out;
	}

#ifdef VMA_TIME_MEASURE
	TAKE_T_RX_START;
#endif
	save_stats_threadid_rx();

	int rx_wait_ret;

	// Drop lock to not starve other threads
	m_lock_rcv.unlock();

	// Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in mce_sys.rx_udp_poll_os_ratio)
	if ((mce_sys.rx_udp_poll_os_ratio > 0) && (m_rx_udp_poll_os_ratio_counter >= mce_sys.rx_udp_poll_os_ratio)) {
		ret = poll_os();
		if (ret == -1) {
			m_lock_rcv.lock();
			goto out;
		}
		if (ret == 1) {
			m_lock_rcv.lock();
			goto os;
		}
	}

	// First check if we have a packet in the ready list
	if ((m_n_rx_pkt_ready_list_count > 0 && mce_sys.rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED)
	    || is_readable(&poll_sn)) {
		m_lock_rcv.lock();
		m_rx_udp_poll_os_ratio_counter++;
		if (m_n_rx_pkt_ready_list_count > 0) {
			// Found a ready packet in the list
			if (__msg) handle_cmsg(__msg);
			ret = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, p_flags);
			goto out;
		}
		m_lock_rcv.unlock();
	}

	/*
	 * We (probably) do not have a ready packet.
	 * Wait for RX to become ready.
	 */
	rx_wait_ret = rx_wait(m_b_blocking && !(*p_flags & MSG_DONTWAIT));

	m_lock_rcv.lock();

	if (likely(rx_wait_ret == 0)) {
		// Got 0, means we must have a ready packet
		if (__msg) handle_cmsg(__msg);
		ret = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, p_flags);
		goto out;
	}
	else if (unlikely(rx_wait_ret < 0)) {
		// Got < 0, means an error occurred
		ret = rx_wait_ret;
		goto out;
	} // else - packet in OS

	/*
	 * If we got here, either the socket is not offloaded or rx_wait() returned 1.
	 */
os:
	if (*p_flags & MSG_VMA_ZCOPY_FORCE) {
		errno = EIO;
		ret = -1;
		goto out;
	}

#ifdef VMA_TIME_MEASURE
	INC_GO_TO_OS_RX_COUNT;
#endif

	*p_flags &= ~MSG_VMA_ZCOPY;
	ret = socket_fd_api::rx_os(call_type, p_iov, sz_iov, p_flags, __from, __fromlen, __msg);
	save_stats_rx_os(ret);
	if (ret > 0) {
		// This will cause the next non-blocked read to check the OS again.
		// We do this only after a successful read.
		m_rx_udp_poll_os_ratio_counter = mce_sys.rx_udp_poll_os_ratio;
	}

out:
	m_lock_rcv.unlock();

	if (__msg)
		__msg->msg_flags |= (*p_flags) & MSG_TRUNC;

	if (ret < 0) {
#ifdef VMA_TIME_MEASURE
		INC_ERR_RX_COUNT;
#endif
		si_udp_logfunc("returning with: %d (errno=%d %m)", ret, errno);
	}
	else {
#ifdef VMA_TIME_MEASURE
		TAKE_T_RX_END;
#endif
		si_udp_logfunc("returning with: %d", ret);
	}
	return ret;
}

void sockinfo_udp::handle_recv_timestamping(struct cmsg_state *cm_state)
{
	struct {
		struct timespec systime;
		struct timespec hwtimetrans;
		struct timespec hwtimeraw;
	} tsing;

	memset(&tsing, 0, sizeof(tsing));

	tsing.systime = m_rx_pkt_ready_list.front()->path.rx.timestamp;

	// timestamping was requested after packet arrived
	if (!tsing.systime.tv_nsec && !tsing.systime.tv_sec) {
		//this mean that a packet which came first might have later timestamp than a packet which came second.
		clock_gettime(CLOCK_REALTIME, &(tsing.systime));
	}

	// Only fill in SO_TIMESTAMPNS if both requested.
	// This matches the kernel behavior.
	if (m_b_rcvtstampns) {
		insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPNS, &tsing.systime, sizeof(tsing.systime));
	} else if (m_b_rcvtstamp) {
		struct timeval tv;
		tv.tv_sec = tsing.systime.tv_sec;
		tv.tv_usec = tsing.systime.tv_nsec/1000;
		insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMP, &tv, sizeof(tv));
	}

	// Only support software timestamps at this time
	if (!(m_n_tsing_flags & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE))) {
		return;
	}

	insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPING, &tsing, sizeof(tsing));
}

void sockinfo_udp::handle_ip_pktinfo(struct cmsg_state * cm_state)
{
	struct in_pktinfo in_pktinfo;
	rx_net_device_map_t::iterator iter = m_rx_nd_map.find(m_rx_pkt_ready_list.front()->path.rx.local_if);
	if (iter == m_rx_nd_map.end()) {
		si_udp_logerr("could not find net device for ip %d.%d.%d.%d", NIPQUAD(m_rx_pkt_ready_list.front()->path.rx.local_if));
		return;
	}
	in_pktinfo.ipi_ifindex = iter->second.p_ndv->get_if_idx();
	in_pktinfo.ipi_addr = m_rx_pkt_ready_list.front()->path.rx.dst.sin_addr;
	in_pktinfo.ipi_spec_dst.s_addr = m_rx_pkt_ready_list.front()->path.rx.local_if;
	insert_cmsg(cm_state, IPPROTO_IP, IP_PKTINFO, &in_pktinfo, sizeof(struct in_pktinfo));
}

void sockinfo_udp::insert_cmsg(struct cmsg_state * cm_state, int level, int type, void *data, int len)
{
	if (!cm_state->cmhdr ||
	    cm_state->mhdr->msg_flags & MSG_CTRUNC)
		return;

	// Ensure there is enough space for the data payload
	const unsigned int cmsg_len = CMSG_LEN(len);
	if (cmsg_len > cm_state->mhdr->msg_controllen - cm_state->cmsg_bytes_consumed) {
	    cm_state->mhdr->msg_flags |= MSG_CTRUNC;
		return;
	}

	// Fill in the cmsghdr
	cm_state->cmhdr->cmsg_level = level;
	cm_state->cmhdr->cmsg_type = type;
	cm_state->cmhdr->cmsg_len = cmsg_len;
	memcpy(CMSG_DATA(cm_state->cmhdr), data, len);

	// Update bytes consumed to update msg_controllen later
	cm_state->cmsg_bytes_consumed += CMSG_SPACE(len);

	// Advance to next cmsghdr
	// can't simply use CMSG_NXTHDR() due to glibc bug 13500
	struct cmsghdr *next = (struct cmsghdr*)((char*)cm_state->cmhdr +
						 CMSG_ALIGN(cm_state->cmhdr->cmsg_len));
	if ((char*)(next + 1) >
	    ((char*)cm_state->mhdr->msg_control + cm_state->mhdr->msg_controllen))
		cm_state->cmhdr = NULL;
	else
		cm_state->cmhdr = next;
}

void sockinfo_udp::handle_cmsg(struct msghdr * msg)
{
	struct cmsg_state cm_state;

	cm_state.mhdr = msg;
	cm_state.cmhdr = CMSG_FIRSTHDR(msg);
	cm_state.cmsg_bytes_consumed = 0;

	if (m_b_pktinfo) handle_ip_pktinfo(&cm_state);
	if (m_b_rcvtstamp || m_n_tsing_flags) handle_recv_timestamping(&cm_state);

	cm_state.mhdr->msg_controllen = cm_state.cmsg_bytes_consumed;
}

// This function is relevant only for non-blocking socket
void sockinfo_udp::set_immediate_os_sample()
{
	m_rx_udp_poll_os_ratio_counter = mce_sys.rx_udp_poll_os_ratio;
}

// This function is relevant only for non-blocking socket
void sockinfo_udp::unset_immediate_os_sample()
{
	m_rx_udp_poll_os_ratio_counter = 0;
}

bool sockinfo_udp::is_readable(uint64_t *p_poll_sn, fd_array_t* p_fd_ready_array)
{
	si_udp_logfuncall("");

	// Check local list of ready rx packets
	// This is the quickest way back to the user with a ready packet (which will happen if we don't force draining of the CQ)
	if (m_n_rx_pkt_ready_list_count > 0) {

		if (mce_sys.rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) {
			si_udp_logfunc("=> true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
			return true;
		}
		else {
			tscval_t tsc_now = TSCVAL_INITIALIZER;
			gettimeoftsc(&tsc_now);
			if (tsc_now - g_si_tscv_last_poll < mce_sys.rx_delta_tsc_between_cq_polls) {
				si_udp_logfunc("=> true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
				return true;
			}

			// Getting here means that although socket has rx 
			// ready packets we still want to poll the CQ 
			g_si_tscv_last_poll = tsc_now;
		}
	}


	// Loop on rx cq_list and process waiting wce (non blocking! polling only from this context)
	// AlexR todo: would be nice to start after the last cq_pos for better cq coverage
	if (p_poll_sn) {
		consider_rings_migration();
		si_udp_logfuncall("try poll rx cq's");
		rx_ring_map_t::iterator rx_ring_iter;
		m_rx_ring_map_lock.lock();
		for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
			if (rx_ring_iter->second.refcnt <= 0)
				continue;

			ring* p_ring = rx_ring_iter->first;
			while(1) {
				int ret = p_ring->poll_and_process_element_rx(p_poll_sn, p_fd_ready_array);

				if (ret <= 0) {
					break; // Get out of the CQ polling while loop (no wce or error case)
				}

				/* else (ret > 0) - at least one processed wce */
				if (m_n_rx_pkt_ready_list_count) {
					// Get out of the CQ polling loop
					si_udp_logfunc("=> polled true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
					m_rx_ring_map_lock.unlock();
					return true;
				}
			}
		}
		m_rx_ring_map_lock.unlock();
	}

	// Check local list of ready rx packets
	// This check is added in case we processed all wce and drained the cq
	//TODO: handle the scenario of 2 thread accessing the same socket - might need to lock m_n_rx_pkt_ready_list_count
	if (m_n_rx_pkt_ready_list_count) {
		si_udp_logfunc("=> true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
		return true;
	}

	// Not ready packets in ready queue, return false
	si_udp_logfuncall("=> false (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
	return false;
}

int sockinfo_udp::rx_request_notification(uint64_t poll_sn)
{
	si_udp_logfuncall("");
	int ring_ready_count = 0, ring_armed_count = 0;
	rx_ring_map_t::iterator rx_ring_iter;
	m_rx_ring_map_lock.lock();
	for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
		ring* p_ring = rx_ring_iter->first;
		int ret = p_ring->request_notification(CQT_RX, poll_sn);
		if (ret > 0) {
			// cq not armed and might have ready completions for processing
			ring_ready_count++;
		}
		else if (ret == 0) {
			// cq armed
			ring_armed_count++;
		}
		else { //if (ret < 0) 
			si_udp_logerr("failure from ring[%p]->request_notification() (errno=%d %m)", p_ring, errno);
		}
	}
	m_rx_ring_map_lock.unlock();

	si_udp_logfunc("armed or busy %d ring(s) and %d ring are pending processing", ring_armed_count, ring_ready_count);
	return ring_ready_count;
}

ssize_t sockinfo_udp::tx(const tx_call_t call_type, const struct iovec* p_iov, const ssize_t sz_iov,
		     const int __flags /*=0*/, const struct sockaddr *__dst /*=NULL*/, const socklen_t __dstlen /*=0*/)
{
	int ret;
	bool is_dropped = false;
	dst_entry* p_dst_entry = m_p_connected_dst_entry; // Default for connected() socket but we'll update it on a specific sendTO(__to) call

	si_udp_logfunc("");

	m_lock_snd.lock();

	save_stats_threadid_tx();

	if (unlikely(m_b_closed) || unlikely(g_b_exit))
		goto tx_packet_to_os;

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_START;
#endif

	if (__dst != NULL) {
		if (__dstlen < sizeof(struct sockaddr_in)) {
			si_udp_logdbg("going to os, dstlen < sizeof(struct sockaddr_in), dstlen = %d", __dstlen);
			goto tx_packet_to_os;
		}
		if (get_sa_family(__dst) != AF_INET) {
			si_udp_logdbg("to->sin_family != AF_INET (tx-ing to os)");
			goto tx_packet_to_os;
		}
		if (unlikely(__flags & MSG_OOB)) {
			si_udp_logdbg("MSG_OOB not supported in UDP (tx-ing to os)");
			goto tx_packet_to_os;
		}

		sock_addr dst((struct sockaddr*)__dst);

		// Find dst_entry in map (create one if needed)
		dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.find(dst);

		if (likely(dst_entry_iter != m_dst_entry_map.end())) {

			// Fast path
			// We found our target dst_entry object
			p_dst_entry = dst_entry_iter->second;
		}
		else {
			// Slow path
			// We do not have the correct dst_entry in the map and need to create a one

			// Verify we are bounded (got a local port)
			// can happen in UDP sendto() directly after socket(DATAGRAM)
			if (m_bound.get_in_port() == INPORT_ANY) {
				struct sockaddr addr = {AF_INET, {0}};
				if (bind(&addr, sizeof(struct sockaddr))) {
#ifdef VMA_TIME_MEASURE
					INC_ERR_TX_COUNT;
#endif
					errno = EAGAIN;
					m_lock_snd.unlock();
					return -1;
				}
			}
			in_port_t src_port = m_bound.get_in_port();

			// Create the new dst_entry
			if (dst.is_mc()) {
				p_dst_entry = new dst_entry_udp_mc(dst.get_in_addr(), dst.get_in_port(), src_port,
						m_mc_tx_if ? m_mc_tx_if : m_bound.get_in_addr(), m_b_mc_tx_loop, m_n_mc_ttl, m_fd);
			}
			else {
				p_dst_entry = new dst_entry_udp(dst.get_in_addr(), dst.get_in_port(),
						src_port, m_fd);
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!p_dst_entry) {
				si_udp_logpanic("Failed to create dst_entry(dst_ip:%s, dst_port:%d, src_port:%d)", dst.to_str_in_addr(), dst.to_str_in_port(), ntohs(src_port));
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
				p_dst_entry->set_bound_addr(m_bound.get_in_addr());
			}
			if (m_so_bindtodevice_ip) {
				p_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
			}
			// Save new dst_entry in map
			m_dst_entry_map[dst] = p_dst_entry;
			/* ADD logging
				si_udp_logfunc("Address %d.%d.%d.%d failed resolving as Tx on supported devices for interfaces %d.%d.%d.%d (tx-ing to os)", NIPQUAD(to_ip), NIPQUAD(local_if));
			//*/
		}
	}

	if (!p_dst_entry) {
		si_udp_logdbg("going to os, __dst = %p, m_p_connected_dst_entry = %p", __dst, m_p_connected_dst_entry);
		goto tx_packet_to_os;
	}

	{
		bool b_blocking = m_b_blocking;
		if (unlikely(__flags & MSG_DONTWAIT))
			b_blocking = false;

		if (p_dst_entry->try_migrate_ring(m_lock_snd)) {
			m_p_socket_stats->counters.n_tx_migrations++;
		}

		if (likely(p_dst_entry->is_valid())) {
			// All set for fast path packet sending - this is our best performance flow
			ret = p_dst_entry->fast_send((struct iovec*)p_iov, sz_iov, b_blocking);
		}
		else {
			// updates the dst_entry internal information and packet headers
			ret = p_dst_entry->slow_send(p_iov, sz_iov, b_blocking, false, __flags, this, call_type);
		}

		// TODO ALEXR - still need to handle "is_dropped" in send path
		// For now we removed the support of this feature (AlexV & AlexR)
	}

	if (likely(p_dst_entry->is_offloaded())) {

		// MNY: Problematic in cases where packet was dropped because no tx buffers were available..
		// Yet we need to add this code to avoid deadlocks in case of EPOLLOUT ET.
		notify_epoll_context(EPOLLOUT);

		save_stats_tx_offload(ret, is_dropped);

#ifdef VMA_TIME_MEASURE
		TAKE_T_TX_END;
#endif
		m_lock_snd.unlock();

		return ret;
	}
	else {
		goto tx_packet_to_os_stats;
	}

tx_packet_to_os:
#ifdef VMA_TIME_MEASURE
	INC_GO_TO_OS_TX_COUNT;
#endif
	// Calling OS transmit
	ret = socket_fd_api::tx_os(call_type, p_iov, sz_iov, __flags, __dst, __dstlen);

tx_packet_to_os_stats:
	save_stats_tx_os(ret);
	m_lock_snd.unlock();
	return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
bool sockinfo_udp::tx_check_if_would_not_block()
{
	si_udp_logfuncall("");
	return true;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

bool sockinfo_udp::rx_input_cb(mem_buf_desc_t* p_desc, void* pv_fd_ready_array)
{
	// Check that sockinfo is bound to the packets dest port
	if (p_desc->path.rx.dst.sin_port != m_bound.get_in_port()) {
		si_udp_logfunc("rx packet discarded - not socket's bound port (pkt: %d, sock:%s)",
		           ntohs(p_desc->path.rx.dst.sin_port), m_bound.to_str_in_port());
		return false;
	}

	if (m_connected.get_in_port() != INPORT_ANY && m_connected.get_in_addr() != INADDR_ANY) {
		if (m_connected.get_in_port() != p_desc->path.rx.src.sin_port) {
			si_udp_logfunc("rx packet discarded - not socket's connected port (pkt: %d, sock:%s)",
				   ntohs(p_desc->path.rx.src.sin_port), m_connected.to_str_in_port());
			return false;
		}

		if (m_connected.get_in_addr() != p_desc->path.rx.src.sin_addr.s_addr) {
			si_udp_logfunc("rx packet discarded - not socket's connected port (pkt: [%d:%d:%d:%d], sock:[%s])",
				   NIPQUAD(p_desc->path.rx.src.sin_addr.s_addr), m_connected.to_str_in_addr());
			return false;
		}
	}

	// if loopback is disabled, discard loopback packets.
	// in linux, loopback control (set by setsockopt) is done in TX flow.
	// since we currently can't control it in TX, we behave like windows, which filter on RX
	if (!m_b_mc_tx_loop && p_desc->path.rx.local_if == p_desc->path.rx.src.sin_addr.s_addr) {
		si_udp_logfunc("rx packet discarded - loopback is disabled (pkt: [%d:%d:%d:%d], sock:%s)",
			NIPQUAD(p_desc->path.rx.src.sin_addr.s_addr), m_bound.to_str_in_addr());
		return false;
	}

	// Check port mapping - redirecting packets to another socket
	while (!m_port_map.empty()) {
		m_port_map_lock.lock();
		if (m_port_map.empty()) {
			m_port_map_lock.unlock();
			break;
		}
		m_port_map_index = ((m_port_map_index + 1) >= m_port_map.size() ? 0 : (m_port_map_index + 1));
		int new_port = m_port_map[m_port_map_index].port;
		socket_fd_api* sock_api = g_p_fd_collection->get_sockfd(m_port_map[m_port_map_index].fd);
		if (!sock_api || sock_api->get_type()!=FD_TYPE_SOCKET) {
			m_port_map.erase(std::remove(m_port_map.begin(), m_port_map.end(), m_port_map[m_port_map_index].port));
			if(m_port_map_index) m_port_map_index--;
			m_port_map_lock.unlock();
			continue;
		}
		m_port_map_lock.unlock();
		p_desc->path.rx.dst.sin_port = new_port;
		return ((sockinfo_udp*)sock_api)->rx_input_cb(p_desc, pv_fd_ready_array);
	}

	// Check if sockinfo rx byte quato reached - then disregard this packet
	if (m_p_socket_stats->n_rx_ready_byte_count >= m_p_socket_stats->n_rx_ready_byte_limit) {
		si_udp_logfunc("rx packet discarded - socket limit reached (%d bytes)", m_p_socket_stats->n_rx_ready_byte_limit);
		m_p_socket_stats->counters.n_rx_ready_byte_drop += p_desc->path.rx.sz_payload;
		m_p_socket_stats->counters.n_rx_ready_pkt_drop++;
		return false;
	}

	if (unlikely(m_b_closed) || unlikely(g_b_exit)) {
		si_udp_logfunc("rx packet discarded - fd closed");
		return false;
	}

	vma_recv_callback_retval_t callback_retval = VMA_PACKET_RECV;
	if (m_rx_callback) {
		mem_buf_desc_t *tmp;
		vma_info_t pkt_info;
		int nr_frags = 0;

		pkt_info.struct_sz = sizeof(pkt_info);
		pkt_info.datagram_id = (void*)p_desc;
		pkt_info.src = &p_desc->path.rx.src;
		pkt_info.dst = &p_desc->path.rx.dst;
		pkt_info.socket_ready_queue_pkt_count = m_p_socket_stats->n_rx_ready_pkt_count;
		pkt_info.socket_ready_queue_byte_count = m_p_socket_stats->n_rx_ready_byte_count;

		// fill io vector array with data buffer pointers
		iovec iov[p_desc->n_frags];
		nr_frags = 0;
		for (tmp = p_desc; tmp; tmp = tmp->p_next_desc) {
			iov[nr_frags++] = tmp->path.rx.frag;
		}

		// call user callback
		callback_retval = m_rx_callback(m_fd, nr_frags, iov,
		                                &pkt_info, m_rx_callback_context);

		if (callback_retval == VMA_PACKET_DROP) {
			si_udp_logfunc("rx packet discarded - by user callback");
			m_p_socket_stats->counters.n_rx_ready_byte_drop += p_desc->path.rx.sz_payload;
			m_p_socket_stats->counters.n_rx_ready_pkt_drop++;
			return false;
		}
	}

	// Yes, we want to keep this packet!
	// And we must increment ref_counter before pushing this packet into the ready queue
	//  to prevent race condition with the 'if( (--ref_count) <= 0)' in ib_comm_mgr
	p_desc->inc_ref_count();

	if (m_b_rcvtstamp || (m_n_tsing_flags & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE))) {
		clock_gettime(CLOCK_REALTIME, &(p_desc->path.rx.timestamp));
	}

	// In ZERO COPY case we let the user's application manage the ready queue
	if (callback_retval != VMA_PACKET_HOLD) {
		m_lock_rcv.lock();
		// Save rx packet info in our ready list
		m_rx_pkt_ready_list.push_back(p_desc);
		m_n_rx_pkt_ready_list_count++;
		m_rx_ready_byte_count += p_desc->path.rx.sz_payload;
		m_p_socket_stats->n_rx_ready_pkt_count++;
		m_p_socket_stats->n_rx_ready_byte_count += p_desc->path.rx.sz_payload;
		m_p_socket_stats->counters.n_rx_ready_pkt_max = max((uint32_t)m_p_socket_stats->n_rx_ready_pkt_count, m_p_socket_stats->counters.n_rx_ready_pkt_max);
		m_p_socket_stats->counters.n_rx_ready_byte_max = max((uint32_t)m_p_socket_stats->n_rx_ready_byte_count, m_p_socket_stats->counters.n_rx_ready_byte_max);
		do_wakeup();
		m_lock_rcv.unlock();
	}

	notify_epoll_context(EPOLLIN);

	// Add this fd to the ready fd list
        io_mux_call::update_fd_array((fd_array_t*)pv_fd_ready_array, m_fd);

	si_udp_logfunc("rx ready count = %d packets / %d bytes", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);

	// Yes we like this packet - keep it!
	return true;
}

void sockinfo_udp::rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_udp_logdbg("");
	sockinfo::rx_add_ring_cb(flow_key, p_ring, is_migration);

	//Now that we got at least 1 CQ attached enable the skip os mechanism.
	m_rx_udp_poll_os_ratio_counter = mce_sys.rx_udp_poll_os_ratio;

	// Now that we got at least 1 CQ attached start polling the CQs
	if (m_b_blocking)
        	m_loops_to_go = mce_sys.rx_poll_num;
	else
		m_loops_to_go = 1; // Force single CQ poll in case of non-blocking socket


	// Multicast Only:
	// Check and Issue ADD_MEMBERSHIP to OS

	if (!flow_key.is_udp_mc() || is_migration)
		return;

	// Validate that the IGMP flags in the interface is set correctly
	validate_igmpv2(flow_key);

	// Issue kernel IP_ADD_MEMBERSHIP for IGMP join etc
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = flow_key.get_dst_ip();
	mreq.imr_interface.s_addr = flow_key.get_local_if();
	si_udp_logdbg("calling orig_setsockopt(ADD_MEMBERSHIP) for igmp support by OS");
	if (orig_os_api.setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		si_udp_logdbg("orig setsockopt(ADD_MEMBERSHIP) failed (errno=%d %m)", errno);
	}

	// Now we're done with the IP_ADD_MEMBERSHIP
}

void sockinfo_udp::rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_udp_logdbg("");
	
	// Multicast Only: 
	// Check and Issue DROP_MEMBERSHIP to OS
	if (flow_key.is_udp_mc() && !is_migration) {

		// Issue kernel IP_DROP_MEMBERSHIP for IGMP cleanup in case this is a re-play scenario
		struct ip_mreq mreq;
		mreq.imr_multiaddr.s_addr = flow_key.get_dst_ip();
		mreq.imr_interface.s_addr = flow_key.get_local_if();
		si_udp_logdbg("calling orig_setsockopt(DROP_MEMBERSHIP) for igmp cleanup in OS");
		BULLSEYE_EXCLUDE_BLOCK_START
		if (orig_os_api.setsockopt(m_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq))) {
			si_udp_logerr("orig setsockopt(DROP_MEMBERSHIP) failed (errno=%d %m)", errno);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	sockinfo::rx_del_ring_cb(flow_key, p_ring, is_migration);

	// If no more CQ's are attached on this socket, return CQ polling loops ot init state
	if (m_rx_ring_map.size() <= 0) {
		if (m_b_blocking)
			m_loops_to_go = mce_sys.rx_poll_num_init;
		else
			m_loops_to_go = 1;
	}
}

void sockinfo_udp::set_blocking(bool is_blocked)
{
	sockinfo::set_blocking(is_blocked);

	if (m_b_blocking) {
		// Set the high CQ polling RX_POLL value 
		// depending on where we have mapped offloaded MC gorups
		if (m_rx_ring_map.size() > 0)
			m_loops_to_go = mce_sys.rx_poll_num;
		else
			m_loops_to_go = mce_sys.rx_poll_num_init;
	}
	else {
		// Force single CQ poll in case of non-blocking socket
		m_loops_to_go = 1;
	}
}

void sockinfo_udp::handle_pending_mreq()
{
	si_udp_logdbg("Attaching to pending multicast groups");

	ip_mreq_list_t::iterator mreq_iter, mreq_iter_temp;
	for (mreq_iter = m_pending_mreqs.begin(); mreq_iter != m_pending_mreqs.end();) {
		if ((m_sock_offload == false) || mc_change_membership(&(*mreq_iter), IP_ADD_MEMBERSHIP)) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (orig_os_api.setsockopt(m_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &(*mreq_iter), sizeof(struct ip_mreq))) {
				si_udp_logerr("orig setsockopt(ADD_MEMBERSHIP) failed (errno=%d %m)", errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
		mreq_iter_temp = mreq_iter;
		++mreq_iter;
		m_pending_mreqs.erase(mreq_iter_temp);
	}
}

int sockinfo_udp::mc_change_pending_mreq(const struct ip_mreq *p_mreq, int optname)
{
	si_udp_logdbg("setsockopt(%s) will be pending until bound to UDP port", setsockopt_ip_opt_to_str(optname));

	ip_mreq_list_t::iterator mreq_iter, mreq_iter_temp;
	switch (optname) {
	case IP_ADD_MEMBERSHIP:
		m_pending_mreqs.push_back(*p_mreq);
		break;
	case IP_DROP_MEMBERSHIP:
		for (mreq_iter = m_pending_mreqs.begin(); mreq_iter != m_pending_mreqs.end();) {
			if (mreq_iter->imr_multiaddr.s_addr == p_mreq->imr_multiaddr.s_addr) {
				mreq_iter_temp = mreq_iter;
				++mreq_iter;
				m_pending_mreqs.erase(mreq_iter_temp);
			} else {
				++mreq_iter;
			}
		}
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) illegal", setsockopt_ip_opt_to_str(optname));
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	return 0;
}

int sockinfo_udp::mc_change_membership_start_helper(in_addr_t mc_grp, int optname)
{
	switch (optname) {
	case IP_ADD_MEMBERSHIP:
		if (m_mc_memberships_map.find(mc_grp) == m_mc_memberships_map.end()
				&&  m_mc_memberships_map.size() >= (size_t)g_n_os_igmp_max_membership) {
			errno = ENOBUFS;
			return -1;
		}
		break;
	case IP_DROP_MEMBERSHIP:
		break;
		BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(optname));
		return -1;
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	return 0;
}

int sockinfo_udp::mc_change_membership_end_helper(in_addr_t mc_grp, int optname)
{
	switch (optname) {
	case IP_ADD_MEMBERSHIP:
		m_mc_memberships_map[mc_grp] = 1;
		break;
	case IP_DROP_MEMBERSHIP:
		m_mc_memberships_map.erase(mc_grp);
		break;
		BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(optname));
		return -1;
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	return 0;
}

int sockinfo_udp::mc_change_membership(const struct ip_mreq *p_mreq, int optname)
{
	in_addr_t mc_grp = p_mreq->imr_multiaddr.s_addr;
	in_addr_t mc_if = p_mreq->imr_interface.s_addr;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (IN_MULTICAST_N(mc_grp) == false) {
		si_udp_logerr("%s for non multicast (%d.%d.%d.%d) %#x", setsockopt_ip_opt_to_str(optname), NIPQUAD(mc_grp), mc_grp);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	sock_addr tmp_grp_addr(AF_INET, mc_grp, m_bound.get_in_port());
	if (__vma_match_udp_receiver(TRANS_VMA, mce_sys.app_id, tmp_grp_addr.get_p_sa(), tmp_grp_addr.get_socklen()) == TRANS_OS) {
		// Break so we call orig setsockopt() and don't try to offlaod
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(optname));
		return -1;
	}

	if (mc_if == INADDR_ANY) {
		in_addr_t dst_ip	= mc_grp;
		in_addr_t src_ip	= 0;
		uint8_t tos		= 0;
		uint8_t table_id 	= 0;
		
		if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
			src_ip = m_bound.get_in_addr();
		}else if (m_so_bindtodevice_ip) {
			src_ip = m_so_bindtodevice_ip;
		}
		if (!g_p_rule_table_mgr->rule_resolve(rule_table_key(dst_ip, src_ip, tos), &table_id))
		{
			si_udp_logdbg("Unable to find table ID : No rule match destination Info");
		}
		// Find local if for this MC ADD/DROP
		g_p_route_table_mgr->route_resolve(mc_grp, table_id, &mc_if);
	}

	// MNY: TODO: Check rules for local_if (blacklist interface feature)
	/*sock_addr tmp_if_addr(AF_INET, mc_if, m_bound.get_in_port());
	if (__vma_match_udp_receiver(TRANS_VMA, tmp_if_addr.get_p_sa(), tmp_if_addr.get_socklen(), mce_sys.app_id) == TRANS_OS) {
		// Break so we call orig setsockopt() and don't try to offlaod
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(optname));
		return -1;
	}*/

	// Check if local_if is offloadable
	if (!g_p_net_device_table_mgr->get_net_device_val(mc_if)) {
		// Break so we call orig setsockopt() and try to offlaod
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling - not offload interface (%d.%d.%d.%d)", setsockopt_ip_opt_to_str(optname), NIPQUAD(mc_if));
		return -1;
	}

	flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), m_connected.get_in_addr(), m_connected.get_in_port(), PROTO_UDP, mc_if);

	switch (optname) {
	case IP_ADD_MEMBERSHIP:
		if (!attach_receiver(flow_key)) {
			return -1;
		}
		vma_stats_mc_group_add(mc_grp, m_p_socket_stats);
		break;

	case IP_DROP_MEMBERSHIP:
		if (!detach_receiver(flow_key)) {
			return -1;
		}
		vma_stats_mc_group_remove(mc_grp, m_p_socket_stats);
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(optname));
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	return 0;
}


int sockinfo_udp::validate_igmpv2(char* ifname)
{
	char igmp_force_value = 0;
	char igmpver_filename[256];
	
	char base_ifname[IFNAMSIZ];
	if (get_base_interface_name((const char*)ifname, base_ifname, sizeof(base_ifname))) {
		vlog_printf(VLOG_ERROR,"VMA couldn't map %s for IGMP version validation\n", ifname);
		return 0;
	}

	// Read the value stored for FORCE IGMP VERSION flag

	// IGMP_FORCE_ALL_IF_PARAM_FILE is: "/proc/sys/net/ipv4/conf/all/force_igmp_version"
	sprintf(igmpver_filename, IGMP_FORCE_PARAM_FILE, "all");
	if (priv_read_file(igmpver_filename, &igmp_force_value, 1) <= 0) {
		return 1;
	}
	if (igmp_force_value == '0') { 
		// Check the specific interface configuration 
		// IGMP_FORCE_PARAM_FILE is: "/proc/sys/net/ipv4/conf/%s/force_igmp_version"
		sprintf(igmpver_filename, IGMP_FORCE_PARAM_FILE, base_ifname);
		priv_read_file(igmpver_filename, &igmp_force_value, 1);
	}
	if (igmp_force_value != '2' && igmp_force_value != '1') {  
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
		vlog_printf(VLOG_WARNING,"IGMP Version flag is not forced to IGMPv2 for interface %s!\n", base_ifname);
		vlog_printf(VLOG_WARNING,"Working in this mode might causes VMA functionality degradation\n");
		if (igmp_force_value != 0) {
                	vlog_printf(VLOG_WARNING,"Please \"echo 2 > %s\"\n", igmpver_filename);
			vlog_printf(VLOG_WARNING,"before loading your application with VMA library\n");
		}
		vlog_printf(VLOG_WARNING,"Please refer to the IGMP section in the VMA's User Manual for more information\n");
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
	}
	return 0;
}

// This function will validate that IGMP is forced to V2
// on the interface (IPR only supports IGMP V2)
// If not correct (or any failure) it will log warning message
void sockinfo_udp::validate_igmpv2(flow_tuple_with_local_if& flow_key)
{
	int found = 1;
	int igmp_ret = -1;
	char ifname[IFNAMSIZ] = "\0";
	unsigned int ifflags; /* Flags as from SIOCGIFFLAGS ioctl. */

	if (!get_local_if_info(flow_key.get_local_if(), ifname, ifflags)) {
		found = 0;
		goto clean_and_exit;
	}

	if (get_iftype_from_ifname(ifname) == ARPHRD_INFINIBAND && !mce_sys.suppress_igmp_warning) {
		igmp_ret = validate_igmpv2(ifname); // Extract IGMP version flag
	}
	else {
		si_udp_logdbg("Skipping igmpv2 validation check");
		igmp_ret = 0;
	}

clean_and_exit:
	if (!found || !ifname[0] || igmp_ret) {
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
		vlog_printf(VLOG_WARNING,"Error in reading IGMP Version flags for interface %d.%d.%d.%d! \n", NIPQUAD(flow_key.get_dst_ip()));
		vlog_printf(VLOG_WARNING,"Working in this mode most probably causes VMA performance degradation\n");
		vlog_printf(VLOG_WARNING,"Please refer to the IGMP section in the VMA's User Manual for more information\n");
		vlog_printf(VLOG_WARNING,"************************************************************************\n");
	}

	return;
}

void sockinfo_udp::statistics_print()
{
	bool b_any_activiy = false;
	if (m_p_socket_stats->counters.n_tx_sent_byte_count || m_p_socket_stats->counters.n_tx_sent_pkt_count || m_p_socket_stats->counters.n_tx_errors || m_p_socket_stats->counters.n_tx_drops ) {
		si_logdbg_no_funcname("Tx Offload: %d KB / %d / %d / %d [bytes/packets/drops/errors]", m_p_socket_stats->counters.n_tx_sent_byte_count/1024, m_p_socket_stats->counters.n_tx_sent_pkt_count, m_p_socket_stats->counters.n_tx_drops, m_p_socket_stats->counters.n_tx_errors);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_tx_os_bytes || m_p_socket_stats->counters.n_tx_os_packets || m_p_socket_stats->counters.n_tx_os_errors) {
		si_logdbg_no_funcname("Tx OS info: %d KB / %d / %d [bytes/packets/errors]", m_p_socket_stats->counters.n_tx_os_bytes/1024, m_p_socket_stats->counters.n_tx_os_packets, m_p_socket_stats->counters.n_tx_os_errors);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_bytes || m_p_socket_stats->counters.n_rx_packets || m_p_socket_stats->counters.n_rx_errors || m_p_socket_stats->counters.n_rx_eagain || m_p_socket_stats->n_rx_ready_pkt_count) {
		si_logdbg_no_funcname("Rx Offload: %d KB / %d / %d / %d [bytes/packets/eagains/errors]", m_p_socket_stats->counters.n_rx_bytes/1024, m_p_socket_stats->counters.n_rx_packets, m_p_socket_stats->counters.n_rx_eagain, m_p_socket_stats->counters.n_rx_errors);

		float rx_drop_percentage = 0;
		if (m_p_socket_stats->counters.n_rx_packets || m_p_socket_stats->n_rx_ready_pkt_count)
			rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_byte_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
		si_logdbg_no_funcname("Rx byte: max %d / dropped %d (%2.2f%%) / limit %d", m_p_socket_stats->counters.n_rx_ready_byte_max, m_p_socket_stats->counters.n_rx_ready_byte_drop, rx_drop_percentage, m_p_socket_stats->n_rx_ready_byte_limit);

		if (m_p_socket_stats->counters.n_rx_packets || m_p_socket_stats->n_rx_ready_pkt_count)
			rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_pkt_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
		si_logdbg_no_funcname("Rx pkt : max %d / dropped %d (%2.2f%%)", m_p_socket_stats->counters.n_rx_ready_pkt_max, m_p_socket_stats->counters.n_rx_ready_pkt_drop, rx_drop_percentage);

		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_os_bytes || m_p_socket_stats->counters.n_rx_os_packets || m_p_socket_stats->counters.n_rx_os_errors || m_p_socket_stats->counters.n_rx_os_eagain) {
		si_logdbg_no_funcname("Rx OS info: %d KB / %d / %d / %d [bytes/packets/eagains/errors]", m_p_socket_stats->counters.n_rx_os_bytes/1024, m_p_socket_stats->counters.n_rx_os_packets, m_p_socket_stats->counters.n_rx_os_eagain, m_p_socket_stats->counters.n_rx_os_errors);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_poll_miss || m_p_socket_stats->counters.n_rx_poll_hit) {
		float rx_poll_hit_percentage = (float)(m_p_socket_stats->counters.n_rx_poll_hit * 100) / (float)(m_p_socket_stats->counters.n_rx_poll_miss + m_p_socket_stats->counters.n_rx_poll_hit);
		si_logdbg_no_funcname("Rx poll: %d / %d (%2.2f%%) [miss/hit]", m_p_socket_stats->counters.n_rx_poll_miss, m_p_socket_stats->counters.n_rx_poll_hit, rx_poll_hit_percentage);
		b_any_activiy = true;
	}
	if (b_any_activiy == false) {
		si_logdbg_no_funcname("Rx and Tx where not active");
	}
}

void sockinfo_udp::save_stats_threadid_rx()
{
	// Save Thread Id for statistics module
	if (g_vlogger_level >= VLOG_DEBUG)
		m_p_socket_stats->threadid_last_rx = gettid();
}

void sockinfo_udp::save_stats_threadid_tx()
{
	// Save Thread Id for statistics module
	if (g_vlogger_level >= VLOG_DEBUG)
		m_p_socket_stats->threadid_last_tx = gettid();
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
void sockinfo_udp::save_stats_rx_offload(int bytes)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_rx_bytes += bytes;
		m_p_socket_stats->counters.n_rx_packets++;
	}
	else if (errno == EAGAIN) {
		m_p_socket_stats->counters.n_rx_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_rx_errors++;
	}
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void sockinfo_udp::save_stats_tx_offload(int bytes, bool is_dropped)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_tx_sent_byte_count += bytes;
		m_p_socket_stats->counters.n_tx_sent_pkt_count++;
	}
	else if (errno == EAGAIN) {
		m_p_socket_stats->counters.n_rx_os_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_tx_errors++;
	}

	if (is_dropped) {
		m_p_socket_stats->counters.n_tx_drops++;
	}
}

int sockinfo_udp::register_callback(vma_recv_callback_t callback, void *context)
{
	m_rx_callback = callback;
	m_rx_callback_context = context;
	return 0;
}

int sockinfo_udp::free_datagrams(void **pkt_desc_ids, size_t count)
{
	int ret = 0;
	mem_buf_desc_t *buff;
	
	m_lock_rcv.lock();
	while (count--) {
		buff = (mem_buf_desc_t*)*(pkt_desc_ids++);
		if (m_rx_ring_map.find((ring*)buff->p_desc_owner) == m_rx_ring_map.end()) {
			errno = ENOENT;
			ret = -1;
			break;
		}
		reuse_buffer(buff);
		m_p_socket_stats->n_rx_zcopy_pkt_count--;
	}
	m_lock_rcv.unlock();
	return ret;
}

mem_buf_desc_t* sockinfo_udp::get_next_desc(mem_buf_desc_t *p_desc)
{
	return p_desc->p_next_desc;
}

mem_buf_desc_t* sockinfo_udp::get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx)
{
	NOT_IN_USE(rx_pkt_ready_list_idx);
	return p_desc->p_next_desc;
}

void sockinfo_udp::post_deqeue(bool release_buff)
{
	mem_buf_desc_t *to_resue = m_rx_pkt_ready_list.front();
	m_rx_pkt_ready_list.pop_front();
	m_p_socket_stats->n_rx_ready_pkt_count--;
	m_n_rx_pkt_ready_list_count--;
	if (release_buff)
		reuse_buffer(to_resue);
	m_rx_pkt_ready_offset = 0;
}

int sockinfo_udp::zero_copy_rx(iovec *p_iov, mem_buf_desc_t *p_desc, int *p_flags)
{
	mem_buf_desc_t* p_desc_iter;
	int total_rx = 0;
	int len = p_iov[0].iov_len - sizeof(vma_datagram_t);

	// Make sure there is enough room for the header
	if (len < 0) {
		errno = ENOBUFS;
		return -1;
	}

	// Copy iov pointers to user buffer
	vma_datagram_t *p_dgram = (vma_datagram_t*)p_iov[0].iov_base;
	p_dgram->datagram_id = (void*)p_desc;
	p_dgram->sz_iov = 0;
	for (p_desc_iter = p_desc; p_desc_iter; p_desc_iter = p_desc_iter->p_next_desc) {
		len -= sizeof(p_dgram->iov[0]);
		if (len < 0) {
			*p_flags = MSG_TRUNC;
			break;
		}
		p_dgram->iov[p_dgram->sz_iov++] = p_desc_iter->path.rx.frag;
		total_rx += p_desc_iter->path.rx.frag.iov_len;
	}

	m_p_socket_stats->n_rx_zcopy_pkt_count++;

	si_udp_logfunc("copied pointers to %d bytes to user buffer", total_rx);
	return total_rx;
}

size_t sockinfo_udp::handle_msg_trunc(size_t total_rx, size_t payload_size, int* p_flags)
{
	if (payload_size > total_rx) {
		m_rx_ready_byte_count -= (payload_size-total_rx);
		m_p_socket_stats->n_rx_ready_byte_count -= (payload_size-total_rx);
		if (*p_flags & MSG_TRUNC) return payload_size;
		else *p_flags |= MSG_TRUNC;
	} else {
		*p_flags &= ~MSG_TRUNC;
	}

	return total_rx;
}

inline ssize_t sockinfo_udp::poll_os()
{
	ssize_t ret;
	pollfd os_fd[1];

	m_rx_udp_poll_os_ratio_counter = 0;
	os_fd[0].fd = m_fd;
	os_fd[0].events = POLLIN;
	ret = orig_os_api.poll(os_fd, 1, 0); // Zero timeout - just poll and return quickly
	if (unlikely(ret == -1)) {
		m_p_socket_stats->counters.n_rx_os_errors++;
		si_udp_logdbg("orig_os_api.poll returned with error in polling loop (errno=%d %m)", errno);
		return -1;
	}
	if (ret == 1) {
		m_p_socket_stats->counters.n_rx_poll_os_hit++;
		return 1;
	}
	return 0;
}
