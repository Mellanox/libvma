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


#include "sockinfo_udp.h"

#include <fcntl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include "vma/util/if.h"
#include <net/if_arp.h>
#include <sys/epoll.h>
#include <algorithm>

#include "utils/bullseye.h"
#include "utils/rdtsc.h"
#include "vma/util/libvma.h"
#include "vma/sock/sock-redirect.h"
#include "vma/sock/fd_collection.h"
#include "vma/event/event_handler_manager.h"
#include "vma/dev/buffer_pool.h"
#include "vma/dev/ring.h"
#include "vma/dev/ring_slave.h"
#include "vma/dev/ring_bond.h"
#include "vma/dev/ring_simple.h"
#include "vma/dev/ring_profile.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/proto/dst_entry_tcp.h"
#include "vma/proto/dst_entry_udp.h"
#include "vma/proto/dst_entry_udp_mc.h"
#include "vma/iomux/epfd_info.h"
#include "vma/iomux/io_mux_call.h"
#include "vma/util/instrumentation.h"
#include "vma/dev/ib_ctx_handler_collection.h"

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

/* For MCD */
#define UDP_MAP_ADD             101
#define UDP_MAP_REMOVE          102

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void	sockinfo_udp::reuse_buffer(mem_buf_desc_t *buff)
{
	if(buff->dec_ref_count() <= 1) {
		buff->inc_ref_count();
		sockinfo::reuse_buffer(buff);
	}
}

inline int sockinfo_udp::poll_os()
{
	int ret;
	uint64_t pending_data = 0;

	m_rx_udp_poll_os_ratio_counter = 0;
	ret = orig_os_api.ioctl(m_fd, FIONREAD, &pending_data);
	if (unlikely(ret == -1)) {
		m_p_socket_stats->counters.n_rx_os_errors++;
		si_udp_logdbg("orig_os_api.ioctl returned with error in polling loop (errno=%d %m)", errno);
		return -1;
	}
	if (pending_data > 0) {
		m_p_socket_stats->counters.n_rx_poll_os_hit++;
		return 1;
	}
	return 0;
}

inline int sockinfo_udp::rx_wait(bool blocking)
{
	ssize_t ret = 0;
	int32_t	loops = 0;
	int32_t loops_to_go = blocking ? m_loops_to_go : 1;
	epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
	uint64_t poll_sn = 0;

        m_loops_timer.start();

	while (loops_to_go) {

		// Multi-thread polling support - let other threads have a go on this CPU
		if ((m_n_sysvar_rx_poll_yield_loops > 0) && ((loops % m_n_sysvar_rx_poll_yield_loops) == (m_n_sysvar_rx_poll_yield_loops - 1))) {
			sched_yield();
		}

		// Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in m_n_sysvar_rx_udp_poll_os_ratio)
		if ((m_n_sysvar_rx_udp_poll_os_ratio > 0) && (m_rx_udp_poll_os_ratio_counter >= m_n_sysvar_rx_udp_poll_os_ratio)) {
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
		if (!blocking || m_n_sysvar_rx_poll_num != -1) {
			loops_to_go--;
		}
		if (m_loops_timer.is_timeout()) {
			errno = EAGAIN;
			return -1;
		}

		if (unlikely(m_state == SOCKINFO_CLOSED)) {
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
		if (unlikely(m_state == SOCKINFO_CLOSED)) {
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
		/* coverity[double_lock] TODO: RM#1049980 */
		m_lock_rcv.lock();
		if (!m_n_rx_pkt_ready_list_count) {
			going_to_sleep();
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_rcv.unlock();
		} else {
			m_lock_rcv.unlock();
			continue;
		}

		ret = orig_os_api.epoll_wait(m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, m_loops_timer.time_left_msec());

		/* coverity[double_lock] TODO: RM#1049980 */
		m_lock_rcv.lock();
		return_from_sleep();
		/* coverity[double_unlock] TODO: RM#1049980 */
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
					/* coverity[double_lock] TODO: RM#1049980 */
					m_lock_rcv.lock();
					remove_wakeup_fd();
					/* coverity[double_unlock] TODO: RM#1049980 */
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
						p_ring->wait_for_notification_and_process_element(fd, &poll_sn);
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
	if (!blocking && unlikely(m_state != SOCKINFO_CLOSED)) {
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

const char * setsockopt_ip_opt_to_str(int opt)
{
	switch (opt) {
	case IP_MULTICAST_IF:           return "IP_MULTICAST_IF";
	case IP_MULTICAST_TTL:          return "IP_MULTICAST_TTL";
	case IP_MULTICAST_LOOP:         return "IP_MULTICAST_LOOP";
	case IP_ADD_MEMBERSHIP:         return "IP_ADD_MEMBERSHIP";
	case IP_ADD_SOURCE_MEMBERSHIP:  return "IP_ADD_SOURCE_MEMBERSHIP";
	case IP_DROP_MEMBERSHIP:        return "IP_DROP_MEMBERSHIP";
	case IP_DROP_SOURCE_MEMBERSHIP: return "IP_DROP_SOURCE_MEMBERSHIP";
	default:			break;
	}
	return "UNKNOWN IP opt";
}

// Throttle the amount of ring polling we do (remember last time we check for receive packets)
tscval_t g_si_tscv_last_poll = 0;

sockinfo_udp::sockinfo_udp(int fd):
	sockinfo(fd)
	,m_rx_packet_processor(&sockinfo_udp::rx_process_udp_packet_full)
	,m_mc_tx_if(INADDR_ANY)
	,m_b_mc_tx_loop(safe_mce_sys().tx_mc_loopback_default) // default value is 'true'. User can change this with config parameter SYS_VAR_TX_MC_LOOPBACK
	,m_n_mc_ttl(DEFAULT_MC_TTL)
	,m_loops_to_go(safe_mce_sys().rx_poll_num_init) // Start up with a init polling loops value
	,m_rx_udp_poll_os_ratio_counter(0)
	,m_sock_offload(true)
	,m_mc_num_grp_with_src_filter(0)
	,m_port_map_lock("sockinfo_udp::m_ports_map_lock")
	,m_port_map_index(0)
	,m_p_last_dst_entry(NULL)
	,m_tos(0)
	,m_n_sysvar_rx_poll_yield_loops(safe_mce_sys().rx_poll_yield_loops)
	,m_n_sysvar_rx_udp_poll_os_ratio(safe_mce_sys().rx_udp_poll_os_ratio)
	,m_n_sysvar_rx_ready_byte_min_limit(safe_mce_sys().rx_ready_byte_min_limit)
	,m_n_sysvar_rx_cq_drain_rate_nsec(safe_mce_sys().rx_cq_drain_rate_nsec)
	,m_n_sysvar_rx_delta_tsc_between_cq_polls(safe_mce_sys().rx_delta_tsc_between_cq_polls)
	,m_reuseaddr(false)
	,m_reuseport(false)
	,m_sockopt_mapped(false)
	,m_is_connected(false)
	,m_multicast(false)
{
	si_udp_logfunc("");

	m_protocol = PROTO_UDP;
	m_p_socket_stats->socket_type = SOCK_DGRAM;
	m_p_socket_stats->b_is_offloaded = m_sock_offload;

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

	epoll_event ev = {0, {0}};

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

	if (m_n_rx_pkt_ready_list_count || m_rx_ready_byte_count || m_rx_pkt_ready_list.size() || m_rx_ring_map.size() || m_rx_reuse_buff.n_buff_num)
		si_udp_logerr("not all buffers were freed. protocol=UDP. m_n_rx_pkt_ready_list_count=%d, m_rx_ready_byte_count=%d, m_rx_pkt_ready_list.size()=%d, m_rx_ring_map.size()=%d, m_rx_reuse_buff.n_buff_num=%d",
				m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count, (int)m_rx_pkt_ready_list.size() ,(int)m_rx_ring_map.size(), m_rx_reuse_buff.n_buff_num);

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
	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit)) {
		errno = EBUSY;
		return -1; // zero returned from orig_bind()
	}

	struct sockaddr_in bound_addr;
	socklen_t boundlen = sizeof(struct sockaddr_in);
	struct sockaddr *name = (struct sockaddr *)&bound_addr;
	socklen_t *namelen = &boundlen;

	ret = getsockname(name, namelen);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret) {
		si_udp_logdbg("getsockname failed (ret=%d %m)", ret);
		return -1; 
	}

	BULLSEYE_EXCLUDE_BLOCK_END
	// save the bound info and then attach to offload flows
	on_sockname_change(name, *namelen);
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
	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit)) {
		errno = EBUSY;
		return -1; // zero returned from orig_connect()
	}

	auto_unlocker _lock(m_lock_snd);

	// Dissolve the current connection setting if it's not AF_INET
	// (this also support the default dissolve by AF_UNSPEC)
	if (connect_to.get_sa_family() == AF_INET) {
		m_connected.set_sa_family(AF_INET);
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
*/

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
		// Call on_sockname_change (this will save the bind information and attach to unicast flow)
		struct sockaddr_in bound_addr;
		socklen_t   boundlen = sizeof(struct sockaddr_in);
		struct sockaddr *name = (struct sockaddr *)&bound_addr;
		socklen_t *namelen = &boundlen;

		ret = getsockname(name, namelen);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret) {
			si_udp_logerr("getsockname failed (ret=%d %m)", ret);
			return 0; // zero returned from orig_connect()
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		m_is_connected = true; // will inspect for SRC

		on_sockname_change(name, *namelen);

		si_udp_logdbg("bound to %s", m_bound.to_str());
		in_port_t src_port = m_bound.get_in_port();

		if (TRANS_VMA != find_target_family(ROLE_UDP_CONNECT, m_connected.get_p_sa(), m_bound.get_p_sa())) {
			setPassthrough();
			return 0;
		}
		// Create the new dst_entry
		if (IN_MULTICAST_N(dst_ip)) {
			socket_data data = { m_fd, m_n_mc_ttl, m_tos, m_pcp };
			m_p_connected_dst_entry = new dst_entry_udp_mc(dst_ip, dst_port, src_port,
					m_mc_tx_if ? m_mc_tx_if : m_bound.get_in_addr(),
							m_b_mc_tx_loop, data, m_ring_alloc_log_tx);
		}
		else {
			socket_data data = { m_fd, m_n_uc_ttl, m_tos, m_pcp };
			m_p_connected_dst_entry = new dst_entry_udp(dst_ip, dst_port,
					src_port, data, m_ring_alloc_log_tx);
		}

		BULLSEYE_EXCLUDE_BLOCK_START
		if (!m_p_connected_dst_entry) {
			si_udp_logerr("Failed to create dst_entry(dst_ip:%s, dst_port:%d, src_port:%d)", NIPQUAD(dst_ip), ntohs(dst_port), ntohs(src_port));
			m_connected.set_in_addr(INADDR_ANY);
			m_p_socket_stats->connected_ip = INADDR_ANY;
			m_connected.set_in_port(INPORT_ANY);
			m_p_socket_stats->connected_port = INPORT_ANY;
			m_is_connected = false; // will skip inspection for SRC
			return 0;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
			m_p_connected_dst_entry->set_bound_addr(m_bound.get_in_addr());
		}
		if (m_so_bindtodevice_ip) {
			m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
		}
		m_p_connected_dst_entry->prepare_to_send(m_so_ratelimit, false, true);
		return 0;
	}
	return 0;
}

int sockinfo_udp::getsockname(struct sockaddr *__name, socklen_t *__namelen)
{
	si_udp_logdbg("");

	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit)) {
		errno = EINTR;
		return -1;
	}

	return orig_os_api.getsockname(m_fd, __name, __namelen);
}

int sockinfo_udp::on_sockname_change(struct sockaddr *__name, socklen_t __namelen)
{
	NOT_IN_USE(__namelen); /* TODO use __namelen for IPV6 */

	BULLSEYE_EXCLUDE_BLOCK_START
	if (__name == NULL) {
		si_udp_logerr("invalid NULL __name");
		errno = EFAULT;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	sock_addr bindname(__name);

	sa_family_t sin_family = bindname.get_sa_family();
	if (sin_family != AF_INET) {
		si_udp_logfunc("not AF_INET family (%d)", sin_family);
		return 0; 
	}

	bool is_bound_modified = false;
	in_addr_t bound_if = bindname.get_in_addr();
	in_port_t bound_port = bindname.get_in_port();

	auto_unlocker _lock(m_lock_rcv);

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
		// 1. Check if local_if is offloadable OR is on INADDR_ANY which means attach to ALL
		// 2. Verify not binding to MC address in the UC case
		// 3. if not offloaded then set a PassThrough
		if ((m_bound.is_anyaddr() || g_p_net_device_table_mgr->get_net_device_val(m_bound.get_in_addr()))) {
			attach_as_uc_receiver(ROLE_UDP_RECEIVER); // if failed, we will get RX from OS
		}
		else if (m_bound.is_mc()) {
			// MC address binding will happen later as part of the ADD_MEMBERSHIP in handle_pending_mreq()
			si_udp_logdbg("bound to MC address, no need to attach to UC address as offloaded");
		}
		else {
			si_udp_logdbg("will be passed to OS for handling - not offload interface (%s)", m_bound.to_str());
			setPassthrough();
		}

		// Attach UDP port pending MC groups to offloaded interface (set by ADD_MEMBERSHIP before bind() was called)
		handle_pending_mreq();
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo_udp::setsockopt(int __level, int __optname, __const void *__optval, socklen_t __optlen)
{
	si_udp_logfunc("level=%d, optname=%d", __level, __optname);

	int ret = 0;

	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit))
		return orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);

	auto_unlocker lock_tx(m_lock_snd);
	auto_unlocker lock_rx(m_lock_rcv);

	if ((ret = sockinfo::setsockopt(__level, __optname, __optval, __optlen)) != SOCKOPT_PASS_TO_OS) {
		return ret;
	}

	bool supported = true;
	switch (__level) {

	case SOL_SOCKET:
		{
			switch (__optname) {

			case SO_REUSEADDR:
				set_reuseaddr(*(bool*)__optval);
				si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), (*(bool*)__optval ? "true" : "false"));
				break;

			case SO_REUSEPORT:
				set_reuseport(*(bool*)__optval);
				si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), (*(bool*)__optval ? "true" : "false"));
				break;

			case SO_BROADCAST:
				si_udp_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), (*(bool*)__optval ? "true" : "false"));
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
				// this is supported without doing something special because VMA send immediately without buffering
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
				else {
					si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
				}
				break;

			case SO_BINDTODEVICE:
				if (__optval) {
					struct sockaddr_in sockaddr;
					if (__optlen == 0 || ((char*)__optval)[0] == '\0') {
						m_so_bindtodevice_ip = INADDR_ANY;
					} else if (get_ipv4_from_ifname((char*)__optval, &sockaddr)) {
						si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, cannot find if_name", setsockopt_so_opt_to_str(__optname));
						break;
					} else {
						m_so_bindtodevice_ip = sockaddr.sin_addr.s_addr;
					}
					si_udp_logdbg("SOL_SOCKET, %s='%s' (%d.%d.%d.%d)", setsockopt_so_opt_to_str(__optname), (char*)__optval, NIPQUAD(m_so_bindtodevice_ip));

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

					// handle RX side - TODO
				}
				else {
					si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
				}
				break;
			case SO_MAX_PACING_RATE:
				if (__optval) {
					struct vma_rate_limit_t val;

					if (sizeof(struct vma_rate_limit_t) == __optlen) {
						val = *(struct vma_rate_limit_t*)__optval; // value is in Kbits per second
					} else if (sizeof(uint32_t) == __optlen) {
						// value is in bytes per second
						val.rate = BYTE_TO_KB(*(uint32_t*)__optval); // value is in bytes per second
						val.max_burst_sz = 0;
						val.typical_pkt_sz = 0;
					} else {
						si_udp_logdbg("SOL_SOCKET, %s=\"???\" - bad length got %d",
							      setsockopt_so_opt_to_str(__optname), __optlen);
						return -1;
					}

					if (modify_ratelimit(m_p_connected_dst_entry, val) < 0) {
						si_udp_logdbg("error setting setsockopt SO_MAX_PACING_RATE for connected dst_entry %p: %d bytes/second ", m_p_connected_dst_entry, val.rate);

						// Do not fall back to kernel in this case.
						// The kernel's support for packet pacing is of no consequence
						// to the VMA user and may only confuse the calling application.
						return -1;
					}

					size_t dst_entries_not_modified = 0;
					dst_entry_map_t::iterator dst_entry_iter ;
					for (dst_entry_iter = m_dst_entry_map.begin();
					     dst_entry_iter != m_dst_entry_map.end();
					     ++dst_entry_iter) {
						dst_entry* p_dst_entry = dst_entry_iter->second;
						if (modify_ratelimit(p_dst_entry, val) < 0) {
							si_udp_logdbg("error setting setsockopt SO_MAX_PACING_RATE "
								      "for dst_entry %p: %d bytes/second ",
								      p_dst_entry, val.rate);
							dst_entries_not_modified++;
						}
					}
					// It is possible that the user has a setup with some NICs that support
					// packet pacing and some that don't.
					// Setting packet pacing fails only if all NICs do not support it.
					if (m_dst_entry_map.size() &&
					    (dst_entries_not_modified == m_dst_entry_map.size())) {
						return -1;
					}
					return 0;
				}
				else {
					si_udp_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
				}
				break;
			case SO_PRIORITY:
				if (set_sockopt_prio(__optval, __optlen)) {
					return -1;
				}
			break;
			default:
				si_udp_logdbg("SOL_SOCKET, optname=%s (%d)", setsockopt_so_opt_to_str(__optname), __optname);
				supported = false;
				break;
			}
		} // case SOL_SOCKET
		break;

	case IPPROTO_IP:
		{
			switch (__optname) {

			case IP_MULTICAST_IF:
				{
					struct ip_mreqn mreqn;
					memset(&mreqn, 0, sizeof(mreqn));

					if (!__optval || __optlen < sizeof(struct in_addr)) {
						si_udp_loginfo("IPPROTO_IP, %s=\"???\", optlen:%d", setsockopt_ip_opt_to_str(__optname), (int)__optlen);
						break;
					}

					if (__optlen >= sizeof(struct ip_mreqn)) {
						memcpy(&mreqn, __optval, sizeof(struct ip_mreqn));
					} else if (__optlen >= sizeof(struct ip_mreq)) {
						memcpy(&mreqn, __optval, sizeof(struct ip_mreq));
					} else {
						memcpy(&mreqn.imr_address, __optval, sizeof(struct in_addr));
					}

					if (mreqn.imr_ifindex) {
						local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list(mreqn.imr_ifindex);
						if (!lip_offloaded_list.empty()) {
							mreqn.imr_address.s_addr = lip_offloaded_list.front().local_addr;
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
					if (__optlen == sizeof(m_n_mc_ttl))
						n_mc_ttl = *(char*)__optval;
					else if (__optlen == sizeof(int))
						n_mc_ttl = *(int*)__optval;
					else {
						break;
					}
					if (n_mc_ttl == -1) {
						n_mc_ttl = 1;
					}
					if (n_mc_ttl >= 0 && n_mc_ttl <= 255) {
						m_n_mc_ttl = n_mc_ttl;
						header_ttl_updater du(m_n_mc_ttl, true);
						update_header_field(&du);
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
			case IP_ADD_SOURCE_MEMBERSHIP:
			case IP_DROP_SOURCE_MEMBERSHIP:
				{
					if (!m_sock_offload) {
						si_udp_logdbg("VMA Rx Offload is Disabled! calling OS setsockopt() for IPPROTO_IP, %s", setsockopt_ip_opt_to_str(__optname));
						break;
					}

					if (NULL == __optval) {
						si_udp_logdbg("IPPROTO_IP, %s; Bad optval! calling OS setsockopt()", setsockopt_ip_opt_to_str(__optname));
						break;
					}

					// There are 3 types of structs that we can receive, ip_mreq(2 members), ip_mreqn(3 members), ip_mreq_source(3 members)
					// ip_mreq struct type and size depend on command type, let verify all possibilities and continue
					// below with safe logic.

					// NOTE: The ip_mreqn structure is available only since Linux 2.2. For compatibility, the old ip_mreq
					// structure (present since Linux 1.2) is still supported; it differs from ip_mreqn only by not
					// including the imr_ifindex field.
					if (__optlen < sizeof(struct ip_mreq)) {
						si_udp_logdbg("IPPROTO_IP, %s; Bad optlen! calling OS setsockopt() with optlen=%d (required optlen=%d)",
							setsockopt_ip_opt_to_str(__optname), __optlen, sizeof(struct ip_mreq));
						break;
					}
					// IP_ADD_SOURCE_MEMBERSHIP (and DROP) used ip_mreq_source which is same size struct as ip_mreqn,
					// but fields have different meaning
					if (((IP_ADD_SOURCE_MEMBERSHIP == __optname) || (IP_DROP_SOURCE_MEMBERSHIP == __optname)) &&
						    (__optlen < sizeof(struct ip_mreq_source))) {
						si_udp_logdbg("IPPROTO_IP, %s; Bad optlen! calling OS setsockopt() with optlen=%d (required optlen=%d)",
							setsockopt_ip_opt_to_str(__optname), __optlen, sizeof(struct ip_mreq_source));
						break;
					}

					// Use  local variable for easy access
					in_addr_t mc_grp = ((struct ip_mreq*)__optval)->imr_multiaddr.s_addr;
				 	in_addr_t mc_if  = ((struct ip_mreq*)__optval)->imr_interface.s_addr;

					// In case interface address is undefined[INADDR_ANY] we need to find the ip address to use
					struct ip_mreq_source mreqprm = {{mc_grp}, {mc_if}, {0}};
					if ((IP_ADD_MEMBERSHIP == __optname) || (IP_DROP_MEMBERSHIP == __optname)) {
						if (__optlen >= sizeof(struct ip_mreqn)) {
							struct ip_mreqn* p_mreqn = (struct ip_mreqn*)__optval;
							if (p_mreqn->imr_ifindex) {
								local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list(p_mreqn->imr_ifindex);
								if (!lip_offloaded_list.empty()) {
									mreqprm.imr_interface.s_addr = lip_offloaded_list.front().local_addr;
								} else {
									struct sockaddr_in src_addr;
									if (get_ipv4_from_ifindex(p_mreqn->imr_ifindex, &src_addr) == 0) {
										mreqprm.imr_interface.s_addr = src_addr.sin_addr.s_addr;
									} else {
										si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, can't get address of interface index %d ",
												setsockopt_ip_opt_to_str(__optname), p_mreqn->imr_ifindex);
										break;
									}
								}
							}
						}
					}
					else {
						// Save and use the user provided source address filter in case of IP_ADD_SOURCE_MEMBERSHIP or IP_DROP_SOURCE_MEMBERSHIP
						mreqprm.imr_sourceaddr.s_addr = ((struct ip_mreq_source*)__optval)->imr_sourceaddr.s_addr;
					}

					// Update interface IP in case it was changed above
					mc_if  = mreqprm.imr_interface.s_addr;

					if (!IN_MULTICAST_N(mc_grp)) {
						si_udp_logdbg("setsockopt(%s) will be passed to OS for handling, IP %d.%d.%d.%d is not MC ",
								setsockopt_ip_opt_to_str(__optname),  NIPQUAD(mc_grp));
						break;
					}

					// Find local interface IP address
					if (INADDR_ANY == mc_if) {
						in_addr_t dst_ip	= mc_grp;
						in_addr_t src_ip	= 0;

						if ((!m_bound.is_anyaddr()) && (!m_bound.is_mc())) {
							src_ip = m_bound.get_in_addr();
						} else if (m_so_bindtodevice_ip) {
							src_ip = m_so_bindtodevice_ip;
						}
						// Find local if for this MC ADD/DROP
						route_result res;
						g_p_route_table_mgr->route_resolve(route_rule_table_key(dst_ip, src_ip, m_tos), res);
						mc_if = res.p_src;
						si_udp_logdbg("IPPROTO_IP, %s=%d.%d.%d.%d, mc_if:INADDR_ANY (resolved to: %d.%d.%d.%d)", setsockopt_ip_opt_to_str(__optname), NIPQUAD(mc_grp), NIPQUAD(mc_if));
					}
					else {
						si_udp_logdbg("IPPROTO_IP, %s=%d.%d.%d.%d, mc_if:%d.%d.%d.%d mc_src:%d.%d.%d.%d", setsockopt_ip_opt_to_str(__optname), NIPQUAD(mc_grp), NIPQUAD(mc_if), NIPQUAD(mreqprm.imr_sourceaddr.s_addr));
					}

					// Add multicast group membership
					if (mc_change_membership_start_helper(mc_grp, __optname)) {
						return -1;
					}

					bool goto_os = false;
					// Check MC rules for not offloading
					sock_addr tmp_grp_addr(AF_INET, mc_grp, m_bound.get_in_port());
					mc_pending_pram mcpram = {mreqprm.imr_multiaddr, mreqprm.imr_interface, mreqprm.imr_sourceaddr, __optname};

					if (TRANS_OS == __vma_match_udp_receiver(TRANS_VMA, safe_mce_sys().app_id, tmp_grp_addr.get_p_sa(), tmp_grp_addr.get_socklen())) {
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
					else if (INPORT_ANY == m_bound.get_in_port()) {
						// Delay attaching to this MC group until we have bound UDP port
						ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
						if (ret) return ret;
						mc_change_pending_mreq(&mcpram);
					}
					// Handle attach to this MC group now
					else if (mc_change_membership( &mcpram )) {
						// Opps, failed in attaching??? call orig setsockopt()
						goto_os = true;
					}

					if (goto_os) {
						ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
						if (ret) return ret;
					}

					mc_change_membership_end_helper(mc_grp, __optname, mreqprm.imr_sourceaddr.s_addr);
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
			case IP_TOS:
				{
					int val;
					if (__optlen == sizeof(int)) {
						val = *(int *)__optval;
					} else if (__optlen == sizeof(uint8_t)) {
						val = *(uint8_t *)__optval;
					} else {
						break;
					}
					m_tos =(uint8_t)val;
					header_tos_updater du(m_tos);
					update_header_field(&du);
					// lists.openwall.net/netdev/2009/12/21/59
					int new_prio = ip_tos2prio[IPTOS_TOS(m_tos) >> 1];
					set_sockopt_prio(&new_prio, sizeof(new_prio));
				}
				break;
			default:
				{
					si_udp_logdbg("IPPROTO_IP, optname=%s (%d)", setsockopt_ip_opt_to_str(__optname), __optname);
					supported = false;
				}
				break;
			}
		} // case IPPROTO_IP
		break;

	case IPPROTO_UDP:
		switch (__optname) {
		case UDP_MAP_ADD:
		{
			if (! __optval) {
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
				if (m_port_map.empty()) {
					m_sockopt_mapped = true;
					// set full versus partial RX UDP handling due to updates in m_socket_mapped
					set_rx_packet_processor();
				}
				si_udp_logdbg("found UDP_MAP_ADD socket fd for port %d. fd is %d", ntohs(port_socket.port), port_socket.fd);
				m_port_map.push_back(port_socket);
			}
			m_port_map_lock.unlock();
			return 0;
		}
		case UDP_MAP_REMOVE:
		{
			if (! __optval) {
				si_udp_loginfo("UDP_MAP_REMOVE __optval = NULL");
				break;
			}
			in_port_t port = *(in_port_t *)__optval;
			si_udp_logdbg("stopping de-muxing packets to port %d", ntohs(port));
			m_port_map_lock.lock();
			std::vector<struct port_socket_t>::iterator iter = std::find(m_port_map.begin(), m_port_map.end(), port);
			if (iter != m_port_map.end()) {
				m_port_map.erase(iter);
				if (m_port_map.empty()) {
					m_sockopt_mapped = false;
					// set full versus partial RX UDP handling due to updates in m_socket_mapped
					set_rx_packet_processor();
				}
			}
			m_port_map_lock.unlock();
			return 0;
		}
		default:
			si_udp_logdbg("IPPROTO_UDP, optname=%s (%d)", setsockopt_ip_opt_to_str(__optname), __optname);
			supported = false;
			break;
		} // case IPPROTO_UDP
		break;

	default:
		{
			si_udp_logdbg("level = %d, optname = %d", __level, __optname);
			supported = false;
		}
		break;
	}
	return setsockopt_kernel(__level, __optname, __optval, __optlen, supported, false);
}

int sockinfo_udp::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
	si_udp_logfunc("level=%d, optname=%d", __level, __optname);

	int ret = orig_os_api.getsockopt(m_fd, __level, __optname, __optval, __optlen);

	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit))
		return ret;

	if (0 == sockinfo::getsockopt(__level, __optname, __optval, __optlen)) {
		return 0;
	}

	auto_unlocker lock_tx(m_lock_snd);
	auto_unlocker lock_rx(m_lock_rcv);

	bool supported = true;
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

			case SO_MAX_PACING_RATE:
				ret = sockinfo::getsockopt(__level, __optname, __optval, __optlen);
				break;

			default:
				si_udp_logdbg("SOL_SOCKET, optname=%d", __optname);
				supported = false;
				break;
			}

		} // case SOL_SOCKET
		break;

	default:
		{
			si_udp_logdbg("level = %d, optname = %d", __level, __optname);
			supported = false;
		}
		break;
	}

	if (! supported) {
		char buf[256];
		snprintf(buf, sizeof(buf), "unimplemented getsockopt __level=%#x, __optname=%#x, __optlen=%d", (unsigned)__level, (unsigned)__optname, __optlen ? *__optlen : 0);
		buf[ sizeof(buf)-1 ] = '\0';

		VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
		int rc = handle_exception_flow();
		switch (rc) {
		case -1:
			return rc;
		case -2:
			vma_throw_object_with_msg(vma_unsupported_api, buf);
		}
	}

	return ret;
}

// Drop rx ready packets from head of queue
void sockinfo_udp::rx_ready_byte_count_limit_update(size_t n_rx_ready_bytes_limit_new)
{
	si_udp_logfunc("new limit: %d Bytes (old: %d Bytes, min value %d Bytes)", n_rx_ready_bytes_limit_new, m_p_socket_stats->n_rx_ready_byte_limit, m_n_sysvar_rx_ready_byte_min_limit);
	if (n_rx_ready_bytes_limit_new > 0 && n_rx_ready_bytes_limit_new < m_n_sysvar_rx_ready_byte_min_limit)
		n_rx_ready_bytes_limit_new = m_n_sysvar_rx_ready_byte_min_limit;
	m_p_socket_stats->n_rx_ready_byte_limit = n_rx_ready_bytes_limit_new;

	m_lock_rcv.lock();
	while (m_p_socket_stats->n_rx_ready_byte_count > m_p_socket_stats->n_rx_ready_byte_limit) {
		if (m_n_rx_pkt_ready_list_count) {
			mem_buf_desc_t* p_rx_pkt_desc = m_rx_pkt_ready_list.get_and_pop_front();
			m_n_rx_pkt_ready_list_count--;
			m_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
			m_p_socket_stats->n_rx_ready_pkt_count--;
			m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;

			reuse_buffer(p_rx_pkt_desc);
			return_reuse_buffers_postponed();
		}
		else
			break;
	}
	m_lock_rcv.unlock();

	return;
}

ssize_t sockinfo_udp::rx(const rx_call_t call_type, iovec* p_iov,ssize_t sz_iov, 
                     int* p_flags, sockaddr *__from ,socklen_t *__fromlen, struct msghdr *__msg)
{
	int errno_tmp = errno;
	int ret;
	uint64_t poll_sn = 0;
	int out_flags = 0;
	int in_flags = *p_flags;

	si_udp_logfunc("");
	
	m_lock_rcv.lock();

	if (unlikely(m_state == SOCKINFO_CLOSED)) {
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

	return_reuse_buffers_postponed();

	// Drop lock to not starve other threads
	m_lock_rcv.unlock();

	// Poll socket for OS ready packets... (at a ratio of the offloaded sockets as defined in m_n_sysvar_rx_udp_poll_os_ratio)
	if ((m_n_sysvar_rx_udp_poll_os_ratio > 0) && (m_rx_udp_poll_os_ratio_counter >= m_n_sysvar_rx_udp_poll_os_ratio)) {
		ret = poll_os();
		if (ret == -1) {
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_rcv.lock();
			goto out;
		}
		if (ret == 1) {
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_rcv.lock();
			goto os;
		}
	}

	// First check if we have a packet in the ready list
	if ((m_n_rx_pkt_ready_list_count > 0 && m_n_sysvar_rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED)
	    || is_readable(&poll_sn)) {
		/* coverity[double_lock] TODO: RM#1049980 */
		m_lock_rcv.lock();
		m_rx_udp_poll_os_ratio_counter++;
		if (m_n_rx_pkt_ready_list_count > 0) {
			// Found a ready packet in the list
			if (__msg) handle_cmsg(__msg);
			ret = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, in_flags, &out_flags);
			goto out;
		}
		/* coverity[double_unlock] TODO: RM#1049980 */
		m_lock_rcv.unlock();
	}

wait:
	/*
	 * We (probably) do not have a ready packet.
	 * Wait for RX to become ready.
	 */
	rx_wait_ret = rx_wait(m_b_blocking && !(in_flags & MSG_DONTWAIT));

	m_lock_rcv.lock();

	if (likely(rx_wait_ret == 0)) {
		// Got 0, means we might have a ready packet
		if (m_n_rx_pkt_ready_list_count > 0) {
			if (__msg) handle_cmsg(__msg);
			ret = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, in_flags, &out_flags);
			goto out;
		} else {
			m_lock_rcv.unlock();
			goto wait;
		}
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
	if (in_flags & MSG_VMA_ZCOPY_FORCE) {
		// Enable the next non-blocked read to check the OS 
		m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
		errno = EIO;
		ret = -1;
		goto out;
	}

#ifdef VMA_TIME_MEASURE
	INC_GO_TO_OS_RX_COUNT;
#endif

	in_flags &= ~MSG_VMA_ZCOPY;
	ret = socket_fd_api::rx_os(call_type, p_iov, sz_iov, in_flags, __from, __fromlen, __msg);
	*p_flags = in_flags;
	save_stats_rx_os(ret);
	if (ret > 0) {
		// This will cause the next non-blocked read to check the OS again.
		// We do this only after a successful read.
		m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
	}

out:
	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_rcv.unlock();

	if (__msg)
		__msg->msg_flags |= out_flags & MSG_TRUNC;

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
		/* Restore errno on function entry in case success */
		errno = errno_tmp;

		si_udp_logfunc("returning with: %d", ret);
	}
	return ret;
}

void sockinfo_udp::handle_ip_pktinfo(struct cmsg_state * cm_state)
{
	struct in_pktinfo in_pktinfo;
	mem_buf_desc_t* p_desc = m_rx_pkt_ready_list.front();

	rx_net_device_map_t::iterator iter = m_rx_nd_map.find(p_desc->rx.udp.local_if);
	if (iter == m_rx_nd_map.end()) {
		si_udp_logerr("could not find net device for ip %d.%d.%d.%d", NIPQUAD(p_desc->rx.udp.local_if));
		return;
	}
	in_pktinfo.ipi_ifindex = iter->second.p_ndv->get_if_idx();
	in_pktinfo.ipi_addr = p_desc->rx.dst.sin_addr;
	in_pktinfo.ipi_spec_dst.s_addr = p_desc->rx.udp.local_if;
	insert_cmsg(cm_state, IPPROTO_IP, IP_PKTINFO, &in_pktinfo, sizeof(struct in_pktinfo));
}

// This function is relevant only for non-blocking socket
void sockinfo_udp::set_immediate_os_sample()
{
	m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
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

		if (m_n_sysvar_rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) {
			si_udp_logfunc("=> true (ready count = %d packets / %d bytes)", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
			return true;
		}
		else {
			tscval_t tsc_now = TSCVAL_INITIALIZER;
			gettimeoftsc(&tsc_now);
			if (tsc_now - g_si_tscv_last_poll < m_n_sysvar_rx_delta_tsc_between_cq_polls) {
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
			if (rx_ring_iter->second->refcnt <= 0)
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

ssize_t sockinfo_udp::tx(const tx_call_t call_type, const iovec* p_iov, const ssize_t sz_iov,
		     const int __flags /*=0*/, const struct sockaddr *__dst /*=NULL*/, const socklen_t __dstlen /*=0*/)
{
	int errno_tmp = errno;
	int ret = 0;
	bool is_dummy = IS_DUMMY_PACKET(__flags);
	dst_entry* p_dst_entry = m_p_connected_dst_entry; // Default for connected() socket but we'll update it on a specific sendTO(__to) call

	si_udp_logfunc("");

	m_lock_snd.lock();

	save_stats_threadid_tx();

	/* Let allow OS to process all invalid scenarios to avoid any
	 * inconsistencies in setting errno values.
	 * Note: The field size sets a theoretical limit of 65,535 bytes
	 * (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by
	 * the underlying IPv4 protocol, is 65,507 bytes
	 * (65,535 - 8 byte UDP header - 20 byte IP header).
	 */
	if (unlikely((m_state == SOCKINFO_CLOSED) || (g_b_exit) ||
			(NULL == p_iov) ||
			(0 >= sz_iov) ||
			(NULL == p_iov[0].iov_base) ||
			(65507 < p_iov[0].iov_len))) {
		goto tx_packet_to_os;
	}

	if (unlikely(__flags & MSG_OOB)) {
		si_udp_logdbg("MSG_OOB not supported in UDP (tx-ing to os)");
		goto tx_packet_to_os;
	}
#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_START;
#endif
	if (__dst != NULL) {
		if (unlikely(__dstlen < sizeof(struct sockaddr_in))) {
			si_udp_logdbg("going to os, dstlen < sizeof(struct sockaddr_in), dstlen = %d", __dstlen);
			goto tx_packet_to_os;
		}
		if (unlikely(get_sa_family(__dst) != AF_INET)) {
			si_udp_logdbg("to->sin_family != AF_INET (tx-ing to os)");
			goto tx_packet_to_os;
		}

		sock_addr dst((struct sockaddr*)__dst);

		if (dst == m_last_sock_addr && m_p_last_dst_entry) {
			p_dst_entry = m_p_last_dst_entry;
		} else {

			// Find dst_entry in map (create one if needed)
			dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.find(dst);

			if (likely(dst_entry_iter != m_dst_entry_map.end())) {

				// Fast path
				// We found our target dst_entry object
				m_p_last_dst_entry = p_dst_entry = dst_entry_iter->second;
				m_last_sock_addr = dst;
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
					socket_data data = { m_fd, m_n_mc_ttl, m_tos, m_pcp };
					p_dst_entry = new dst_entry_udp_mc(
							dst.get_in_addr(),
							dst.get_in_port(),
							src_port,
							m_mc_tx_if ? m_mc_tx_if : m_bound.get_in_addr(),
							m_b_mc_tx_loop,
							data,
							m_ring_alloc_log_tx);
				}
				else {
					socket_data data = { m_fd, m_n_uc_ttl, m_tos, m_pcp };
					p_dst_entry = new dst_entry_udp(
							dst.get_in_addr(),
							dst.get_in_port(),
							src_port,
							data,
							m_ring_alloc_log_tx);
				}
				BULLSEYE_EXCLUDE_BLOCK_START
				if (!p_dst_entry) {
					si_udp_logerr("Failed to create dst_entry(dst_ip:%s, dst_port:%d, src_port:%d)", dst.to_str_in_addr(), dst.to_str_in_port(), ntohs(src_port));
					goto tx_packet_to_os;
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
			*/
			}
		}
	} else if (unlikely(!p_dst_entry)) {
		si_udp_logdbg("going to os, __dst = %p, m_p_connected_dst_entry = %p", __dst, m_p_connected_dst_entry);
		goto tx_packet_to_os;
	}

	{
#ifdef DEFINED_TSO
		vma_send_attr attr = {(vma_wr_tx_packet_attr)0, 0};
		bool b_blocking = m_b_blocking;
		if (unlikely(__flags & MSG_DONTWAIT))
			b_blocking = false;

		attr.flags = (vma_wr_tx_packet_attr)((b_blocking * VMA_TX_PACKET_BLOCK) | (is_dummy * VMA_TX_PACKET_DUMMY));
		if (likely(p_dst_entry->is_valid())) {
			// All set for fast path packet sending - this is our best performance flow
			ret = p_dst_entry->fast_send((iovec*)p_iov, sz_iov, attr);
		}
		else {
			// updates the dst_entry internal information and packet headers
			ret = p_dst_entry->slow_send(p_iov, sz_iov, attr, m_so_ratelimit, __flags, this, call_type);
		}
#else
		bool b_blocking = m_b_blocking;
		if (unlikely(__flags & MSG_DONTWAIT))
			b_blocking = false;

		if (likely(p_dst_entry->is_valid())) {
			// All set for fast path packet sending - this is our best performance flow
			ret = p_dst_entry->fast_send((iovec*)p_iov, sz_iov, is_dummy, b_blocking);
		}
		else {
			// updates the dst_entry internal information and packet headers
			ret = p_dst_entry->slow_send(p_iov, sz_iov, is_dummy, m_so_ratelimit, b_blocking, false, __flags, this, call_type);
		}
#endif /* DEFINED_TSO */

		if (unlikely(p_dst_entry->try_migrate_ring(m_lock_snd))) {
			m_p_socket_stats->counters.n_tx_migrations++;
		}

		// TODO ALEXR - still need to handle "is_dropped" in send path
		// For now we removed the support of this feature (AlexV & AlexR)
	}

	if (likely(p_dst_entry->is_offloaded())) {

		// MNY: Problematic in cases where packet was dropped because no tx buffers were available..
		// Yet we need to add this code to avoid deadlocks in case of EPOLLOUT ET.
		NOTIFY_ON_EVENTS(this, EPOLLOUT);

		save_stats_tx_offload(ret, is_dummy);

#ifdef VMA_TIME_MEASURE
		TAKE_T_TX_END;
#endif
		m_lock_snd.unlock();

		/* Restore errno on function entry in case success */
		if (ret >= 0) {
			errno = errno_tmp;
		}

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

int sockinfo_udp::rx_verify_available_data()
{
	int ret;

	// Don't poll cq if offloaded data is ready
	if (!m_rx_pkt_ready_list.empty()) {
		auto_unlocker locker(m_lock_rcv);
		if (!m_rx_pkt_ready_list.empty()) {
			return m_rx_pkt_ready_list.front()->rx.sz_payload;
		}
	}

	ret = rx_wait(false);

	if (ret == 0) {
		// Got 0, means we might have a ready packet
		auto_unlocker locker(m_lock_rcv);
		if (!m_rx_pkt_ready_list.empty()) {
			ret = m_rx_pkt_ready_list.front()->rx.sz_payload;
		}
	}
	else if (ret == 1) {
		// Got 1, means we have a ready packet in OS
		uint64_t pending_data = 0;
		ret = orig_os_api.ioctl(m_fd, FIONREAD, &pending_data);
		if (ret >= 0) {
			// This will cause the next non-blocked read to check the OS again.
			// We do this only after a successful read.
			m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;
			ret = pending_data;
		}
	} else if (errno == EAGAIN) {
		errno = 0;
		ret = 0;
	}

	return ret;
}

/**
 * sockinfo_udp::inspect_uc_packet inspects the input packet for basic rules,
 * common for all cases. Its applicable for UC case as well.
 */
inline bool sockinfo_udp::inspect_uc_packet(mem_buf_desc_t* p_desc)
{
	// Check that sockinfo is bound to the packets dest port
	// This protects the case where a socket is closed and a new one is rapidly opened
	// receiving the same socket id.
	// In this case packets arriving for the old sockets should be dropped.
	// This distinction assumes that the OS guarantees the old and new sockets to receive different
	// port numbers from bind().
	// If the user requests to bind the new socket to the same port number as the old one it will be
	// impossible to identify packets designated for the old socket in this way.
	if (unlikely(p_desc->rx.dst.sin_port != m_bound.get_in_port())) {
		si_udp_logfunc("rx packet discarded - not socket's bound port (pkt: %d, sock:%s)",
			   ntohs(p_desc->rx.dst.sin_port), m_bound.to_str_in_port());
		return false;
	}

	// Check if sockinfo rx byte quato reached - then disregard this packet
	if (unlikely(m_p_socket_stats->n_rx_ready_byte_count >= m_p_socket_stats->n_rx_ready_byte_limit)) {
		si_udp_logfunc("rx packet discarded - socket limit reached (%d bytes)", m_p_socket_stats->n_rx_ready_byte_limit);
		m_p_socket_stats->counters.n_rx_ready_byte_drop += p_desc->rx.sz_payload;
		m_p_socket_stats->counters.n_rx_ready_pkt_drop++;
		return false;
	}

	if (unlikely(m_state == SOCKINFO_CLOSED) || unlikely(g_b_exit)) {
		si_udp_logfunc("rx packet discarded - fd closed");
		return false;
	}
	return true;
}

/**
 *	Inspects UDP packets in case socket was connected
 *
 */
inline bool sockinfo_udp::inspect_connected(mem_buf_desc_t* p_desc)
{
	if ((m_connected.get_in_port() != INPORT_ANY) && (m_connected.get_in_addr() != INADDR_ANY)) {
		if (unlikely(m_connected.get_in_port() != p_desc->rx.src.sin_port)) {
			si_udp_logfunc("rx packet discarded - not socket's connected port (pkt: %d, sock:%s)",
				   ntohs(p_desc->rx.src.sin_port), m_connected.to_str_in_port());
			return false;
		}

		if (unlikely(m_connected.get_in_addr() != p_desc->rx.src.sin_addr.s_addr)) {
			si_udp_logfunc("rx packet discarded - not socket's connected port (pkt: [%d:%d:%d:%d], sock:[%s])",
				   NIPQUAD(p_desc->rx.src.sin_addr.s_addr), m_connected.to_str_in_addr());
			return false;
		}
	}
	return true;
}

/**
 *	Inspects multicast packets
 *
 */
inline bool sockinfo_udp::inspect_mc_packet(mem_buf_desc_t* p_desc)
{
	// if loopback is disabled, discard loopback packets.
	// in linux, loopback control (set by setsockopt) is done in TX flow.
	// since we currently can't control it in TX, we behave like windows, which filter on RX
	if (unlikely(!m_b_mc_tx_loop && p_desc->rx.udp.local_if == p_desc->rx.src.sin_addr.s_addr)) {
		si_udp_logfunc("rx packet discarded - loopback is disabled (pkt: [%d:%d:%d:%d], sock:%s)",
			NIPQUAD(p_desc->rx.src.sin_addr.s_addr), m_bound.to_str_in_addr());
		return false;
	}
	if (m_mc_num_grp_with_src_filter) {
		in_addr_t mc_grp = p_desc->rx.dst.sin_addr.s_addr;
		if (IN_MULTICAST_N(mc_grp)) {
			in_addr_t mc_src = p_desc->rx.src.sin_addr.s_addr;

			if ((m_mc_memberships_map.find(mc_grp) == m_mc_memberships_map.end()) ||
				((0 < m_mc_memberships_map[mc_grp].size()) &&
				(m_mc_memberships_map[mc_grp].find(mc_src) == m_mc_memberships_map[mc_grp].end()))) {
				si_udp_logfunc("rx packet discarded - multicast source mismatch");
				return false;
			}
		}
	}
	return true;
}

/**
 *	Performs inspection by registered user callback
 *
 */
inline vma_recv_callback_retval_t sockinfo_udp::inspect_by_user_cb(mem_buf_desc_t* p_desc)
{
	vma_info_t pkt_info;

	pkt_info.struct_sz = sizeof(pkt_info);
	pkt_info.packet_id = (void*)p_desc;
	pkt_info.src = &p_desc->rx.src;
	pkt_info.dst = &p_desc->rx.dst;
	pkt_info.socket_ready_queue_pkt_count = m_p_socket_stats->n_rx_ready_pkt_count;
	pkt_info.socket_ready_queue_byte_count = m_p_socket_stats->n_rx_ready_byte_count;

	if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
		pkt_info.hw_timestamp = p_desc->rx.timestamps.hw;
	}
	if (p_desc->rx.timestamps.sw.tv_sec) {
		pkt_info.sw_timestamp = p_desc->rx.timestamps.sw;
	}

	// fill io vector array with data buffer pointers
	iovec iov[p_desc->rx.n_frags];
	int nr_frags = 0;

	for (mem_buf_desc_t *tmp = p_desc; tmp; tmp = tmp->p_next_desc) {
		iov[nr_frags++] = tmp->rx.frag;
	}

	// call user callback
	return m_rx_callback(m_fd, nr_frags, iov, &pkt_info, m_rx_callback_context);
}

/* Update vma_completion with
 * VMA_SOCKETXTREME_PACKET related data
 */
inline void sockinfo_udp::fill_completion(mem_buf_desc_t* p_desc)
{
	struct vma_completion_t *completion;

	/* Try to process socketxtreme_poll() completion directly */
	m_socketxtreme.completion = m_p_rx_ring->get_comp();

	if (m_socketxtreme.completion) {
		completion = m_socketxtreme.completion;
	} else {
		completion = &m_socketxtreme.ec.completion;
	}

	completion->packet.num_bufs = p_desc->rx.n_frags;
	completion->packet.total_len = 0;
	completion->src = p_desc->rx.src;

	if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
		completion->packet.hw_timestamp = p_desc->rx.timestamps.hw;
	}

	for(mem_buf_desc_t *tmp_p = p_desc; tmp_p; tmp_p = tmp_p->p_next_desc) {
		completion->packet.total_len        += tmp_p->rx.sz_payload;
		completion->packet.buff_lst          = (struct vma_buff_t*)tmp_p;
		completion->packet.buff_lst->next    = (struct vma_buff_t*)tmp_p->p_next_desc;
		completion->packet.buff_lst->payload = p_desc->rx.frag.iov_base;
		completion->packet.buff_lst->len     = p_desc->rx.frag.iov_len;
	}

	NOTIFY_ON_EVENTS(this, VMA_SOCKETXTREME_PACKET);

	save_stats_rx_offload(completion->packet.total_len);
	m_socketxtreme.completion = NULL;
	m_socketxtreme.last_buff_lst = NULL;
}

/**
 *	Performs packet processing for NON-SOCKETXTREME cases and store packet
 *	in ready queue.
 */
inline void sockinfo_udp::update_ready(mem_buf_desc_t* p_desc, void* pv_fd_ready_array, vma_recv_callback_retval_t cb_ret)
{
	// In ZERO COPY case we let the user's application manage the ready queue
	if (cb_ret != VMA_PACKET_HOLD) {
		m_lock_rcv.lock();
		// Save rx packet info in our ready list
		m_rx_pkt_ready_list.push_back(p_desc);
		m_n_rx_pkt_ready_list_count++;
		m_rx_ready_byte_count += p_desc->rx.sz_payload;
		m_p_socket_stats->n_rx_ready_pkt_count++;
		m_p_socket_stats->n_rx_ready_byte_count += p_desc->rx.sz_payload;
		m_p_socket_stats->counters.n_rx_ready_pkt_max = max((uint32_t)m_p_socket_stats->n_rx_ready_pkt_count, 
								    m_p_socket_stats->counters.n_rx_ready_pkt_max);
		m_p_socket_stats->counters.n_rx_ready_byte_max = max((uint32_t)m_p_socket_stats->n_rx_ready_byte_count,
								     m_p_socket_stats->counters.n_rx_ready_byte_max);
		do_wakeup();
		m_lock_rcv.unlock();
	} else {
		m_p_socket_stats->n_rx_zcopy_pkt_count++;
	}

	NOTIFY_ON_EVENTS(this, EPOLLIN);

	// Add this fd to the ready fd list
	/*
	 * Note: No issue is expected in case socketxtreme_poll() usage because 'pv_fd_ready_array' is null
	 * in such case and as a result update_fd_array() call means nothing
	 */
	io_mux_call::update_fd_array((fd_array_t*)pv_fd_ready_array, m_fd);

	si_udp_logfunc("rx ready count = %d packets / %d bytes", m_n_rx_pkt_ready_list_count, m_p_socket_stats->n_rx_ready_byte_count);
}

/**
 *	Performs full inspection and processing for generic UDP
 *	It will be bypassing some inspections if appropriate flags were
 *	not set.
 */
inline bool sockinfo_udp::rx_process_udp_packet_full(mem_buf_desc_t* p_desc, void* pv_fd_ready_array)
{
	if (!inspect_uc_packet(p_desc))
		return false;

	if (m_is_connected && !inspect_connected(p_desc))
		return false;

	if (m_multicast && !inspect_mc_packet(p_desc))
		return false;

	if (m_sockopt_mapped) {
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
				if (m_port_map_index)
					m_port_map_index--;
				m_port_map_lock.unlock();
				continue;
			}
			m_port_map_lock.unlock();
			p_desc->rx.dst.sin_port = new_port;
			return ((sockinfo_udp*)sock_api)->rx_process_udp_packet_full(p_desc, pv_fd_ready_array);
		}
	}

	process_timestamps(p_desc);

	vma_recv_callback_retval_t cb_ret = VMA_PACKET_RECV;
	if (m_rx_callback && ((cb_ret = inspect_by_user_cb(p_desc)) == VMA_PACKET_DROP)) {
		si_udp_logfunc("rx packet discarded - by user callback");
		return false;
	}
	// Yes, we want to keep this packet!
	// And we must increment ref_counter before pushing this packet into the ready queue
	//  to prevent race condition with the 'if( (--ref_count) <= 0)' in ib_comm_mgr
	p_desc->inc_ref_count();

	if (p_desc->rx.socketxtreme_polled) {
		fill_completion(p_desc);
		p_desc->rx.socketxtreme_polled = false;
	} else {
		update_ready(p_desc, pv_fd_ready_array, cb_ret);
	}
	return true;
}

/**
 *	Performs inspection and processing for simple UC UDP case
 *	bypassing all other inspections
 */
inline bool sockinfo_udp::rx_process_udp_packet_partial(mem_buf_desc_t* p_desc, void* pv_fd_ready_array)
{
	if (!inspect_uc_packet(p_desc))
		return false;

	process_timestamps(p_desc);

	vma_recv_callback_retval_t cb_ret = VMA_PACKET_RECV;
	if (m_rx_callback && ((cb_ret = inspect_by_user_cb(p_desc)) == VMA_PACKET_DROP)) {
		si_udp_logfunc("rx packet discarded - by user callback");
		return false;
	}
	// Yes, we want to keep this packet!
	// And we must increment ref_counter before pushing this packet into the ready queue
	//  to prevent race condition with the 'if( (--ref_count) <= 0)' in ib_comm_mgr
	p_desc->inc_ref_count();

	if (p_desc->rx.socketxtreme_polled) {
		fill_completion(p_desc);
		p_desc->rx.socketxtreme_polled = false;
	} else {
		update_ready(p_desc, pv_fd_ready_array, cb_ret);
	}
	return true;
}

/**
 *	set packet inspector and processor
 */
inline void sockinfo_udp::set_rx_packet_processor(void)
{
	si_udp_logdbg("is_connected: %d mapped: %d multicast: %d",
		      m_is_connected, m_sockopt_mapped, m_multicast);
	// Select partial or full packet processing.
	// Full packet processing is selected in case of:
	// - connect() was done on the UDP socket
	//   In this case the UDP 3-tuple is not sufficient for the packet matching.
	// - In the case that socket mapping is enabled extra processing is required
	// - Multicast packets
	// For simple UC traffic reduced packet processing is selected.
	if (m_is_connected || m_sockopt_mapped || m_multicast) {
		m_rx_packet_processor = &sockinfo_udp::rx_process_udp_packet_full;
	} else {
		m_rx_packet_processor = &sockinfo_udp::rx_process_udp_packet_partial;
	}
}

void sockinfo_udp::rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_udp_logdbg("");
	sockinfo::rx_add_ring_cb(flow_key, p_ring, is_migration);

	//Now that we got at least 1 CQ attached enable the skip os mechanism.
	m_rx_udp_poll_os_ratio_counter = m_n_sysvar_rx_udp_poll_os_ratio;

	// Now that we got at least 1 CQ attached start polling the CQs
	if (m_b_blocking) {
        	m_loops_to_go = m_n_sysvar_rx_poll_num;
	}
	else {
		m_loops_to_go = 1; // Force single CQ poll in case of non-blocking socket
	}
}

void sockinfo_udp::rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_udp_logdbg("");

	sockinfo::rx_del_ring_cb(flow_key, p_ring, is_migration);

	// If no more CQ's are attached on this socket, return CQ polling loops ot init state
	if (m_rx_ring_map.size() <= 0) {
		if (m_b_blocking) {
			m_loops_to_go = safe_mce_sys().rx_poll_num_init;
		}
		else {
			m_loops_to_go = 1;
		}
	}
}

void sockinfo_udp::set_blocking(bool is_blocked)
{
	sockinfo::set_blocking(is_blocked);

	if (m_b_blocking) {
		// Set the high CQ polling RX_POLL value 
		// depending on where we have mapped offloaded MC gorups
		if (m_rx_ring_map.size() > 0)
			m_loops_to_go = m_n_sysvar_rx_poll_num;
		else
			m_loops_to_go = safe_mce_sys().rx_poll_num_init;
	}
	else {
		// Force single CQ poll in case of non-blocking socket
		m_loops_to_go = 1;
	}
}

void sockinfo_udp::handle_pending_mreq()
{
	si_udp_logdbg("Attaching to pending multicast groups");
	mc_pram_list_t::iterator mreq_iter, mreq_iter_temp;
	for (mreq_iter = m_pending_mreqs.begin(); mreq_iter != m_pending_mreqs.end();) {
		if (m_sock_offload) {
			mc_change_membership(&(*mreq_iter));
		}
		mreq_iter_temp = mreq_iter;
		++mreq_iter;
		m_pending_mreqs.erase(mreq_iter_temp);
	}
}

int sockinfo_udp::mc_change_pending_mreq(const mc_pending_pram *p_mc_pram)
{
	si_udp_logdbg("setsockopt(%s) will be pending until bound to UDP port", setsockopt_ip_opt_to_str(p_mc_pram->optname));

	mc_pram_list_t::iterator mc_pram_iter, mreq_iter_temp;
	switch (p_mc_pram->optname) {
	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP:
		m_pending_mreqs.push_back(*p_mc_pram);
		break;
	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
		for (mc_pram_iter = m_pending_mreqs.begin(); mc_pram_iter != m_pending_mreqs.end();) {
			if ((mc_pram_iter->imr_multiaddr.s_addr == p_mc_pram->imr_multiaddr.s_addr) &&
				((IP_DROP_MEMBERSHIP == p_mc_pram->optname) || // In case of a IP_DROP_SOURCE_MEMBERSHIP we should check source address too
				 (mc_pram_iter->imr_sourceaddr.s_addr == p_mc_pram->imr_sourceaddr.s_addr))) {
				 // We found the group, erase it
				mreq_iter_temp = mc_pram_iter;
				++mc_pram_iter;
				m_pending_mreqs.erase(mreq_iter_temp);
			} else {
				++mc_pram_iter;
			}
		}
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) illegal", setsockopt_ip_opt_to_str(p_mc_pram->optname));
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
			&&  m_mc_memberships_map.size() >= (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_membership()) {
			errno = ENOBUFS;
			return -1;
		}
		break;
	case IP_ADD_SOURCE_MEMBERSHIP:
		if (m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end()) {//This group is exist
			if (m_mc_memberships_map[mc_grp].size() >= (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_source_membership()) {
				errno = ENOBUFS;
				return -1;
		  }
		}
		else {//This group is not exist
			if (m_mc_memberships_map.size() >= (size_t)safe_mce_sys().sysctl_reader.get_igmp_max_membership()) {
					errno = ENOBUFS;
					return -1;
				}
		}
		break;
	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
		break;
		BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(optname));
		return -1;
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	return 0;
}

int sockinfo_udp::mc_change_membership_end_helper(in_addr_t mc_grp, int optname, in_addr_t mc_src /*=0*/)
{
	switch (optname) {
	case IP_ADD_MEMBERSHIP:
		m_mc_memberships_map[mc_grp];
		break;
	case IP_ADD_SOURCE_MEMBERSHIP:
		m_mc_memberships_map[mc_grp][mc_src] = 1;
		if (1 == m_mc_memberships_map[mc_grp].size()) {
			++m_mc_num_grp_with_src_filter;
		}
		break;
	case IP_DROP_MEMBERSHIP:
		m_mc_memberships_map.erase(mc_grp);
		break;
	case IP_DROP_SOURCE_MEMBERSHIP:
		if ((m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end())) {
			m_mc_memberships_map[mc_grp].erase(mc_src);
			if (0 == m_mc_memberships_map[mc_grp].size()) {
				m_mc_memberships_map.erase(mc_grp);
				--m_mc_num_grp_with_src_filter;
			}
		}
		break;
		BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(optname));
		return -1;
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	return 0;
}

int sockinfo_udp::mc_change_membership(const mc_pending_pram *p_mc_pram)
{
	in_addr_t mc_grp = p_mc_pram->imr_multiaddr.s_addr;
	in_addr_t mc_if = p_mc_pram->imr_interface.s_addr;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (IN_MULTICAST_N(mc_grp) == false) {
		si_udp_logerr("%s for non multicast (%d.%d.%d.%d) %#x", setsockopt_ip_opt_to_str(p_mc_pram->optname), NIPQUAD(mc_grp), mc_grp);
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	sock_addr tmp_grp_addr(AF_INET, mc_grp, m_bound.get_in_port());
	if (__vma_match_udp_receiver(TRANS_VMA, safe_mce_sys().app_id, tmp_grp_addr.get_p_sa(), tmp_grp_addr.get_socklen()) == TRANS_OS) {
		// Break so we call orig setsockopt() and don't try to offload
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(p_mc_pram->optname));
		return -1;
	}

	if (mc_if == INADDR_ANY) {
		in_addr_t dst_ip	= mc_grp;
		in_addr_t src_ip	= 0;
		
		if (!m_bound.is_anyaddr() && !m_bound.is_mc()) {
			src_ip = m_bound.get_in_addr();
		}else if (m_so_bindtodevice_ip) {
			src_ip = m_so_bindtodevice_ip;
		}
		// Find local if for this MC ADD/DROP
		route_result res;
		g_p_route_table_mgr->route_resolve(route_rule_table_key(dst_ip, src_ip, m_tos), res);
		mc_if = res.p_src;
	}

	// MNY: TODO: Check rules for local_if (blacklist interface feature)
	/*sock_addr tmp_if_addr(AF_INET, mc_if, m_bound.get_in_port());
	if (__vma_match_udp_receiver(TRANS_VMA, tmp_if_addr.get_p_sa(), tmp_if_addr.get_socklen(), safe_mce_sys().app_id) == TRANS_OS) {
		// Break so we call orig setsockopt() and don't try to offlaod
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling due to rule matching", setsockopt_ip_opt_to_str(optname));
		return -1;
	}*/

	// Check if local_if is offloadable
	if (!g_p_net_device_table_mgr->get_net_device_val(mc_if)) {
		// Break so we call orig setsockopt() and try to offlaod
		si_udp_logdbg("setsockopt(%s) will be passed to OS for handling - not offload interface (%d.%d.%d.%d)", setsockopt_ip_opt_to_str(p_mc_pram->optname), NIPQUAD(mc_if));
		return -1;
	}

	int pram_size = sizeof(ip_mreq);
	struct ip_mreq_source mreq_src;
	mreq_src.imr_multiaddr.s_addr = p_mc_pram->imr_multiaddr.s_addr;
	mreq_src.imr_interface.s_addr = p_mc_pram->imr_interface.s_addr;
	mreq_src.imr_sourceaddr.s_addr = p_mc_pram->imr_sourceaddr.s_addr;

	switch (p_mc_pram->optname) {
	case IP_ADD_MEMBERSHIP:
	{
		if ((m_mc_memberships_map.find(mc_grp) != m_mc_memberships_map.end()) && (0 < m_mc_memberships_map[mc_grp].size())) {
			return -1; // Same group with source filtering is already exist
		}

		// The address specified in bind() has a filtering role.
		// i.e. sockets should discard datagrams which sent to an unbound ip address.
		if (!m_bound.is_anyaddr() && mc_grp != m_bound.get_in_addr()) {
			// Ignore for socketXtreme because m_bound is used as part of the legacy implementation
			if (!safe_mce_sys().enable_socketxtreme) {
				return -1; // Socket was bound to a different ip address
			}
		}

		flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), m_connected.get_in_addr(), m_connected.get_in_port(), PROTO_UDP, mc_if);
		if (!attach_receiver(flow_key)) {
			// we will get RX from OS
			return -1;
		}
		vma_stats_mc_group_add(mc_grp, m_p_socket_stats);
		original_os_setsockopt_helper( &mreq_src, pram_size, p_mc_pram->optname);
		m_multicast = true;
		break;
	}
	case IP_ADD_SOURCE_MEMBERSHIP:
	{
		flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), 0, 0, PROTO_UDP, mc_if);
		if (!attach_receiver(flow_key)) {
			// we will get RX from OS
			return -1;
		}
		vma_stats_mc_group_add(mc_grp, m_p_socket_stats);
		pram_size = sizeof(ip_mreq_source);
		original_os_setsockopt_helper( &mreq_src, pram_size, p_mc_pram->optname);
		m_multicast = true;
		break;
	}
	case IP_DROP_MEMBERSHIP:
	{
		flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), m_connected.get_in_addr(), m_connected.get_in_port(), PROTO_UDP, mc_if);
		original_os_setsockopt_helper( &mreq_src, pram_size, p_mc_pram->optname);
		if (!detach_receiver(flow_key)) {
			return -1;
		}
		vma_stats_mc_group_remove(mc_grp, m_p_socket_stats);
		m_multicast = false;
		break;
	}
	case IP_DROP_SOURCE_MEMBERSHIP:
	{
		flow_tuple_with_local_if flow_key(mc_grp, m_bound.get_in_port(), 0, 0, PROTO_UDP, mc_if);
		pram_size = sizeof(ip_mreq_source);
		original_os_setsockopt_helper( &mreq_src, pram_size, p_mc_pram->optname);
		if (1 == m_mc_memberships_map[mc_grp].size()) { //Last source in the group
			if (!detach_receiver(flow_key)) {
				return -1;
			}
			vma_stats_mc_group_remove(mc_grp, m_p_socket_stats);
			m_multicast = false; // get out from MC group
		}
		break;
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		si_udp_logerr("setsockopt(%s) will be passed to OS for handling", setsockopt_ip_opt_to_str(p_mc_pram->optname));
		return -1;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	
	// set full versus partial RX UDP handling due to potential updates in m_multicast
	set_rx_packet_processor();
	return 0;
}

void sockinfo_udp::original_os_setsockopt_helper( void* pram, int pram_size, int optname)
{
	si_udp_logdbg("calling orig_setsockopt(%s) for igmp support by OS", setsockopt_ip_opt_to_str(optname));
	if (orig_os_api.setsockopt(m_fd, IPPROTO_IP, optname, pram, pram_size)) {
		si_udp_logdbg("orig setsockopt(%s) failed (errno=%d %m)",setsockopt_ip_opt_to_str(optname), errno);
	}
}

void sockinfo_udp::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
	sockinfo::statistics_print(log_level);

	// Socket data
	vlog_printf(log_level, "Rx ready list size : %u\n", m_rx_pkt_ready_list.size());

	vlog_printf(log_level, "Socket timestamp : m_b_rcvtstamp %s, m_b_rcvtstampns %s, m_n_tsing_flags %u\n",
			m_b_rcvtstamp ? "true" : "false" , m_b_rcvtstampns ? "true" : "false", m_n_tsing_flags);
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

void sockinfo_udp::save_stats_tx_offload(int bytes, bool is_dummy)
{
	if (unlikely(is_dummy)) {
		m_p_socket_stats->counters.n_tx_dummy++;
	} else {
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
	}
}

int sockinfo_udp::free_packets(struct vma_packet_t *pkts, size_t count)
{
	int ret = 0;
	unsigned int 	index = 0;
	mem_buf_desc_t 	*buff;
	
	m_lock_rcv.lock();
	for(index=0; index < count; index++){
		buff = (mem_buf_desc_t*)pkts[index].packet_id;
		if (m_rx_ring_map.find(buff->p_desc_owner->get_parent()) == m_rx_ring_map.end()) {
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

timestamps_t* sockinfo_udp::get_socket_timestamps()
{
	if (unlikely(m_rx_pkt_ready_list.empty())) {
		si_udp_logdbg("m_rx_pkt_ready_list empty");
		return NULL;
	}
	return &m_rx_pkt_ready_list.front()->rx.timestamps;
}

void sockinfo_udp::post_deqeue(bool release_buff)
{
	mem_buf_desc_t *to_resue = m_rx_pkt_ready_list.get_and_pop_front();
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
	int len = p_iov[0].iov_len - sizeof(vma_packets_t) - sizeof(vma_packet_t);

	// Make sure there is enough room for the header
	if (len < 0) {
		errno = ENOBUFS;
		return -1;
	}

	// Copy iov pointers to user buffer
	vma_packets_t *p_packets = (vma_packets_t*)p_iov[0].iov_base;
	p_packets->n_packet_num = 1;	
	p_packets->pkts[0].packet_id = (void*)p_desc;
	p_packets->pkts[0].sz_iov = 0;
	for (p_desc_iter = p_desc; p_desc_iter; p_desc_iter = p_desc_iter->p_next_desc) {
		len -= sizeof(p_packets->pkts[0].iov[0]);
		if (len < 0) {
			*p_flags = MSG_TRUNC;
			break;
		}
		p_packets->pkts[0].iov[p_packets->pkts[0].sz_iov++] = p_desc_iter->rx.frag;
		total_rx += p_desc_iter->rx.frag.iov_len;
	}

	m_p_socket_stats->n_rx_zcopy_pkt_count++;

	si_udp_logfunc("copied pointers to %d bytes to user buffer", total_rx);
	return total_rx;
}

size_t sockinfo_udp::handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags, int* p_out_flags)
{
	if (payload_size > total_rx) {
		m_rx_ready_byte_count -= (payload_size-total_rx);
		m_p_socket_stats->n_rx_ready_byte_count -= (payload_size-total_rx);
		*p_out_flags |= MSG_TRUNC;
		if (in_flags & MSG_TRUNC) 
			return payload_size;
	} 

	return total_rx;
}

int sockinfo_udp::get_socket_tx_ring_fd(struct sockaddr *to, socklen_t tolen)
{
	NOT_IN_USE(tolen);
	si_udp_logfunc("get_socket_tx_ring_fd fd %d to %p tolen %d", m_fd, to ,tolen);

	if (!to) {
		si_udp_logdbg("got invalid to addr null for fd %d", m_fd);
		errno = EINVAL;
		return -1;
	}
	sock_addr dst(to);
	ring *ring = NULL;

	if (m_p_connected_dst_entry && m_connected == dst) {
		ring = m_p_connected_dst_entry->get_ring();
	} else {
		dst_entry_map_t::iterator it = m_dst_entry_map.find(dst);
		if (it != m_dst_entry_map.end()) {
			ring = it->second->get_ring();
		}
	}
	if (!ring) {
		si_udp_logdbg("could not find TX ring for fd %d addr %s",
				m_fd, dst.to_str());
		errno = ENODATA;
		return -1;
	}
	int res = ring->get_tx_channel_fd();
	si_udp_logdbg("Returning TX ring fd %d for sock fd %d adrr %s",
			res, m_fd, dst.to_str());
	return res;
}

mem_buf_desc_t* sockinfo_udp::get_front_m_rx_pkt_ready_list(){
	return m_rx_pkt_ready_list.front();
}

size_t sockinfo_udp::get_size_m_rx_pkt_ready_list(){
	return m_rx_pkt_ready_list.size();
}

void sockinfo_udp::pop_front_m_rx_pkt_ready_list(){
	m_rx_pkt_ready_list.pop_front();
}

void sockinfo_udp::push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff){
	m_rx_pkt_ready_list.push_back(buff);
}

bool sockinfo_udp::prepare_to_close(bool process_shutdown) {
	m_lock_rcv.lock();
	do_wakeup();
	m_lock_rcv.unlock();
	NOT_IN_USE(process_shutdown);
	m_state = SOCKINFO_CLOSING;
	return is_closable();
}

void sockinfo_udp::update_header_field(data_updater *updater)
{
	dst_entry_map_t::iterator dst_entry_iter = m_dst_entry_map.begin();
	for (; dst_entry_iter != m_dst_entry_map.end(); dst_entry_iter++) {
		updater->update_field(*dst_entry_iter->second);

	}
	if (m_p_connected_dst_entry) {
		updater->update_field(*m_p_connected_dst_entry);
	}
}
