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


#include "sockinfo.h"

#include <sys/epoll.h>
#include <netdb.h>
#include <linux/sockios.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/if.h"
#include "vma/proto/route_table_mgr.h"
#include "sock-redirect.h"
#include "fd_collection.h"
#include "vma/dev/ring_simple.h"


#define MODULE_NAME 		"si"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[fd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_fd

#define si_logpanic		__log_info_panic
#define si_logerr		__log_info_err
#define si_logwarn		__log_info_warn
#define si_loginfo		__log_info_info
#define si_logdbg		__log_info_dbg
#define si_logfunc		__log_info_func
#define si_logfuncall		__log_info_funcall


sockinfo::sockinfo(int fd):
		socket_fd_api(fd),
		m_b_blocking(true),
		m_b_pktinfo(false),
		m_b_rcvtstamp(false),
		m_b_rcvtstampns(false),
		m_n_tsing_flags(0),
		m_protocol(PROTO_UNDEFINED),
		m_lock_rcv(MODULE_NAME "::m_lock_rcv"),
		m_lock_snd(MODULE_NAME "::m_lock_snd"),
		m_state(SOCKINFO_OPENED),
		m_p_connected_dst_entry(NULL),
		m_so_bindtodevice_ip(INADDR_ANY),
		m_p_rx_ring(0),
		m_rx_reuse_buf_pending(false),
		m_rx_reuse_buf_postponed(false),
		m_rx_ring_map_lock(MODULE_NAME "::m_rx_ring_map_lock"),
		m_n_rx_pkt_ready_list_count(0), m_rx_pkt_ready_offset(0), m_rx_ready_byte_count(0),
		m_n_sysvar_rx_num_buffs_reuse(safe_mce_sys().rx_bufs_batch),
		m_n_sysvar_rx_poll_num(safe_mce_sys().rx_poll_num),
		m_ring_alloc_log_rx(safe_mce_sys().ring_allocation_logic_rx),
		m_ring_alloc_log_tx(safe_mce_sys().ring_allocation_logic_tx),
		m_pcp(0),
		m_rx_callback(NULL),
		m_rx_callback_context(NULL),
		m_fd_context((void *)((uintptr_t)m_fd)),
		m_flow_tag_id(0),
		m_flow_tag_enabled(false),
		m_n_uc_ttl(safe_mce_sys().sysctl_reader.get_net_ipv4_ttl()),
		m_tcp_flow_is_5t(false),
		m_p_rings_fds(NULL)

{
	m_ring_alloc_logic = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx, this);
	m_rx_epfd = orig_os_api.epoll_create(128);
	if (unlikely(m_rx_epfd == -1)) {
	  throw_vma_exception("create internal epoll");
	}
	wakeup_set_epoll_fd(m_rx_epfd);

	m_p_socket_stats = &m_socket_stats; // Save stats as local copy and allow state publisher to copy from this location
	vma_stats_instance_create_socket_block(m_p_socket_stats);
	m_p_socket_stats->reset();
	m_p_socket_stats->fd = m_fd;
	m_p_socket_stats->inode = fd2inode(m_fd);
	m_p_socket_stats->b_blocking = m_b_blocking;
	m_p_socket_stats->ring_alloc_logic_rx = m_ring_alloc_log_rx.get_ring_alloc_logic();
	m_p_socket_stats->ring_alloc_logic_tx = m_ring_alloc_log_tx.get_ring_alloc_logic();
	m_p_socket_stats->ring_user_id_rx = m_ring_alloc_logic.calc_res_key_by_logic();
	m_p_socket_stats->ring_user_id_tx =
			ring_allocation_logic_tx(get_fd(), m_ring_alloc_log_tx, this).calc_res_key_by_logic();
	m_rx_reuse_buff.n_buff_num = 0;
	memset(&m_so_ratelimit, 0, sizeof(vma_rate_limit_t));
	set_flow_tag(m_fd + 1);

	m_socketxtreme.ec.clear();
	m_socketxtreme.completion = NULL;
	m_socketxtreme.last_buff_lst = NULL;
}

sockinfo::~sockinfo()
{
	m_state = SOCKINFO_CLOSED;

	// Change to non-blocking socket so calling threads can exit
	m_b_blocking = false;
	orig_os_api.close(m_rx_epfd); // this will wake up any blocked thread in rx() call to orig_os_api.epoll_wait()
	if (m_p_rings_fds) {
		delete[] m_p_rings_fds;
		m_p_rings_fds = NULL;
	}
        vma_stats_instance_remove_socket_block(m_p_socket_stats);
}

void sockinfo::set_blocking(bool is_blocked)
{
	if (is_blocked) {
		si_logdbg("set socket to blocked mode");
		m_b_blocking = true;
	}
	else {
		si_logdbg("set socket to non-blocking mode");
		m_b_blocking = false;
	}

	// Update statistics info
	m_p_socket_stats->b_blocking = m_b_blocking;
}

int sockinfo::fcntl(int __cmd, unsigned long int __arg)
{
	switch (__cmd) {
	case F_SETFL:
		{
			si_logdbg("cmd=F_SETFL, arg=%#x", __arg);
			if (__arg & O_NONBLOCK)
				set_blocking(false);
			else
				set_blocking(true);
		}
		break;
	case F_GETFL:		/* Get file status flags.  */
		si_logfunc("cmd=F_GETFL, arg=%#x", __arg);
		break;

	case F_GETFD:		/* Get file descriptor flags.  */
		si_logfunc("cmd=F_GETFD, arg=%#x", __arg);
		break;

	case F_SETFD:		/* Set file descriptor flags.  */
		si_logfunc("cmd=F_SETFD, arg=%#x", __arg);
		break;

	default:
		char buf[128];
		snprintf(buf, sizeof(buf), "unimplemented fcntl cmd=%#x, arg=%#x", (unsigned)__cmd, (unsigned)__arg);
		buf[ sizeof(buf)-1 ] = '\0';

		VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
		int rc = handle_exception_flow();
		switch (rc) {
		case -1:
			return rc;
		case -2:
			vma_throw_object_with_msg(vma_unsupported_api, buf);
		}
		break;
	}
	si_logdbg("going to OS for fcntl cmd=%d, arg=%#x", __cmd, __arg);
	return orig_os_api.fcntl(m_fd, __cmd, __arg);
}

int sockinfo::set_ring_attr(vma_ring_alloc_logic_attr *attr)
{
	if ((attr->comp_mask & VMA_RING_ALLOC_MASK_RING_ENGRESS) && attr->engress) {
		if (set_ring_attr_helper(&m_ring_alloc_log_tx, attr)) {
			return SOCKOPT_NO_VMA_SUPPORT;
		}
		ring_alloc_logic_updater du(get_fd(), m_lock_snd, m_ring_alloc_log_tx, m_p_socket_stats);
		update_header_field(&du);
		m_p_socket_stats->ring_alloc_logic_tx = m_ring_alloc_log_tx.get_ring_alloc_logic();
		m_p_socket_stats->ring_user_id_tx =
			ring_allocation_logic_tx(get_fd(), m_ring_alloc_log_tx, this).calc_res_key_by_logic();
	}
	if ((attr->comp_mask & VMA_RING_ALLOC_MASK_RING_INGRESS) && attr->ingress) {
		ring_alloc_logic_attr old_key(*m_ring_alloc_logic.get_key());

		if (set_ring_attr_helper(&m_ring_alloc_log_rx, attr)) {
			return SOCKOPT_NO_VMA_SUPPORT;
		}
		m_ring_alloc_logic = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx, this);
		
		if (m_rx_nd_map.size()) {
			auto_unlocker locker(m_rx_migration_lock);
			do_rings_migration(old_key);
		}

		m_p_socket_stats->ring_alloc_logic_rx = m_ring_alloc_log_rx.get_ring_alloc_logic();
		m_p_socket_stats->ring_user_id_rx =  m_ring_alloc_logic.calc_res_key_by_logic();
	}

	return SOCKOPT_INTERNAL_VMA_SUPPORT;
}

int sockinfo::set_ring_attr_helper(ring_alloc_logic_attr *sock_attr,
				   vma_ring_alloc_logic_attr *user_attr)
{
	if (user_attr->comp_mask & VMA_RING_ALLOC_MASK_RING_PROFILE_KEY) {
		if (sock_attr->get_ring_profile_key()) {
			si_logdbg("ring_profile_key is already set and "
				  "cannot be changed");
			return -1;
		}
		sock_attr->set_ring_profile_key(user_attr->ring_profile_key);
	}

	sock_attr->set_ring_alloc_logic(user_attr->ring_alloc_logic);

	if (user_attr->comp_mask & VMA_RING_ALLOC_MASK_RING_USER_ID)
		sock_attr->set_user_id_key(user_attr->user_id);

	return 0;
}

int sockinfo::ioctl(unsigned long int __request, unsigned long int __arg)
{

	int *p_arg = (int *)__arg;

	switch (__request) {
	case FIONBIO:
		{
			si_logdbg("request=FIONBIO, arg=%d", *p_arg);
			if (*p_arg)
				set_blocking(false);
			else
				set_blocking(true);
		}
		break;

	case FIONREAD:
		{
			si_logfunc("request=FIONREAD, arg=%d", *p_arg);
			int ret = rx_verify_available_data();
			if (ret >= 0) {
				*p_arg = ret;
				return 0;
			}
			return ret;
		}
		break;
	case SIOCGIFVLAN: /* prevent error print */
		break;
	default:
		char buf[128];
		snprintf(buf, sizeof(buf), "unimplemented ioctl request=%#x, flags=%#x", (unsigned)__request, (unsigned)__arg);
		buf[ sizeof(buf)-1 ] = '\0';

		VLOG_PRINTF_INFO(safe_mce_sys().exception_handling.get_log_severity(), "%s", buf);
		int rc = handle_exception_flow();
		switch (rc) {
		case -1:
			return rc;
		case -2:
			vma_throw_object_with_msg(vma_unsupported_api, buf);
		}
		break;
	}

    si_logdbg("going to OS for ioctl request=%d, flags=%x", __request, __arg);
	return orig_os_api.ioctl(m_fd, __request, __arg);
}

int sockinfo::setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen)
{
	int ret = SOCKOPT_PASS_TO_OS;

	if (__level == SOL_SOCKET) {
		switch(__optname) {
		case SO_VMA_USER_DATA:
			if (__optlen == sizeof(m_fd_context)) {
				m_fd_context = *(void **)__optval;
				ret = SOCKOPT_INTERNAL_VMA_SUPPORT;
			} else {
				ret = SOCKOPT_NO_VMA_SUPPORT;
				errno = EINVAL;
			}
			break;
		case SO_VMA_RING_USER_MEMORY:
			if (__optval) {
				if (__optlen == sizeof(iovec)) {
					iovec *attr = (iovec *)__optval;
					m_ring_alloc_log_rx.set_memory_descriptor(*attr);
					m_ring_alloc_logic = ring_allocation_logic_rx(get_fd(), m_ring_alloc_log_rx, this);
					if (m_p_rx_ring || m_rx_ring_map.size()) {
						si_logwarn("user asked to assign memory for "
							   "RX ring but ring already exists");
					}
					ret = SOCKOPT_INTERNAL_VMA_SUPPORT;
				} else {
					ret = SOCKOPT_NO_VMA_SUPPORT;
					errno = EINVAL;
					si_logdbg("SOL_SOCKET, SO_VMA_RING_USER_MEMORY - "
						  "bad length expected %d got %d",
						  sizeof(iovec), __optlen);
				}
			}
			else {
				ret = SOCKOPT_NO_VMA_SUPPORT;
				errno = EINVAL;
				si_logdbg("SOL_SOCKET, SO_VMA_RING_USER_MEMORY - NOT HANDLED, optval == NULL");
			}
			break;
		case SO_VMA_FLOW_TAG:
			if (__optval) {
				if (__optlen == sizeof(uint32_t)) {
					if (set_flow_tag(*(uint32_t*)__optval)) {
						si_logdbg("SO_VMA_FLOW_TAG, set "
							  "socket %s to flow id %d",
							  m_fd, m_flow_tag_id);
						// not supported in OS
						ret = SOCKOPT_INTERNAL_VMA_SUPPORT;
					} else {
						ret = SOCKOPT_NO_VMA_SUPPORT;
						errno = EINVAL;
					}
				} else {
					ret = SOCKOPT_NO_VMA_SUPPORT;
					errno = EINVAL;
					si_logdbg("SO_VMA_FLOW_TAG, bad length "
						  "expected %d got %d",
						  sizeof(uint32_t), __optlen);
					break;
				}
			} else {
				ret = SOCKOPT_NO_VMA_SUPPORT;
				errno = EINVAL;
				si_logdbg("SO_VMA_FLOW_TAG - NOT HANDLED, "
					  "optval == NULL");
			}
			break;
		case SO_TIMESTAMP:
		case SO_TIMESTAMPNS:
			if (__optval) {
				m_b_rcvtstamp = *(bool*)__optval;
				if (__optname == SO_TIMESTAMPNS)
					m_b_rcvtstampns = m_b_rcvtstamp;
				si_logdbg("SOL_SOCKET, %s=%s", setsockopt_so_opt_to_str(__optname), (m_b_rcvtstamp ? "true" : "false"));
			}
			else {
				si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
			}
			break;

		case SO_TIMESTAMPING:
			if (__optval) {
				uint8_t val = *(uint8_t*)__optval;

				// SOF_TIMESTAMPING_TX_SOFTWARE and SOF_TIMESTAMPING_TX_HARDWARE is NOT supported.
				if (val & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE)) {
					ret = SOCKOPT_NO_VMA_SUPPORT;
					errno = EOPNOTSUPP;
					si_logdbg("SOL_SOCKET, SOF_TIMESTAMPING_TX_SOFTWARE and SOF_TIMESTAMPING_TX_HARDWARE is not supported, errno set to EOPNOTSUPP");
				}

				if (val & (SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE)) {
					if (g_p_net_device_table_mgr->get_ctx_time_conversion_mode() == TS_CONVERSION_MODE_DISABLE){
						if (safe_mce_sys().hw_ts_conversion_mode ==  TS_CONVERSION_MODE_DISABLE) {
							ret = SOCKOPT_NO_VMA_SUPPORT;
							errno = EPERM;
							si_logdbg("SOL_SOCKET, SOF_TIMESTAMPING_RAW_HARDWARE and SOF_TIMESTAMPING_RX_HARDWARE socket options were disabled (VMA_HW_TS_CONVERSION = %d) , errno set to EPERM", TS_CONVERSION_MODE_DISABLE);
						} else {
							ret = SOCKOPT_NO_VMA_SUPPORT;
							errno = ENODEV;
							si_logdbg("SOL_SOCKET, SOF_TIMESTAMPING_RAW_HARDWARE and SOF_TIMESTAMPING_RX_HARDWARE is not supported by device(s), errno set to ENODEV");
						}
					}
				}

				m_n_tsing_flags  = val;
				si_logdbg("SOL_SOCKET, SO_TIMESTAMPING=%u", m_n_tsing_flags);
			}
			else {
				si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
			}
			break;
		case SO_VMA_RING_ALLOC_LOGIC:
			if (__optval) {
				uint32_t val = ((vma_ring_alloc_logic_attr*) __optval)->comp_mask;

				if (val & (VMA_RING_ALLOC_MASK_RING_PROFILE_KEY | VMA_RING_ALLOC_MASK_RING_USER_ID |
					   VMA_RING_ALLOC_MASK_RING_INGRESS | VMA_RING_ALLOC_MASK_RING_ENGRESS)) {
					if (__optlen == sizeof(vma_ring_alloc_logic_attr)) {
						vma_ring_alloc_logic_attr *attr = (vma_ring_alloc_logic_attr *)__optval;
						return set_ring_attr(attr);
					}
					else {
						ret = SOCKOPT_NO_VMA_SUPPORT;
						errno = EINVAL;
						si_logdbg("SOL_SOCKET, %s=\"???\" - bad length expected %d got %d",
							  setsockopt_so_opt_to_str(__optname),
							  sizeof(vma_ring_alloc_logic_attr), __optlen);
						break;
					}
				}
				else {
					ret = SOCKOPT_NO_VMA_SUPPORT;
					errno = EINVAL;
					si_logdbg("SOL_SOCKET, %s=\"???\" - bad optval (%d)", setsockopt_so_opt_to_str(__optname), val);
				}
			}
			else {
				ret = SOCKOPT_NO_VMA_SUPPORT;
				errno = EINVAL;
				si_logdbg("SOL_SOCKET, %s=\"???\" - NOT HANDLED, optval == NULL", setsockopt_so_opt_to_str(__optname));
			}
			break;
		case SO_VMA_SHUTDOWN_RX:
			shutdown_rx();
			ret = SOCKOPT_INTERNAL_VMA_SUPPORT;
			break;
		default:
			break;
		}
	} else if (__level == IPPROTO_IP) {
		switch(__optname) {
		case IP_TTL:
			if (__optlen < sizeof(m_n_uc_ttl)) {
				ret = SOCKOPT_NO_VMA_SUPPORT;
				errno = EINVAL;
			} else {
				int val = __optlen < sizeof(val) ?  (uint8_t) *(uint8_t *)__optval : (int) *(int *)__optval;
				if (val != -1 && (val < 1 || val > 255)) {
					ret = SOCKOPT_NO_VMA_SUPPORT;
					errno = EINVAL;
				} else {
					m_n_uc_ttl = (val == -1) ? safe_mce_sys().sysctl_reader.get_net_ipv4_ttl() : (uint8_t) val;
					header_ttl_updater du(m_n_uc_ttl, false);
					update_header_field(&du);
					si_logdbg("IPPROTO_IP, optname=IP_TTL (%d)", m_n_uc_ttl);
				}
			}
			break;
		default:
			break;
		}
	}

	si_logdbg("ret (%d)", ret);
	return ret;
}

int sockinfo::getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen)
{
	int ret = -1;

	switch (__level) {
	case SOL_SOCKET:
		switch(__optname) {
		case SO_VMA_USER_DATA:
			if (*__optlen == sizeof(m_fd_context)) {
				*(void **)__optval = m_fd_context;
				ret = 0;
			} else {
				errno = EINVAL;
			}
		break;
		case SO_VMA_FLOW_TAG:
			if (*__optlen >= sizeof(uint32_t)) {
				*(uint32_t*)__optval = m_flow_tag_id;
				ret = 0;
			} else {
				errno = EINVAL;
			}
		break;
		case SO_MAX_PACING_RATE:
			if (*__optlen == sizeof(struct vma_rate_limit_t)) {
				*(struct vma_rate_limit_t*)__optval = m_so_ratelimit;
				*__optlen = sizeof(struct vma_rate_limit_t);
				si_logdbg("(SO_MAX_PACING_RATE) value: %d, %d, %d",
					  (*(struct vma_rate_limit_t*)__optval).rate,
					  (*(struct vma_rate_limit_t*)__optval).max_burst_sz,
					  (*(struct vma_rate_limit_t*)__optval).typical_pkt_sz);
			} else if (*__optlen == sizeof(uint32_t)) {
				*(uint32_t*)__optval = KB_TO_BYTE(m_so_ratelimit.rate);
				*__optlen = sizeof(uint32_t);
				si_logdbg("(SO_MAX_PACING_RATE) value: %d",
					  *(int *)__optval);
				ret = 0;
			} else {
				errno = EINVAL;
			}
		break;
		}
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////
bool sockinfo::try_un_offloading() // un-offload the socket if possible
{
	if (!this->isPassthrough()) {
		setPassthrough();
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
int sockinfo::get_sock_by_L3_L4(in_protocol_t protocol, in_addr_t ip, in_port_t  port)
{
	int map_size = g_p_fd_collection->get_fd_map_size();
	for (int i = 0; i < map_size; i++) {
		socket_fd_api* p_sock_i = g_p_fd_collection->get_sockfd(i);
		if (!p_sock_i || p_sock_i->get_type() != FD_TYPE_SOCKET) continue;
		sockinfo* s = (sockinfo*)p_sock_i;
		if (protocol == s->m_protocol && ip == s->m_bound.get_in_addr() && port == s->m_bound.get_in_port()) return i;
	}
	return -1;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int sockinfo::rx_wait(int &poll_count, bool is_blocking)
{
	int ret_val = 0;
	ret_val = rx_wait_helper(poll_count, is_blocking);
	return ret_val;
}

int sockinfo::rx_wait_helper(int &poll_count, bool is_blocking)
{
	int ret;
	uint64_t poll_sn = 0;
	epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
	rx_ring_map_t::iterator rx_ring_iter;

	// poll for completion
	si_logfunc("");

	poll_count++;

	for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
		//BULLSEYE_EXCLUDE_BLOCK_START
		if (unlikely(rx_ring_iter->second->refcnt <= 0)) {
			si_logerr("Attempted to poll illegal cq");
			continue;
		}
		//BULLSEYE_EXCLUDE_BLOCK_END
		ret = rx_ring_iter->first->poll_and_process_element_rx(&poll_sn);
		if (ret > 0) {
			si_logfuncall("got %d elements sn=%llu", ret, (unsigned long long)poll_sn);
			return ret;
		}
	}

	if (poll_count < m_n_sysvar_rx_poll_num || m_n_sysvar_rx_poll_num == -1) {
		return 0;
	}

	// if we polling too much - go to sleep
	si_logfunc("too many polls without data blocking=%d", is_blocking);
	if (g_b_exit)
		return -1;

	if (!is_blocking) {
		/* if we are in non blocking mode - return EAGAIN */
		errno = EAGAIN;
		return -1;
	}

	for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
		if (rx_ring_iter->second->refcnt <= 0) {
			continue;
		}
		// coverity[check_return]
		rx_ring_iter->first->request_notification(CQT_RX, poll_sn);
	}

	ret = orig_os_api.epoll_wait(m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, -1);

	if (ret < 0)
		return -1;
	if (ret == 0)
		return 0;

	for (int event_idx = 0; event_idx < ret; ++event_idx) {
		int cq_channel_fd = rx_epfd_events[event_idx].data.fd;
		cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(cq_channel_fd);
		if (p_cq_ch_info) {
			ring* p_ring = p_cq_ch_info->get_ring();
			if (p_ring) {
				p_ring->wait_for_notification_and_process_element(cq_channel_fd, &poll_sn);
			}
		}

		// TODO: need to handle wakeup
	}
	return 0;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void sockinfo::save_stats_rx_offload(int nbytes)
{
	if (nbytes >= 0) {
		m_p_socket_stats->counters.n_rx_bytes += nbytes;
		m_p_socket_stats->counters.n_rx_packets++;
	}
	else if (errno == EAGAIN) {
		m_p_socket_stats->counters.n_rx_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_rx_errors++;
	}
}

void sockinfo::save_stats_rx_os(int bytes)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_rx_os_bytes += bytes;
		m_p_socket_stats->counters.n_rx_os_packets++;
	}else if ( errno == EAGAIN ){
		m_p_socket_stats->counters.n_rx_os_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_rx_os_errors++;
	}
}

void sockinfo::save_stats_tx_os(int bytes)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_tx_os_bytes += bytes;
		m_p_socket_stats->counters.n_tx_os_packets++;
	}else if ( errno == EAGAIN ){
		m_p_socket_stats->counters.n_rx_os_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_tx_os_errors++;
	}
}

size_t sockinfo::handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags, int* p_out_flags)
{
	NOT_IN_USE(payload_size);
	NOT_IN_USE(in_flags);
	*p_out_flags &= ~MSG_TRUNC; //don't handle msg_trunc
	return total_rx;
}

bool sockinfo::attach_receiver(flow_tuple_with_local_if &flow_key)
{
	// This function should be called from within mutex protected context of the sockinfo!!!

	si_logdbg("Attaching to %s", flow_key.to_str());

	// Protect against local loopback used as local_if & peer_ip
	// rdma_cm will accept it but we don't want to offload it
	if (flow_key.is_local_loopback()) {
		si_logdbg("VMA does not offload local loopback IP address");
		return false;
	}

	if (m_rx_flow_map.find(flow_key) != m_rx_flow_map.end()) {
		si_logdbg("already attached %s", flow_key.to_str());
		return false;
	}

	// Allocate resources on specific interface (create ring)
	net_device_resources_t* p_nd_resources = create_nd_resources((const ip_address)flow_key.get_local_if());
	if (NULL == p_nd_resources) {
		// any error which occurred inside create_nd_resources() was already printed. No need to reprint errors here
		return false;
	}

	// Map flow in local map
	m_rx_flow_map[flow_key] = p_nd_resources->p_ring;

	// Attach tuple
	BULLSEYE_EXCLUDE_BLOCK_START
	unlock_rx_q();
	if (!p_nd_resources->p_ring->attach_flow(flow_key, this)) {
		lock_rx_q();
		si_logdbg("Failed to attach %s to ring %p", flow_key.to_str(), p_nd_resources->p_ring);
		return false;
	}
	set_rx_packet_processor();
	lock_rx_q();
	BULLSEYE_EXCLUDE_BLOCK_END

	// Registered as receiver successfully
	si_logdbg("Attached %s to ring %p", flow_key.to_str(), p_nd_resources->p_ring);


        // Verify 5 tuple over 3 tuple
        if (flow_key.is_5_tuple())
        {
        	// Check and remove lesser 3 tuple
        	flow_tuple_with_local_if flow_key_3t(flow_key.get_dst_ip(), flow_key.get_dst_port(), INADDR_ANY, INPORT_ANY, flow_key.get_protocol(), flow_key.get_local_if());
        	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key_3t);
        	if (rx_flow_iter != m_rx_flow_map.end()) {
        		si_logdbg("Removing (and detaching) 3 tuple now that we added a stronger 5 tuple");
        		detach_receiver(flow_key_3t);
        	}
        }

	return true;
}

bool sockinfo::detach_receiver(flow_tuple_with_local_if &flow_key)
{
	si_logdbg("Unregistering receiver: %s", flow_key.to_str());

	// TODO ALEXR: DO we need to return a 3 tuple instead of a 5 tuple being removed?
	// if (peer_ip != INADDR_ANY && peer_port != INPORT_ANY);

	// Find ring associated with this tuple
	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_flow_iter == m_rx_flow_map.end()) {
		si_logdbg("Failed to find ring associated with: %s", flow_key.to_str());
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	ring* p_ring = rx_flow_iter->second;

	si_logdbg("Detaching %s from ring %p", flow_key.to_str(), p_ring);

	// Detach tuple
	unlock_rx_q();
	p_ring->detach_flow(flow_key, this);
	lock_rx_q();

	// Un-map flow from local map
	m_rx_flow_map.erase(rx_flow_iter);

	return destroy_nd_resources((const ip_address)flow_key.get_local_if());
}

net_device_resources_t* sockinfo::create_nd_resources(const ip_address ip_local)
{
	net_device_resources_t* p_nd_resources = NULL;

	// Check if we are already registered to net_device with the local ip as observers
	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
	if (rx_nd_iter == m_rx_nd_map.end()) {

		// Need to register as observer to net_device
		net_device_resources_t nd_resources;
		nd_resources.refcnt = 0;
		nd_resources.p_nde = NULL;
		nd_resources.p_ndv = NULL;
		nd_resources.p_ring = NULL;

		BULLSEYE_EXCLUDE_BLOCK_START
		cache_entry_subject<ip_address, net_device_val*>* p_ces = NULL;
		if (!g_p_net_device_table_mgr->register_observer(ip_local, &m_rx_nd_observer, &p_ces)) {
			si_logdbg("Failed registering as observer for local ip %s", ip_local.to_str().c_str());
			goto err;
		}
		nd_resources.p_nde = (net_device_entry*)p_ces;
		if (!nd_resources.p_nde) {
			si_logerr("Got NULL net_devide_entry for local ip %s", ip_local.to_str().c_str());
			goto err;
		}
		if (!nd_resources.p_nde->get_val(nd_resources.p_ndv)) {
			si_logerr("Got net_device_val=NULL (interface is not offloaded) for local ip %s", ip_local.to_str().c_str());
			goto err;
		}

		unlock_rx_q();
		m_rx_ring_map_lock.lock();
		resource_allocation_key *key;
		if (m_rx_ring_map.size() && m_ring_alloc_logic.is_logic_support_migration()) {
			key = m_ring_alloc_logic.get_key();
		} else {
			key = m_ring_alloc_logic.create_new_key(ip_local.get_in_addr());
		}
		m_rx_ring_map_lock.unlock();
		nd_resources.p_ring = nd_resources.p_ndv->reserve_ring(key);
		lock_rx_q();
		if (!nd_resources.p_ring) {
			si_logdbg("Failed to reserve ring for allocation key %s on ip %s",
				  m_ring_alloc_logic.get_key()->to_str(), ip_local.to_str().c_str());
			goto err;
		}

		// Add new net_device to rx_map
		m_rx_nd_map[ip_local.get_in_addr()] = nd_resources;

		rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
		if (rx_nd_iter == m_rx_nd_map.end()) {
			si_logerr("Failed to find rx_nd_iter");
			goto err;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

	}

	// Now we have the net_device object (created or found)
	p_nd_resources = &rx_nd_iter->second;

	/* just increment reference counter on attach */
	p_nd_resources->refcnt++;

	// Save the new CQ from ring (dummy_flow_key is not used)
	{
		flow_tuple_with_local_if dummy_flow_key(m_bound, m_connected, m_protocol, ip_local.get_in_addr());
		rx_add_ring_cb(dummy_flow_key, p_nd_resources->p_ring);
	}

	return p_nd_resources;
err:
	return NULL;
}

bool sockinfo::destroy_nd_resources(const ip_address ip_local)
{
	net_device_resources_t* p_nd_resources = NULL;
	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_nd_iter == m_rx_nd_map.end()) {
		si_logerr("Failed to net_device associated with: %s", ip_local.to_str().c_str());
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	p_nd_resources = &(rx_nd_iter->second);

	p_nd_resources->refcnt--;

	// Release the new CQ from ring (dummy_flow_key is not used)
	{
		flow_tuple_with_local_if dummy_flow_key(m_bound, m_connected, m_protocol, ip_local.get_in_addr());
		rx_del_ring_cb(dummy_flow_key, p_nd_resources->p_ring);
	}

	if (p_nd_resources->refcnt == 0) {

		// Release ring reference
		BULLSEYE_EXCLUDE_BLOCK_START
		unlock_rx_q();
		resource_allocation_key *key;
		if (m_ring_alloc_logic.is_logic_support_migration()) {
			key = m_ring_alloc_logic.get_key();
		} else {
			key = m_ring_alloc_logic.create_new_key(ip_local.get_in_addr());
		}
		if (!p_nd_resources->p_ndv->release_ring(key)) {
			lock_rx_q();
			si_logerr("Failed to release ring for allocation key %s on ip %s",
				  m_ring_alloc_logic.get_key()->to_str(),
				  ip_local.to_str().c_str());
			return false;
		}
		lock_rx_q();

		// Release observer reference
		if (!g_p_net_device_table_mgr->unregister_observer(ip_local, &m_rx_nd_observer)) {
			si_logerr("Failed registering as observer for lip %s", ip_local.to_str().c_str());
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		m_rx_nd_map.erase(rx_nd_iter);
	}

	return true;
}

void sockinfo::do_rings_migration(resource_allocation_key &old_key)
{
	lock_rx_q();

	uint64_t new_calc_id = m_ring_alloc_logic.calc_res_key_by_logic();
	uint64_t old_calc_id = old_key.get_user_id_key();
	resource_allocation_key *new_key = m_ring_alloc_logic.get_key();
	// Check again if migration is needed before migration
	if (old_key.get_user_id_key() == new_calc_id &&
	    old_key.get_ring_alloc_logic() == new_key->get_ring_alloc_logic()) {
		unlock_rx_q();
		return;
	}

	// Update key to new ID
	new_key->set_user_id_key(new_calc_id);
	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.begin();
	while (rx_nd_iter != m_rx_nd_map.end()) {
		net_device_resources_t* p_nd_resources = &(rx_nd_iter->second);
		ring* p_old_ring = p_nd_resources->p_ring;
		unlock_rx_q();
		ring* new_ring = p_nd_resources->p_ndv->reserve_ring(new_key);
		if (new_ring == p_old_ring) {
			if (!p_nd_resources->p_ndv->release_ring(&old_key)) {
				si_logerr("Failed to release ring for allocation key %s",
						old_key.to_str());
				new_key->set_user_id_key(old_calc_id);
				m_ring_alloc_logic.enable_migration(false);
				si_logwarn("Migration is disabled due to failure");
			}
			lock_rx_q();
			rx_nd_iter++;
			continue;
		}
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!new_ring) {
			ip_address ip_local(rx_nd_iter->first);
			si_logerr("Failed to reserve ring for allocation key %s on lip %s",
				  new_key->to_str(), ip_local.to_str().c_str());
			new_key->set_user_id_key(old_calc_id);
			m_ring_alloc_logic.enable_migration(false);
			si_logwarn("Migration is disabled due to failure");
			lock_rx_q();
			rx_nd_iter++;
			continue;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		lock_rx_q();
		rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
		while (rx_flow_iter !=  m_rx_flow_map.end()) {

			ring* p_ring = rx_flow_iter->second;
			if (p_ring != p_old_ring) {
				rx_flow_iter++; // Pop next flow rule
				continue;
			}

			flow_tuple_with_local_if flow_key = rx_flow_iter->first;
			// Save the new CQ from ring
			rx_add_ring_cb(flow_key, new_ring, true);

			// Attach tuple
			BULLSEYE_EXCLUDE_BLOCK_START
			unlock_rx_q();
			if (!new_ring->attach_flow(flow_key, this)) {
				si_logerr("Failed to attach %s to ring %p", flow_key.to_str(), new_ring);
				rx_del_ring_cb(flow_key, new_ring, true);
				if (!p_nd_resources->p_ndv->release_ring(new_key)) {
					si_logerr("Failed to release ring for allocation key %s",
							new_key->to_str());
				}
				new_ring = NULL;
				break;
			}
			lock_rx_q();
			BULLSEYE_EXCLUDE_BLOCK_END

			rx_flow_iter->second = new_ring;

			// Registered as receiver successfully
			si_logdbg("Attached %s to ring %p", flow_key.to_str(), new_ring);

			si_logdbg("Detaching %s from ring %p", flow_key.to_str(), p_old_ring);
			// Detach tuple
			unlock_rx_q();
			p_old_ring->detach_flow(flow_key, this);
			lock_rx_q();
			rx_del_ring_cb(flow_key, p_old_ring, true);

			rx_flow_iter++; // Pop next flow rule;
		}

		if (!new_ring) {
			ip_address ip_local(rx_nd_iter->first);
			si_logerr("Failed to reserve ring for allocation key %s on lip %s",
				  new_key->to_str(), ip_local.to_str().c_str());
			new_key->set_user_id_key(old_calc_id);
			m_ring_alloc_logic.enable_migration(false);
			si_logwarn("Migration is disabled due to failure");
			lock_rx_q();
			rx_nd_iter++;
			continue;
		}

		unlock_rx_q();
		m_rx_ring_map_lock.lock();
		lock_rx_q();
		if (!m_p_rx_ring && m_rx_ring_map.size() == 1) {
			m_p_rx_ring = m_rx_ring_map.begin()->first;
		}
		unlock_rx_q();
		m_rx_ring_map_lock.unlock();

		// Release ring reference
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!p_nd_resources->p_ndv->release_ring(&old_key)) {
			ip_address ip_local(rx_nd_iter->first);
			si_logerr("Failed to release ring for allocation key %s on lip %s",
				  old_key.to_str(), ip_local.to_str().c_str());
		}
		lock_rx_q();
		BULLSEYE_EXCLUDE_BLOCK_END
		p_nd_resources->p_ring = new_ring;
		rx_nd_iter++;
	}

	unlock_rx_q();
	m_p_socket_stats->counters.n_rx_migrations++;
}

void sockinfo::consider_rings_migration()
{
	if (m_ring_alloc_logic.is_logic_support_migration()) {
		if(!m_rx_migration_lock.trylock()) {
			if (m_ring_alloc_logic.should_migrate_ring()) {
				ring_alloc_logic_attr old_key(*m_ring_alloc_logic.get_key());
				do_rings_migration(old_key);
			}
			m_rx_migration_lock.unlock();
		}
	}
}

int sockinfo::add_epoll_context(epfd_info *epfd)
{
	int ret = 0;
	rx_ring_map_t::const_iterator sock_ring_map_iter;

	m_rx_ring_map_lock.lock();
	lock_rx_q();

	ret = socket_fd_api::add_epoll_context(epfd);
	if (ret < 0) {
		goto unlock_locks;
	}

	sock_ring_map_iter = m_rx_ring_map.begin();
	while (sock_ring_map_iter != m_rx_ring_map.end()) {
		notify_epoll_context_add_ring(sock_ring_map_iter->first);
		sock_ring_map_iter++;
	}

unlock_locks:

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();

	return ret;
}

void sockinfo::remove_epoll_context(epfd_info *epfd)
{
	m_rx_ring_map_lock.lock();
	lock_rx_q();

	if (!notify_epoll_context_verify(epfd)) {
		unlock_rx_q();
		m_rx_ring_map_lock.unlock();
		return;
	}

	rx_ring_map_t::const_iterator sock_ring_map_iter = m_rx_ring_map.begin();
	while (sock_ring_map_iter != m_rx_ring_map.end()) {
		notify_epoll_context_remove_ring(sock_ring_map_iter->first);
		sock_ring_map_iter++;
	}

	socket_fd_api::remove_epoll_context(epfd);

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();
}

void sockinfo::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
	const char * const in_protocol_str[] = {
	  "PROTO_UNDEFINED",
	  "PROTO_UDP",
	  "PROTO_TCP",
	  "PROTO_ALL",
	};

	const char * const m_state_str[] = {
	  "SOCKINFO_OPENED",
	  "SOCKINFO_CLOSING",
	  "SOCKINFO_CLOSED",
	};

	bool b_any_activity = false;

	socket_fd_api::statistics_print(log_level);

	vlog_printf(log_level, "Bind info : %s\n", m_bound.to_str());
	vlog_printf(log_level, "Connection info : %s\n", m_connected.to_str());
	vlog_printf(log_level, "Protocol : %s\n", in_protocol_str[m_protocol]);
	vlog_printf(log_level, "Is closed : %s\n", m_state_str[m_state]);
	vlog_printf(log_level, "Is blocking : %s\n", m_b_blocking ? "true" : "false");
	vlog_printf(log_level, "Rx reuse buffer pending : %s\n", m_rx_reuse_buf_pending ? "true" : "false");
	vlog_printf(log_level, "Rx reuse buffer postponed : %s\n", m_rx_reuse_buf_postponed ? "true" : "false");

	if (m_p_connected_dst_entry) {
		vlog_printf(log_level, "Is offloaded : %s\n", m_p_connected_dst_entry->is_offloaded() ? "true" : "false");
	}

	if (m_p_socket_stats->ring_alloc_logic_rx == RING_LOGIC_PER_USER_ID)
		vlog_printf(log_level, "RX Ring User ID : %lu\n", m_p_socket_stats->ring_user_id_rx);
	if (m_p_socket_stats->ring_alloc_logic_tx == RING_LOGIC_PER_USER_ID)
		vlog_printf(log_level, "TX Ring User ID : %lu\n", m_p_socket_stats->ring_user_id_tx);

	if (m_p_socket_stats->counters.n_tx_sent_byte_count || m_p_socket_stats->counters.n_tx_sent_pkt_count || m_p_socket_stats->counters.n_tx_errors || m_p_socket_stats->counters.n_tx_drops ) {
		vlog_printf(log_level, "Tx Offload : %d KB / %d / %d / %d [bytes/packets/drops/errors]\n", m_p_socket_stats->counters.n_tx_sent_byte_count/1024, m_p_socket_stats->counters.n_tx_sent_pkt_count, m_p_socket_stats->counters.n_tx_drops, m_p_socket_stats->counters.n_tx_errors);
		b_any_activity = true;
	}
	if (m_p_socket_stats->counters.n_tx_os_bytes || m_p_socket_stats->counters.n_tx_os_packets || m_p_socket_stats->counters.n_tx_os_errors) {
		vlog_printf(log_level, "Tx OS info : %d KB / %d / %d [bytes/packets/errors]\n", m_p_socket_stats->counters.n_tx_os_bytes/1024, m_p_socket_stats->counters.n_tx_os_packets, m_p_socket_stats->counters.n_tx_os_errors);
		b_any_activity = true;
	}
	if (m_p_socket_stats->counters.n_tx_dummy) {
		vlog_printf(log_level, "Tx Dummy messages : %d\n", m_p_socket_stats->counters.n_tx_dummy);
		b_any_activity = true;
	}
	if (m_p_socket_stats->counters.n_rx_bytes || m_p_socket_stats->counters.n_rx_packets || m_p_socket_stats->counters.n_rx_errors || m_p_socket_stats->counters.n_rx_eagain || m_p_socket_stats->n_rx_ready_pkt_count) {
		vlog_printf(log_level, "Rx Offload : %d KB / %d / %d / %d [bytes/packets/eagains/errors]\n", m_p_socket_stats->counters.n_rx_bytes/1024, m_p_socket_stats->counters.n_rx_packets, m_p_socket_stats->counters.n_rx_eagain, m_p_socket_stats->counters.n_rx_errors);

		if (m_p_socket_stats->counters.n_rx_packets) {
			float rx_drop_percentage = 0;
			if (m_p_socket_stats->n_rx_ready_pkt_count)
				rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_byte_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
			vlog_printf(log_level, "Rx byte : max %d / dropped %d (%2.2f%%) / limit %d\n", m_p_socket_stats->counters.n_rx_ready_byte_max, m_p_socket_stats->counters.n_rx_ready_byte_drop, rx_drop_percentage, m_p_socket_stats->n_rx_ready_byte_limit);

			if (m_p_socket_stats->n_rx_ready_pkt_count)
				rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_pkt_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
			vlog_printf(log_level, "Rx pkt : max %d / dropped %d (%2.2f%%)\n", m_p_socket_stats->counters.n_rx_ready_pkt_max, m_p_socket_stats->counters.n_rx_ready_pkt_drop, rx_drop_percentage);
		}

		b_any_activity = true;
	}
	if (m_p_socket_stats->counters.n_rx_os_bytes || m_p_socket_stats->counters.n_rx_os_packets || m_p_socket_stats->counters.n_rx_os_errors || m_p_socket_stats->counters.n_rx_os_eagain) {
		vlog_printf(log_level, "Rx OS info : %d KB / %d / %d / %d [bytes/packets/eagains/errors]\n", m_p_socket_stats->counters.n_rx_os_bytes/1024, m_p_socket_stats->counters.n_rx_os_packets, m_p_socket_stats->counters.n_rx_os_eagain, m_p_socket_stats->counters.n_rx_os_errors);
		b_any_activity = true;
	}
	if (m_p_socket_stats->counters.n_rx_poll_miss || m_p_socket_stats->counters.n_rx_poll_hit) {
		float rx_poll_hit_percentage = (float)(m_p_socket_stats->counters.n_rx_poll_hit * 100) / (float)(m_p_socket_stats->counters.n_rx_poll_miss + m_p_socket_stats->counters.n_rx_poll_hit);
		vlog_printf(log_level, "Rx poll : %d / %d (%2.2f%%) [miss/hit]\n", m_p_socket_stats->counters.n_rx_poll_miss, m_p_socket_stats->counters.n_rx_poll_hit, rx_poll_hit_percentage);
		b_any_activity = true;
	}
	if (b_any_activity == false) {
		vlog_printf(log_level, "Socket activity : Rx and Tx where not active\n");
	}
}

void sockinfo::rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /*= false*/)
{
	si_logdbg("");
	NOT_IN_USE(flow_key);
	NOT_IN_USE(is_migration);

	bool notify_epoll = false;

	// Add the rx ring to our rx ring map
	unlock_rx_q();
	m_rx_ring_map_lock.lock();
	lock_rx_q();
	rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(p_ring->get_parent());
	if (rx_ring_iter == m_rx_ring_map.end()) {
		// First map of this cq mgr
		ring_info_t* p_ring_info = new ring_info_t();
		m_rx_ring_map[p_ring] = p_ring_info;
		p_ring_info->refcnt = 1;
		p_ring_info->rx_reuse_info.n_buff_num = 0;

		/* m_p_rx_ring is updated in following functions:
		 *  - rx_add_ring_cb()
		 *  - rx_del_ring_cb()
		 *  - do_rings_migration()
		 */
		if (m_rx_ring_map.size() == 1) {
			m_p_rx_ring = m_rx_ring_map.begin()->first;
		}

		notify_epoll = true;

		// Add this new CQ channel fd to the rx epfd handle (no need to wake up any sleeping thread about this new fd)
		epoll_event ev = {0, {0}};
		ev.events = EPOLLIN;
		int num_ring_rx_fds = p_ring->get_num_resources();
		int *ring_rx_fds_array = p_ring->get_rx_channel_fds();

		for (int i = 0; i < num_ring_rx_fds; i++) {
			int cq_ch_fd = ring_rx_fds_array[i];

			ev.data.fd = cq_ch_fd;

			BULLSEYE_EXCLUDE_BLOCK_START
			if (unlikely( orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_ADD, cq_ch_fd, &ev))) {
				si_logerr("failed to add cq channel fd to internal epfd errno=%d (%m)", errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}

		do_wakeup(); // A ready wce can be pending due to the drain logic (cq channel will not wake up by itself)
	} else {
		// Increase ref count on cq_mgr object
		rx_ring_iter->second->refcnt++;
	}

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();

	if (notify_epoll) {
		// todo m_econtext is not protected by socket lock because epfd->m_ring_map_lock should be first in order.
		// possible race between removal of fd from epoll (epoll_ctl del, or epoll close) and here.
		// need to add a third-side lock (fd_collection?) to sync between epoll and socket.
		notify_epoll_context_add_ring(p_ring);
	}

	lock_rx_q();
}

void sockinfo::rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_logdbg("");
	NOT_IN_USE(flow_key);

	bool notify_epoll = false;

	// Remove the rx cq_mgr from our rx cq map
	unlock_rx_q();
	m_rx_ring_map_lock.lock();
	lock_rx_q();

	descq_t temp_rx_reuse;
	temp_rx_reuse.set_id("sockinfo (%p), fd = %d : rx_del_ring_cb temp_rx_reuse", this, m_fd);
	descq_t temp_rx_reuse_global;
	temp_rx_reuse_global.set_id("sockinfo (%p), fd = %d : rx_del_ring_cb temp_rx_reuse_global", this, m_fd);

	ring* base_ring = p_ring->get_parent();
	rx_ring_map_t::iterator rx_ring_iter =  m_rx_ring_map.find(base_ring);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_ring_iter != m_rx_ring_map.end()) {
	BULLSEYE_EXCLUDE_BLOCK_END
		ring_info_t* p_ring_info = rx_ring_iter->second;
		// Decrease ref count on cq_mgr object
		p_ring_info->refcnt--;

		// Is this the last reference to this cq_mgr?
		if (p_ring_info->refcnt == 0) {

			// Get rid of all rx ready buffers from this cq_mgr owner
			if (!is_migration) move_owned_rx_ready_descs(base_ring, &temp_rx_reuse);

			// Move all cq_mgr->rx_reuse buffers to temp reuse queue related to p_rx_cq_mgr
			move_owned_descs(base_ring, &temp_rx_reuse, &p_ring_info->rx_reuse_info.rx_reuse);
			move_not_owned_descs(base_ring, &temp_rx_reuse_global, &p_ring_info->rx_reuse_info.rx_reuse);
			if (p_ring_info->rx_reuse_info.rx_reuse.size()) {
				si_logerr("possible buffer leak, p_ring_info->rx_reuse_buff still contain %d buffers.", p_ring_info->rx_reuse_info.rx_reuse.size());
			}

			int num_ring_rx_fds = base_ring->get_num_resources();
			int *ring_rx_fds_array = base_ring->get_rx_channel_fds();

			for (int i = 0; i < num_ring_rx_fds; i++) {
				int cq_ch_fd = ring_rx_fds_array[i];
				BULLSEYE_EXCLUDE_BLOCK_START
				if (unlikely( orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_DEL, cq_ch_fd, NULL))) {
					si_logerr("failed to delete cq channel fd from internal epfd (errno=%d %m)", errno);
				}
				BULLSEYE_EXCLUDE_BLOCK_END
			}

			notify_epoll = true;

			m_rx_ring_map.erase(base_ring);
			delete p_ring_info;

			if (m_p_rx_ring == base_ring) {
				/* Remove event from rx ring if it is active
				 * or just reinitialize
				 * ring should not have events related closed socket
				 * in wait list
				 */
				m_p_rx_ring->del_ec(&m_socketxtreme.ec);
				if (m_rx_ring_map.size() == 1) {
					m_p_rx_ring = m_rx_ring_map.begin()->first;
				} else {
					m_p_rx_ring = NULL;
				}

				move_owned_descs(base_ring, &temp_rx_reuse, &m_rx_reuse_buff.rx_reuse);
				move_not_owned_descs(base_ring, &temp_rx_reuse_global, &m_rx_reuse_buff.rx_reuse);

				m_rx_reuse_buff.n_buff_num = m_rx_reuse_buff.rx_reuse.size();
			}
		}
	}
	else {
		si_logerr("oops, ring not found in map, so we can't remove it ???");
	}
	unlock_rx_q();
	m_rx_ring_map_lock.unlock();

	if (notify_epoll) {
		// todo m_econtext is not protected by socket lock because epfd->m_ring_map_lock should be first in order.
		// possible race between removal of fd from epoll (epoll_ctl del, or epoll close) and here.
		// need to add a third-side lock (fd_collection?) to sync between epoll and socket.
		notify_epoll_context_remove_ring(base_ring);
	}

	if (temp_rx_reuse.size() > 0) { // no need for m_lock_rcv since temp_rx_reuse is on the stack
		// Get rig of all rx reuse buffers from temp reuse queue
		// Without m_lock_rcv.lock()!!!
		unsigned int counter = 1<<20;
		while (temp_rx_reuse.size() > 0 && counter--) {
			if (base_ring->reclaim_recv_buffers(&temp_rx_reuse))
				break;
			sched_yield();
		}
		if (temp_rx_reuse.size() > 0) //Awareness: we do this without buffer_poll lock after all other tries failed
			g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&temp_rx_reuse);
	}

	if (temp_rx_reuse_global.size() > 0) {
		g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&temp_rx_reuse_global);
	}

	lock_rx_q();
}

// Move all owner's rx ready packets to 'toq'
void sockinfo::move_owned_rx_ready_descs(ring* p_ring, descq_t *toq)
{
	// Assume locked by owner!!!

	mem_buf_desc_t *temp;
	const size_t size = get_size_m_rx_pkt_ready_list();
	for (size_t i = 0 ; i < size; i++) {
		temp = get_front_m_rx_pkt_ready_list();
		pop_front_m_rx_pkt_ready_list();
		if (!p_ring->is_member(temp->p_desc_owner)) {
			push_back_m_rx_pkt_ready_list(temp);
			continue;
		}
		m_n_rx_pkt_ready_list_count--;
		m_p_socket_stats->n_rx_ready_pkt_count--;

		m_rx_ready_byte_count -= temp->rx.sz_payload;
		m_p_socket_stats->n_rx_ready_byte_count -= temp->rx.sz_payload;
		toq->push_back(temp);
	}
}

bool sockinfo::attach_as_uc_receiver(role_t role, bool skip_rules /* = false */)
{
	sock_addr addr(m_bound.get_p_sa());
	in_addr_t local_if;
	bool ret = true;

	/* m_so_bindtodevice_ip has high priority */
	if (m_so_bindtodevice_ip != INADDR_ANY) {
		local_if = m_so_bindtodevice_ip;
		addr.set_in_addr(local_if); // we should pass correct ip-address information in case SO_BINDTODEVICE is used
		si_logdbg("Attaching using bind to device rule");
	}
	else {
		local_if = m_bound.get_in_addr();
		si_logdbg("Attaching using bind to ip rule");
	}

	if (local_if != INADDR_ANY) {
		si_logdbg("Attached to specific local if: (%d.%d.%d.%d) addr: %s", NIPQUAD(local_if), addr.to_str());
		
		transport_t target_family = TRANS_VMA;
		if (!skip_rules) target_family = find_target_family(role, addr.get_p_sa());
		if (target_family == TRANS_VMA) {
			flow_tuple_with_local_if flow_key(addr, m_connected, m_protocol, local_if);
			ret = ret && attach_receiver(flow_key);
		}
	}
	else {
		si_logdbg("Attaching to all offload if addr: %s", addr.to_str());

		local_ip_list_t::iterator lip_iter;
		local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list();
		for (lip_iter = lip_offloaded_list.begin(); ret && lip_offloaded_list.end() != lip_iter; lip_iter++)
		{
			ip_data_t ip = *lip_iter;
			local_if = ip.local_addr;
			addr.set_in_addr(local_if);
			transport_t target_family = TRANS_VMA;
			if (!skip_rules) target_family = find_target_family(role, addr.get_p_sa());
			if (target_family == TRANS_VMA) {
				flow_tuple_with_local_if flow_key(addr, m_connected, m_protocol, local_if);
				ret = ret && attach_receiver(flow_key);
			}
		}
	}

	return ret;
}

transport_t sockinfo::find_target_family(role_t role, struct sockaddr* sock_addr_first, struct sockaddr* sock_addr_second /* = NULL */)
{
	transport_t target_family = TRANS_DEFAULT;
	switch (role) {
	case ROLE_TCP_SERVER:
		target_family = __vma_match_tcp_server(TRANS_VMA, safe_mce_sys().app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_TCP_CLIENT:
		target_family = __vma_match_tcp_client(TRANS_VMA, safe_mce_sys().app_id, sock_addr_first, sizeof(struct sockaddr), sock_addr_second, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_RECEIVER:
		target_family = __vma_match_udp_receiver(TRANS_VMA, safe_mce_sys().app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_SENDER:
		target_family = __vma_match_udp_sender(TRANS_VMA, safe_mce_sys().app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_CONNECT:
		target_family = __vma_match_udp_connect(TRANS_VMA, safe_mce_sys().app_id, sock_addr_first, sizeof(struct sockaddr), sock_addr_second, sizeof(struct sockaddr));
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		break;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	return target_family;
}

void sockinfo::shutdown_rx()
{
	// Unregister this receiver from all ring's in our list
	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
	while (rx_flow_iter !=  m_rx_flow_map.end()) {
		flow_tuple_with_local_if detach_key = rx_flow_iter->first;
		detach_receiver(detach_key);
		rx_flow_iter = m_rx_flow_map.begin(); // Pop next flow rule
	}

	/* Destroy resources in case they are allocated using SO_BINDTODEVICE call */
	if (m_rx_nd_map.size()) {
		destroy_nd_resources(m_so_bindtodevice_ip);
	}
	si_logdbg("shutdown RX");
}

void sockinfo::destructor_helper()
{
	shutdown_rx();
	// Delete all dst_entry in our list
	if (m_p_connected_dst_entry) {
		delete m_p_connected_dst_entry;
	}
	m_p_connected_dst_entry = NULL;
}


int sockinfo::register_callback(vma_recv_callback_t callback, void *context)
{
	m_rx_callback = callback;
	m_rx_callback_context = context;
	return 0;
}

int sockinfo::modify_ratelimit(dst_entry* p_dst_entry, struct vma_rate_limit_t &rate_limit)
{
	if (m_ring_alloc_log_tx.get_ring_alloc_logic() == RING_LOGIC_PER_SOCKET ||
	    m_ring_alloc_log_tx.get_ring_alloc_logic() == RING_LOGIC_PER_USER_ID) {

		if (p_dst_entry) {
			int ret = p_dst_entry->modify_ratelimit(rate_limit);

			if (!ret)
				m_so_ratelimit = rate_limit;
			// value is in bytes (per second). we need to convert it to kilo-bits (per second)
			return ret;
		} else {
			m_so_ratelimit = rate_limit;
		}
		return 0;
	}
	si_logwarn("VMA is not configured with TX ring allocation logic per "
		   "socket or user-id.");
	return -1;
}

int sockinfo::get_rings_num()
{
	int count = 0;

	if (is_socketxtreme()) {
		/* socketXtreme mode support just single ring */
		return 1;
	}
	rx_ring_map_t::iterator it = m_rx_ring_map.begin();
	for (; it != m_rx_ring_map.end(); ++it) {
		count += it->first->get_num_resources();
	}
	return count;
}

int* sockinfo::get_rings_fds(int &res_length)
{
	res_length = 0;
	int index = 0;

	if (is_socketxtreme()) {
		/* socketXtreme mode support just single ring */
		res_length = 1;
		return m_p_rx_ring->get_rx_channel_fds();
	}

	if (m_p_rings_fds) {
		return m_p_rings_fds;
	}
	res_length = get_rings_num();
	m_p_rings_fds = new int[res_length];

	rx_ring_map_t::iterator it = m_rx_ring_map.begin();
	for (; it != m_rx_ring_map.end(); ++it) {
		int *p_n_rx_channel_fds = it->first->get_rx_channel_fds();
		for (int j = 0; j < it->first->get_num_resources(); ++j) {
			int fd = p_n_rx_channel_fds[j];
			if (fd != -1) {
				m_p_rings_fds[index] = fd;
				++index;
			} else {
				si_logdbg("got ring with fd -1");
			}
		}
	}
	return m_p_rings_fds;
}

int sockinfo::get_socket_network_ptr(void *ptr, uint16_t &len)
{
	if (!m_p_connected_dst_entry) {
		si_logdbg("dst entry no created fd %d", m_fd);
		errno = ENOTCONN;
		return -1;
	}
	header* hdr = m_p_connected_dst_entry->get_network_header();
	if (hdr->m_total_hdr_len == 0) {
		si_logdbg("header not created yet fd %d", m_fd);
		errno = ENOTCONN;
		return -1;
	}
	if (!ptr) {
		len = hdr->m_total_hdr_len;
		return 0;
	}
	if (ptr && len >= hdr->m_total_hdr_len) {
		len = hdr->m_total_hdr_len;
		memcpy(ptr, ((uint8_t*)hdr->m_actual_hdr_addr), len);
		return 0;
	}
	errno = ENOBUFS;
	return -1;
}

int sockinfo::setsockopt_kernel(int __level, int __optname, const void *__optval,
		socklen_t __optlen, int supported, bool allow_privileged)
{
	if (!supported) {
		char buf[256];
		snprintf(buf, sizeof(buf), "unimplemented setsockopt __level=%#x, __optname=%#x, [__optlen (%d) bytes of __optval=%.*s]", (unsigned)__level, (unsigned)__optname, __optlen, __optlen, (char*)__optval);
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

	si_logdbg("going to OS for setsockopt level %d optname %d", __level, __optname);
	int ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret) {
		if (EPERM == errno && allow_privileged) {
			si_logdbg("setsockopt failure is suppressed (ret=%d %m)", ret);
			ret = 0;
			errno = 0;
		}
		else {
			si_logdbg("setsockopt failed (ret=%d %m)", ret);
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return ret;
}

int sockinfo::set_sockopt_prio(__const void *__optval, socklen_t __optlen)
{
	if (__optlen < sizeof(int)) {
		si_logdbg("bad parameter size in set_sockopt_prio");
		errno = EINVAL;
		return -1;
	}
	uint32_t val = *(uint32_t*)__optval;
	if (m_pcp != val) {
		m_pcp = val;
		si_logdbg("set socket pcp to be %d", m_pcp);
		header_pcp_updater du(m_pcp);
		update_header_field(&du);
	}
	return 0;

}

/**
 * Function to process SW & HW timestamps
 */
void sockinfo::process_timestamps(mem_buf_desc_t* p_desc)
{
	// keep the sw_timestamp the same to all sockets
	if ((m_b_rcvtstamp ||
		 (m_n_tsing_flags &
		  (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE))) &&
		!p_desc->rx.timestamps.sw.tv_sec) {
		clock_gettime(CLOCK_REALTIME, &(p_desc->rx.timestamps.sw));
	}

	// convert hw timestamp to system time
	if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
		ring_simple* owner_ring = (ring_simple*) p_desc->p_desc_owner;
		if (owner_ring) {
			owner_ring->convert_hw_time_to_system_time(p_desc->rx.hw_raw_timestamp, &p_desc->rx.timestamps.hw);
		}
	}
}

void sockinfo::handle_recv_timestamping(struct cmsg_state *cm_state)
{
	struct {
		struct timespec systime;
		struct timespec hwtimetrans;
		struct timespec hwtimeraw;
	} tsing;

	memset(&tsing, 0, sizeof(tsing));

	timestamps_t* packet_timestamps = get_socket_timestamps();
	struct timespec* packet_systime = &packet_timestamps->sw;

	// Only fill in SO_TIMESTAMPNS if both requested.
	// This matches the kernel behavior.
	if (m_b_rcvtstampns) {
		insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPNS, packet_systime, sizeof(*packet_systime));
	} else if (m_b_rcvtstamp) {
		struct timeval tv;
		tv.tv_sec = packet_systime->tv_sec;
		tv.tv_usec = packet_systime->tv_nsec/1000;
		insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMP, &tv, sizeof(tv));
	}

	// Handle timestamping options
	// Only support rx time stamps at this time
	int support = m_n_tsing_flags & (SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE);
	if (!support) {
		return;
	}

	if (m_n_tsing_flags & SOF_TIMESTAMPING_SOFTWARE) {
		tsing.systime = packet_timestamps->sw;
	}

	if (m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
		tsing.hwtimeraw = packet_timestamps->hw;
	}

	insert_cmsg(cm_state, SOL_SOCKET, SO_TIMESTAMPING, &tsing, sizeof(tsing));
}

void sockinfo::insert_cmsg(struct cmsg_state * cm_state, int level, int type, void *data, int len)
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

void sockinfo::handle_cmsg(struct msghdr * msg)
{
	struct cmsg_state cm_state;

	cm_state.mhdr = msg;
	cm_state.cmhdr = CMSG_FIRSTHDR(msg);
	cm_state.cmsg_bytes_consumed = 0;

	if (m_b_pktinfo) handle_ip_pktinfo(&cm_state);
	if (m_b_rcvtstamp || m_n_tsing_flags) handle_recv_timestamping(&cm_state);

	cm_state.mhdr->msg_controllen = cm_state.cmsg_bytes_consumed;
}
