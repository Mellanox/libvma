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


#include <stdio.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include "vma/util/if.h"

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "utils/rdtsc.h"
#include "vma/util/libvma.h"
#include "vma/util/instrumentation.h"
#include "vma/util/list.h"
#include "vma/util/agent.h"
#include "vma/event/event_handler_manager.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/vma_lwip.h"
#include "vma/proto/dst_entry_tcp.h"
#include "vma/iomux/io_mux_call.h"

#include "sock-redirect.h"
#include "fd_collection.h"
#include "sockinfo_tcp.h"


// debugging macros
#define MODULE_NAME 		"si_tcp"

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[fd=%d]:%d:%s() "

#undef  __INFO__
#define __INFO__                m_fd

#define si_tcp_logpanic             __log_info_panic
#define si_tcp_logerr               __log_info_err
#define si_tcp_logwarn              __log_info_warn
#define si_tcp_loginfo              __log_info_info
#define si_tcp_logdbg               __log_info_dbg
#define si_tcp_logfunc              __log_info_func
#define si_tcp_logfuncall           __log_info_funcall

#define BLOCK_THIS_RUN(blocking, flags) (blocking && !(flags & MSG_DONTWAIT))
#define TCP_SEG_COMPENSATION 64

tcp_seg_pool *g_tcp_seg_pool = NULL;
tcp_timers_collection* g_tcp_timers_collection = NULL;

/*
 * The following socket options are inherited by a connected TCP socket from the listening socket:
 * SO_DEBUG, SO_DONTROUTE, SO_KEEPALIVE, SO_LINGER, SO_OOBINLINE, SO_RCVBUF, SO_RCVLOWAT, SO_SNDBUF,
 * SO_SNDLOWAT, TCP_MAXSEG, TCP_NODELAY.
 */
static bool is_inherited_option(int __level, int __optname)
{
	bool ret = false;
	if (__level == SOL_SOCKET) {
		switch (__optname) {
		case SO_DEBUG:
		case SO_DONTROUTE:
		case SO_KEEPALIVE:
		case SO_LINGER:
		case SO_OOBINLINE:
		case SO_RCVBUF:
		case SO_RCVLOWAT:
		case SO_SNDBUF:
		case SO_SNDLOWAT:
		case SO_VMA_RING_ALLOC_LOGIC:
			ret = true;
		}
	} else if (__level == IPPROTO_TCP) {
		switch (__optname) {
		case TCP_MAXSEG:
		case TCP_NODELAY:
			ret = true;
		}
	} else if (__level == IPPROTO_IP) {
		switch (__optname) {
		case IP_TTL:
			ret = true;
		}
	}

	return ret;
}

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void sockinfo_tcp::lock_tcp_con()
{
	m_tcp_con_lock.lock();
}

inline void sockinfo_tcp::unlock_tcp_con()
{
	if (m_timer_pending) {
		tcp_timer();
	}

	m_tcp_con_lock.unlock();
}

inline void sockinfo_tcp::init_pbuf_custom(mem_buf_desc_t *p_desc)
{
	p_desc->lwip_pbuf.pbuf.flags = PBUF_FLAG_IS_CUSTOM;
	p_desc->lwip_pbuf.pbuf.len = p_desc->lwip_pbuf.pbuf.tot_len = (p_desc->sz_data - p_desc->rx.tcp.n_transport_header_len);
	p_desc->lwip_pbuf.pbuf.ref = 1;
	p_desc->lwip_pbuf.pbuf.type = PBUF_REF;
	p_desc->lwip_pbuf.pbuf.next = NULL;
	p_desc->lwip_pbuf.pbuf.payload = (u8_t *)p_desc->p_buffer + p_desc->rx.tcp.n_transport_header_len;
}

/* change default rx_wait impl to flow based one */
inline int sockinfo_tcp::rx_wait(int &poll_count, bool is_blocking)
{
        int ret_val = 0;
        unlock_tcp_con();
        ret_val = rx_wait_helper(poll_count, is_blocking);
        lock_tcp_con();
        return ret_val;
}

inline int sockinfo_tcp::rx_wait_lockless(int & poll_count, bool is_blocking)
{
	if (m_timer_pending) {
		m_tcp_con_lock.lock();
		tcp_timer();
		m_tcp_con_lock.unlock();
	}

	return rx_wait_helper(poll_count, is_blocking);
}

inline void sockinfo_tcp::return_pending_rx_buffs()
{
    // force reuse of buffers especially for avoiding deadlock in case all buffers were taken and we can NOT get new FIN packets that will release buffers
	if (m_sysvar_buffer_batching_mode == BUFFER_BATCHING_NO_RECLAIM || !m_rx_reuse_buff.n_buff_num)
		return;

    if (m_rx_reuse_buf_pending) {
            if (m_p_rx_ring && m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
            } else {
                    g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&m_rx_reuse_buff.rx_reuse);
            }
            m_rx_reuse_buff.n_buff_num = 0;
            set_rx_reuse_pending(false);
    }
    else {
    	set_rx_reuse_pending(true);
    }
}

inline void sockinfo_tcp::return_pending_tx_buffs()
{
	if (m_sysvar_buffer_batching_mode == BUFFER_BATCHING_NO_RECLAIM || !m_p_connected_dst_entry)
		return;

	m_p_connected_dst_entry->return_buffers_pool();
}

//todo inline void sockinfo_tcp::return_pending_tcp_segs()

inline void sockinfo_tcp::reuse_buffer(mem_buf_desc_t *buff)
{
	set_rx_reuse_pending(false);
	if (likely(m_p_rx_ring)) {
		m_rx_reuse_buff.n_buff_num += buff->rx.n_frags;
		m_rx_reuse_buff.rx_reuse.push_back(buff);
		if (m_rx_reuse_buff.n_buff_num < m_n_sysvar_rx_num_buffs_reuse) {
			return;
		}
		if (m_rx_reuse_buff.n_buff_num >= 2 * m_n_sysvar_rx_num_buffs_reuse) {
			if (m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
				m_rx_reuse_buff.n_buff_num = 0;
			} else {
				g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&m_rx_reuse_buff.rx_reuse);
				m_rx_reuse_buff.n_buff_num = 0;
			}
			m_rx_reuse_buf_postponed = false;
		} else {
			m_rx_reuse_buf_postponed = true;
		}
	}
	else {
		sockinfo::reuse_buffer(buff);
	}
}

sockinfo_tcp::sockinfo_tcp(int fd):
        sockinfo(fd),
        m_timer_handle(NULL),
        m_timer_pending(false),
        m_sysvar_buffer_batching_mode(safe_mce_sys().buffer_batching_mode),
        m_sysvar_tcp_ctl_thread(safe_mce_sys().tcp_ctl_thread),
        m_sysvar_internal_thread_tcp_timer_handling(safe_mce_sys().internal_thread_tcp_timer_handling),
        m_sysvar_rx_poll_on_tx_tcp(safe_mce_sys().rx_poll_on_tx_tcp)
{
	si_tcp_logfuncall("");

	m_accepted_conns.set_id("sockinfo_tcp (%p), fd = %d : m_accepted_conns", this, m_fd);
	m_rx_pkt_ready_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_pkt_ready_list", this, m_fd);
	m_rx_cb_dropped_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_cb_dropped_list", this, m_fd);
	m_rx_ctl_packets_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_ctl_packets_list", this, m_fd);
	m_rx_ctl_reuse_list.set_id("sockinfo_tcp (%p), fd = %d : m_rx_ctl_reuse_list", this, m_fd);

	m_last_syn_tsc = 0;

	m_linger.l_linger = 0;
	m_linger.l_onoff = 0;

	m_bound.set_sa_family(AF_INET);
	m_protocol = PROTO_TCP;
	m_p_socket_stats->socket_type = SOCK_STREAM;

	memset(&m_rx_timestamps, 0, sizeof(m_rx_timestamps));

	m_sock_state = TCP_SOCK_INITED;
	m_conn_state = TCP_CONN_INIT;
	m_conn_timeout = CONNECT_DEFAULT_TIMEOUT_MS;
	setPassthrough(false); // by default we try to accelerate
	si_tcp_logdbg("tcp socket created");

	tcp_pcb_init(&m_pcb, TCP_PRIO_NORMAL);

	si_tcp_logdbg("new pcb %p pcb state %d", &m_pcb, get_tcp_state(&m_pcb));
	tcp_arg(&m_pcb, this);
	tcp_ip_output(&m_pcb, sockinfo_tcp::ip_output);
	tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb);
	tcp_err(&m_pcb, sockinfo_tcp::err_lwip_cb);
	tcp_sent(&m_pcb, sockinfo_tcp::ack_recvd_lwip_cb);
	m_pcb.my_container = this;

	m_n_pbufs_rcvd = m_n_pbufs_freed = 0;

	m_parent = NULL;
	m_iomux_ready_fd_array = NULL;

	/* SNDBUF accounting */
	m_sndbuff_max = 0;
	/* RCVBUF accounting */
	m_rcvbuff_max = safe_mce_sys().sysctl_reader.get_tcp_rmem()->default_value;

	m_rcvbuff_current = 0;
	m_rcvbuff_non_tcp_recved = 0;
	m_received_syn_num = 0;
	m_vma_thr = false;

	m_ready_conn_cnt = 0;
	m_backlog = INT_MAX;
	report_connected = false;

	m_call_orig_close_on_dtor = 0;

	m_error_status = 0;

	m_tcp_seg_count = 0;
	m_tcp_seg_in_use = 0;
	m_tcp_seg_list = g_tcp_seg_pool->get_tcp_segs(TCP_SEG_COMPENSATION);
	if (m_tcp_seg_list) m_tcp_seg_count += TCP_SEG_COMPENSATION;
	m_tx_consecutive_eagain_count = 0;

	// Disable Nagle algorithm if VMA_TCP_NODELAY flag was set.
	if (safe_mce_sys().tcp_nodelay) {
		try {
			int tcp_nodelay = 1;
			setsockopt(IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
		} catch (vma_error&) {
			// We should not be here
		}
	}

	// Enable Quickack if VMA_TCP_QUICKACK flag was set.
	if (safe_mce_sys().tcp_quickack) {
		try {
			int tcp_quickack = 1;
			setsockopt(IPPROTO_TCP, TCP_QUICKACK, &tcp_quickack, sizeof(tcp_quickack));
		} catch (vma_error&) {
			// We should not be here
		}
	}

	si_tcp_logdbg("TCP PCB FLAGS: 0x%x", m_pcb.flags);
	g_p_agent->register_cb((agent_cb_t)&sockinfo_tcp::put_agent_msg, (void *)this);
	si_tcp_logfunc("done");
}

sockinfo_tcp::~sockinfo_tcp()
{
	si_tcp_logfunc("");

	lock_tcp_con();

	if (!is_closable()) {
		//prepare to close wasn't called?
		prepare_to_close();
	}

	do_wakeup();

	destructor_helper();

	// Release preallocated buffers
	tcp_tx_preallocted_buffers_free(&m_pcb);

	if (m_tcp_seg_in_use) {
		si_tcp_logwarn("still %d tcp segs in use!", m_tcp_seg_in_use);
	}
	if (m_tcp_seg_count) {
		g_tcp_seg_pool->put_tcp_segs(m_tcp_seg_list);
	}

	while (!m_socket_options_list.empty()) {
		socket_option_t* opt = m_socket_options_list.front();
		m_socket_options_list.pop_front();
		delete(opt);
	}

	unlock_tcp_con();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_call_orig_close_on_dtor) {
		si_tcp_logdbg("calling orig_os_close on dup %d of %d",m_call_orig_close_on_dtor, m_fd);
		orig_os_api.close(m_call_orig_close_on_dtor);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (m_n_rx_pkt_ready_list_count || m_rx_ready_byte_count || m_rx_pkt_ready_list.size() || m_rx_ring_map.size() || m_rx_reuse_buff.n_buff_num || m_rx_reuse_buff.rx_reuse.size() || m_rx_cb_dropped_list.size() || m_rx_ctl_packets_list.size() || m_rx_peer_packets.size() || m_rx_ctl_reuse_list.size())
		si_tcp_logerr("not all buffers were freed. protocol=TCP. m_n_rx_pkt_ready_list_count=%d, m_rx_ready_byte_count=%d, m_rx_pkt_ready_list.size()=%d, m_rx_ring_map.size()=%d, m_rx_reuse_buff.n_buff_num=%d, m_rx_reuse_buff.rx_reuse.size=%d, m_rx_cb_dropped_list.size=%d, m_rx_ctl_packets_list.size=%d, m_rx_peer_packets.size=%d, m_rx_ctl_reuse_list.size=%d",
				m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count, (int)m_rx_pkt_ready_list.size() ,(int)m_rx_ring_map.size(), m_rx_reuse_buff.n_buff_num, m_rx_reuse_buff.rx_reuse.size(), m_rx_cb_dropped_list.size(), m_rx_ctl_packets_list.size(), m_rx_peer_packets.size(), m_rx_ctl_reuse_list.size());

	g_p_agent->unregister_cb((agent_cb_t)&sockinfo_tcp::put_agent_msg, (void *)this);

	si_tcp_logdbg("sock closed");
}

void sockinfo_tcp::clean_obj()
{
	lock_tcp_con();

	set_cleaned();

	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}

	g_p_event_handler_manager->unregister_timers_event_and_delete(this);

	unlock_tcp_con();
}

bool sockinfo_tcp::prepare_listen_to_close()
{
	//assume locked by sockinfo_tcp lock

	//remove the sockets from the accepted connections list
	while (!m_accepted_conns.empty())
	{
		sockinfo_tcp *new_sock = m_accepted_conns.get_and_pop_front();
		new_sock->m_sock_state = TCP_SOCK_INITED;
		class flow_tuple key;
		sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(new_sock->m_pcb));
		m_syn_received.erase(key);
		m_ready_conn_cnt--;
		new_sock->lock_tcp_con();
		new_sock->m_parent = NULL;
		new_sock->abort_connection();
		new_sock->unlock_tcp_con();
		close(new_sock->get_fd());
	}

	// remove the sockets from the syn_received connections list
	syn_received_map_t::iterator syn_received_itr;
	for (syn_received_itr = m_syn_received.begin(); syn_received_itr != m_syn_received.end(); )
	{
		sockinfo_tcp *new_sock = (sockinfo_tcp *)(syn_received_itr->second->my_container);
		new_sock->m_sock_state = TCP_SOCK_INITED;
		syn_received_map_t::iterator syn_received_itr_erase = syn_received_itr;
		syn_received_itr++;
		m_syn_received.erase(syn_received_itr_erase);
		m_received_syn_num--;
		new_sock->lock_tcp_con();
		new_sock->m_parent = NULL;
		new_sock->abort_connection();
		new_sock->unlock_tcp_con();
		close(new_sock->get_fd());
	}

	return true;
}

bool sockinfo_tcp::prepare_to_close(bool process_shutdown /* = false */)
{

	lock_tcp_con();

	si_tcp_logdbg("");

	bool is_listen_socket = is_server() || get_tcp_state(&m_pcb) == LISTEN;

	/*
	 * consider process_shutdown:
	 * workaround for LBM which does not close the listen sockets properly on process shutdown.
	 * as a result they become ready for select, but calling accept return failure.
	 * see RM#390019
	 */

	// listen, accepted or connected socket
	if ((is_listen_socket && !process_shutdown) || m_sock_state == TCP_SOCK_CONNECTED_RD
			|| m_sock_state == TCP_SOCK_CONNECTED_WR || m_sock_state == TCP_SOCK_CONNECTED_RDWR) {
		m_sock_state = TCP_SOCK_BOUND;
	}

	if (!is_listen_socket && m_n_rx_pkt_ready_list_count) {
		abort_connection();
	}

	m_rx_ready_byte_count += m_rx_pkt_ready_offset;
	m_p_socket_stats->n_rx_ready_byte_count += m_rx_pkt_ready_offset;
	while (m_n_rx_pkt_ready_list_count)
	{
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_pkt_ready_list.get_and_pop_front();
		m_n_rx_pkt_ready_list_count--;
		m_p_socket_stats->n_rx_ready_pkt_count--;
		m_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
		m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->rx.sz_payload;
		reuse_buffer(p_rx_pkt_desc);
	}

	while (!m_rx_ctl_packets_list.empty()) {
		/* coverity[double_lock] TODO: RM#1049980 */
		m_rx_ctl_packets_list_lock.lock();
		if (m_rx_ctl_packets_list.empty()) {
			m_rx_ctl_packets_list_lock.unlock();
			break;
		}
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_ctl_packets_list.get_and_pop_front();
		/* coverity[double_unlock] TODO: RM#1049980 */
		m_rx_ctl_packets_list_lock.unlock();
		reuse_buffer(p_rx_pkt_desc);
	}

	for (peer_map_t::iterator itr = m_rx_peer_packets.begin(); itr != m_rx_peer_packets.end(); ++itr) {
		vma_desc_list_t &peer_packets = itr->second;
		// loop on packets of a peer
		while (!peer_packets.empty()) {
			// get packet from list and reuse them
			mem_buf_desc_t* desc = peer_packets.get_and_pop_front();
			reuse_buffer(desc);
		}
	}
	m_rx_peer_packets.clear();

	while (!m_rx_ctl_reuse_list.empty()) {
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_ctl_reuse_list.get_and_pop_front();
		reuse_buffer(p_rx_pkt_desc);
	}

	while (!m_rx_cb_dropped_list.empty()) {
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_cb_dropped_list.get_and_pop_front();
		reuse_buffer(p_rx_pkt_desc);
	}

	return_reuse_buffers_postponed();

	/* According to "UNIX Network Programming" third edition,
	 * setting SO_LINGER with timeout 0 prior to calling close()
	 * will cause the normal termination sequence not to be initiated.
	 * If l_onoff is nonzero and l_linger is zero, TCP aborts the connection when it is closed.
	 * That is, TCP discards any data still remaining in the socket
	 * send buffer and sends an RST to the peer, not the normal four-packet connection
	 * termination sequence
	 */
        if (get_tcp_state(&m_pcb) != LISTEN && m_linger.l_onoff && !m_linger.l_linger) {
		abort_connection();
	} else {
		tcp_close(&m_pcb);

		if (is_listen_socket) {
			tcp_accept(&m_pcb, 0);
			tcp_syn_handled((struct tcp_pcb_listen*)(&m_pcb), 0);
			tcp_clone_conn((struct tcp_pcb_listen*)(&m_pcb), 0);
			prepare_listen_to_close(); //close pending to accept sockets
		} else {
			tcp_recv(&m_pcb, sockinfo_tcp::rx_drop_lwip_cb);
			tcp_sent(&m_pcb, 0);
		}

		//todo should we do this each time we get into prepare_to_close ?
		if (get_tcp_state(&m_pcb) != LISTEN) {
			handle_socket_linger();
		}
	}

	m_state = SOCKINFO_CLOSING;
	NOTIFY_ON_EVENTS(this, EPOLLHUP);

	do_wakeup();

	unlock_tcp_con();

	return (is_closable());
}

void sockinfo_tcp::handle_socket_linger() {
	timeval start, current, elapsed;
	long int linger_time_usec;
	int poll_cnt = 0;
	
	linger_time_usec = (!m_linger.l_onoff /*|| !m_b_blocking */) ? 0 : m_linger.l_linger * USEC_PER_SEC;
	si_tcp_logdbg("Going to linger for max time of %lu usec", linger_time_usec);
	memset(&elapsed, 0,sizeof(elapsed));
	gettime(&start);
	while ((tv_to_usec(&elapsed) <= linger_time_usec) && (m_pcb.unsent || m_pcb.unacked)) {
                /* SOCKETXTREME WA: Don't call rx_wait() in order not to miss VMA events in socketxtreme_poll() flow.
		 * TBD: find proper solution!
		 * rx_wait(poll_cnt, false);
		 * */
		if (!is_socketxtreme()) {
			rx_wait(poll_cnt, false);
		}
		tcp_output(&m_pcb);
		gettime(&current);
		tv_sub(&current, &start, &elapsed);
	}

	if (m_linger.l_onoff && (m_pcb.unsent || m_pcb.unacked)) {
		if (m_linger.l_linger > 0  /*&& m_b_blocking*/) {
			errno = ERR_WOULDBLOCK;
		}
	}
}

// call this function if you won't be able to go through si_tcp dtor
// do not call this function twice
void sockinfo_tcp::force_close()
{
	si_tcp_logdbg("can't reach dtor - force closing the socket");

	lock_tcp_con();

	//if the socket is not closed yet, send RST to remote host before exit.
	//we have to do this because we don't have VMA deamon
	//to progress connection closure after process termination

	if (!is_closable()) abort_connection();

	//print the statistics of the socket to vma_stats file
	vma_stats_instance_remove_socket_block(m_p_socket_stats);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_call_orig_close_on_dtor) {
		si_tcp_logdbg("calling orig_os_close on dup %d of %d",m_call_orig_close_on_dtor, m_fd);
		orig_os_api.close(m_call_orig_close_on_dtor);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	unlock_tcp_con();
}

// This method will be on syn received on the passive side of a TCP connection
void sockinfo_tcp::create_dst_entry()
{
	if (!m_p_connected_dst_entry) {
		socket_data data = { m_fd, m_n_uc_ttl, m_pcb.tos, m_pcp };
		m_p_connected_dst_entry = new dst_entry_tcp(m_connected.get_in_addr(),
					m_connected.get_in_port(),
					m_bound.get_in_port(),
					data,
					m_ring_alloc_log_tx);

		BULLSEYE_EXCLUDE_BLOCK_START
		if (!m_p_connected_dst_entry) {
			si_tcp_logerr("Failed to allocate m_p_connected_dst_entry");
			return;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!m_bound.is_anyaddr()) {
			m_p_connected_dst_entry->set_bound_addr(m_bound.get_in_addr());
		}
		if (m_so_bindtodevice_ip) {
			m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
		}
	}
}

void sockinfo_tcp::lock_rx_q()
{
	lock_tcp_con();
}

void sockinfo_tcp::unlock_rx_q()
{
	unlock_tcp_con();
}

void sockinfo_tcp::tcp_timer()
{
	if (m_state == SOCKINFO_CLOSED) {
		return;
	}

	tcp_tmr(&m_pcb);
	m_timer_pending = false;

	return_pending_rx_buffs();
	return_pending_tx_buffs();
}

bool sockinfo_tcp::prepare_dst_to_send(bool is_accepted_socket /* = false */)
{
	bool ret_val = false;

	if(m_p_connected_dst_entry) {
		if (is_accepted_socket) {
			ret_val = m_p_connected_dst_entry->prepare_to_send(m_so_ratelimit, true, false);
		} else {
			ret_val = m_p_connected_dst_entry->prepare_to_send(m_so_ratelimit, false, true);
		}

#ifdef DEFINED_TSO
		if (ret_val) {
			/* dst_entry has resolved tx ring,
			 * so it is a time to provide TSO information to PCB
			 */
			m_pcb.tso.max_buf_sz = std::min(safe_mce_sys().tx_buf_size,
					m_p_connected_dst_entry->get_ring()->get_max_payload_sz());
			m_pcb.tso.max_payload_sz = m_p_connected_dst_entry->get_ring()->get_max_payload_sz();
			m_pcb.tso.max_header_sz = m_p_connected_dst_entry->get_ring()->get_max_header_sz();
			m_pcb.tso.max_send_sge = m_p_connected_dst_entry->get_ring()->get_max_send_sge();
		}
#endif /* DEFINED_TSO */
	}
	return ret_val;
}


unsigned sockinfo_tcp::tx_wait(int & err, bool is_blocking)
{
	unsigned sz = tcp_sndbuf(&m_pcb);
	int poll_count = 0;
	si_tcp_logfunc("sz = %d rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
	err = 0;
	while (is_rts() && (sz = tcp_sndbuf(&m_pcb)) == 0) {
		err = rx_wait(poll_count, is_blocking);
		//AlexV:Avoid from going to sleep, for the blocked socket of course, since
		// progress engine may consume an arrived credit and it will not wakeup the
		//transmit thread.
		if (unlikely(err < 0)) {
			return 0;
		}
		if (unlikely(g_b_exit)) {
			errno = EINTR;
			return 0;
		}
		if (is_blocking) {
			/* force out TCP data to avoid spinning in this loop
			 * in case data is not seen on rx
			 */
			tcp_output(&m_pcb);
			poll_count = 0;
		}
	}
	si_tcp_logfunc("end sz=%d rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
	return sz;
}

bool sockinfo_tcp::check_dummy_send_conditions(const int flags, const iovec* p_iov, const ssize_t sz_iov)
{
	// Calculate segment max length
	uint8_t optflags = TF_SEG_OPTS_DUMMY_MSG;
	uint16_t mss_local = MIN(m_pcb.mss, m_pcb.snd_wnd_max / 2);
	mss_local = mss_local ? mss_local : m_pcb.mss;

	#if LWIP_TCP_TIMESTAMPS
		if ((m_pcb.flags & TF_TIMESTAMP)) {
			optflags |= TF_SEG_OPTS_TS;
			mss_local = MAX(mss_local, LWIP_TCP_OPT_LEN_TS + 1);
		}
	#endif /* LWIP_TCP_TIMESTAMPS */

	u16_t max_len = mss_local - LWIP_TCP_OPT_LENGTH(optflags);

	// Calculate window size
	u32_t wnd = MIN(m_pcb.snd_wnd, m_pcb.cwnd);

	return !m_pcb.unsent && // Unsent queue should be empty
		!(flags & MSG_MORE) && // Verify MSG_MORE flags is not set
		sz_iov == 1 && // We want to prevent a case in which we call tcp_write() for scatter/gather element.
		p_iov->iov_len && // We have data to sent
		p_iov->iov_len <= max_len && // Data will not be split into more then one segment
		wnd && // Window is not empty
		(p_iov->iov_len + m_pcb.snd_lbb - m_pcb.lastack) <= wnd; // Window allows the dummy packet it to be sent
}

void sockinfo_tcp::put_agent_msg(void *arg)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)arg;
	struct vma_msg_state data;

	/* Ignore listen socket at the moment */
	if (p_si_tcp->is_server() || get_tcp_state(&p_si_tcp->m_pcb) == LISTEN) {
		return ;
	}

	data.hdr.code = VMA_MSG_STATE;
	data.hdr.ver = VMA_AGENT_VER;
	data.hdr.pid = getpid();
	data.fid = p_si_tcp->get_fd();
	data.state = get_tcp_state(&p_si_tcp->m_pcb);
	data.type = SOCK_STREAM;
	data.src_ip = p_si_tcp->m_bound.get_in_addr();
	data.src_port = p_si_tcp->m_bound.get_in_port();
	data.dst_ip = p_si_tcp->m_connected.get_in_addr();
	data.dst_port = p_si_tcp->m_connected.get_in_port();

	g_p_agent->put((const void*)&data, sizeof(data), (intptr_t)data.fid);
}

ssize_t sockinfo_tcp::tx(const tx_call_t call_type, const iovec* p_iov, const ssize_t sz_iov, const int flags, const struct sockaddr *__to, const socklen_t __tolen)
{
	int errno_tmp = errno;
	int total_tx = 0;
	unsigned tx_size;
	err_t err;
	unsigned pos = 0;
	int ret = 0;
	int poll_count = 0;
	bool is_dummy = IS_DUMMY_PACKET(flags);
	bool block_this_run = BLOCK_THIS_RUN(m_b_blocking, flags);

	/* Let allow OS to process all invalid scenarios to avoid any
	 * inconsistencies in setting errno values
	 */
	if (unlikely((m_sock_offload != TCP_SOCK_LWIP) ||
			(NULL == p_iov) ||
			(0 >= sz_iov) ||
			(NULL == p_iov[0].iov_base))) {
		goto tx_packet_to_os;
		}

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_START;
#endif

retry_is_ready:

	if (unlikely(!is_rts())) {

		if (m_conn_state == TCP_CONN_CONNECTING) {
			si_tcp_logdbg("TX while async-connect on socket go to poll");
			rx_wait_helper(poll_count, false);
			if (m_conn_state == TCP_CONN_CONNECTED) goto retry_is_ready;
			si_tcp_logdbg("TX while async-connect on socket return EAGAIN");
			errno = EAGAIN;
		} else if (m_conn_state == TCP_CONN_RESETED) {
			si_tcp_logdbg("TX on reseted socket");
			errno = ECONNRESET;
		} else if (m_conn_state == TCP_CONN_ERROR) {
			si_tcp_logdbg("TX on connection failed socket");
			errno = ECONNREFUSED;
		} else {
			si_tcp_logdbg("TX on disconnected socket");
			errno = EPIPE;
		}

#ifdef VMA_TIME_MEASURE
		INC_ERR_TX_COUNT;
#endif

		return -1;
	}
	si_tcp_logfunc("tx: iov=%p niovs=%d dummy=%d", p_iov, sz_iov, is_dummy);

	if (unlikely(m_sysvar_rx_poll_on_tx_tcp)) {
		rx_wait_helper(poll_count, false);
	}

	lock_tcp_con();

	if (unlikely(is_dummy) && !check_dummy_send_conditions(flags, p_iov, sz_iov)) {
		unlock_tcp_con();
		errno = EAGAIN;
		return -1;
	}

#ifdef DEFINED_TCP_TX_WND_AVAILABILITY
	if (!tcp_is_wnd_available(&m_pcb, p_iov[0].iov_len)) {
		unlock_tcp_con();
		errno = EAGAIN;
		return -1;
	}
#endif

	for (int i = 0; i < sz_iov; i++) {
		si_tcp_logfunc("iov:%d base=%p len=%d", i, p_iov[i].iov_base, p_iov[i].iov_len);

		pos = 0;
		while (pos < p_iov[i].iov_len) {
			tx_size = tcp_sndbuf(&m_pcb);

			/* Process a case when space is not available at the sending socket
			 * to hold the message to be transmitted
			 * Nonblocking socket:
			 *    - no data is buffered: return (-1) and EAGAIN
			 *    - some data is buffered: return number of bytes ready to be sent
			 * Blocking socket:
			 *    - block until space is available
			 */
			if (tx_size == 0) {
				if (unlikely(!is_rts())) {
					si_tcp_logdbg("TX on disconnected socket");
					ret = -1;
					errno = ECONNRESET;
					goto err;
				}
				//force out TCP data before going on wait()
				tcp_output(&m_pcb);

				/* Set return values for nonblocking socket and finish processing */
				if (!block_this_run) {
					// non blocking socket should return inorder not to tx_wait()
					if (total_tx > 0) {
						m_tx_consecutive_eagain_count = 0;
						goto done;
					}
					else {
						m_tx_consecutive_eagain_count++;
						if (m_tx_consecutive_eagain_count >= TX_CONSECUTIVE_EAGAIN_THREASHOLD) {
							// in case of zero sndbuf and non-blocking just try once polling CQ for ACK
							rx_wait(poll_count, false);
							m_tx_consecutive_eagain_count = 0;
						}
						ret = -1;
						errno = EAGAIN;
						goto err;
					}
				}

				tx_size = tx_wait(ret, true);
			}

			if (tx_size > p_iov[i].iov_len - pos) {
				tx_size = p_iov[i].iov_len - pos;
			}
retry_write:
			if (unlikely(!is_rts())) {
				si_tcp_logdbg("TX on disconnected socket");
				ret = -1;
				errno = ECONNRESET;
				goto err;
			}
			if (unlikely(g_b_exit)) {
				ret = -1;
				errno = EINTR;
				si_tcp_logdbg("returning with: EINTR");
				goto err;
			}
			err = tcp_write(&m_pcb, (char *)p_iov[i].iov_base + pos, tx_size, is_dummy);
			if (unlikely(err != ERR_OK)) {
				if (unlikely(err == ERR_CONN)) { // happens when remote drops during big write
					si_tcp_logdbg("connection closed: tx'ed = %d", total_tx);
					shutdown(SHUT_WR);
					if (total_tx > 0) {
						goto done;
					}
					errno = EPIPE;
					unlock_tcp_con();
#ifdef VMA_TIME_MEASURE
					INC_ERR_TX_COUNT;
#endif					
					return -1;
				}
				if (unlikely(err != ERR_MEM)) {
					// we should not get here...
					BULLSEYE_EXCLUDE_BLOCK_START
					si_tcp_logpanic("tcp_write return: %d", err);
					BULLSEYE_EXCLUDE_BLOCK_END
				}
				/* Set return values for nonblocking socket and finish processing */
				if (!block_this_run) {
					if (total_tx > 0) {
						goto done;
					} else {
						ret = -1;
						errno = EAGAIN;
						goto err;
					}
				}

				rx_wait(poll_count, true);

				//AlexV:Avoid from going to sleep, for the blocked socket of course, since
				// progress engine may consume an arrived credit and it will not wakeup the
				//transmit thread.
				poll_count = 0;

				goto retry_write;
			}
			pos += tx_size;
			total_tx += tx_size;
		}	
	}
done:	

	tcp_output(&m_pcb); // force data out

	if (unlikely(is_dummy)) {
		m_p_socket_stats->counters.n_tx_dummy++;
	} else if (total_tx) {
		m_p_socket_stats->counters.n_tx_sent_byte_count += total_tx;
		m_p_socket_stats->counters.n_tx_sent_pkt_count++;
		m_p_socket_stats->n_tx_ready_byte_count += total_tx;
	}

	unlock_tcp_con();

#ifdef VMA_TIME_MEASURE	
	TAKE_T_TX_END;
#endif
	/* Restore errno on function entry in case success */
	errno = errno_tmp;

	return total_tx; 

err:
#ifdef VMA_TIME_MEASURE
	INC_ERR_TX_COUNT;
#endif

	// nothing send  nb mode or got some other error
	if (errno == EAGAIN)
		m_p_socket_stats->counters.n_tx_drops++;
	else
		m_p_socket_stats->counters.n_tx_errors++;
	unlock_tcp_con();
	return ret;

tx_packet_to_os:
#ifdef VMA_TIME_MEASURE
	INC_GO_TO_OS_TX_COUNT;
#endif

	ret = socket_fd_api::tx_os(call_type, p_iov, sz_iov, flags, __to, __tolen);
	save_stats_tx_os(ret);
	return ret;
}

#ifdef DEFINED_TSO
err_t sockinfo_tcp::ip_output(struct pbuf *p, void* v_p_conn, uint16_t flags)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)v_p_conn)->my_container);
	dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
	int max_count = p_si_tcp->m_pcb.tso.max_send_sge;
	tcp_iovec lwip_iovec[max_count];
	vma_send_attr attr = {(vma_wr_tx_packet_attr)0, 0};
	int count = 0;

	/* maximum number of sge can not exceed this value */
	while (p && (count < max_count)) {
		lwip_iovec[count].iovec.iov_base = p->payload;
		lwip_iovec[count].iovec.iov_len = p->len;
		lwip_iovec[count].p_desc = (mem_buf_desc_t*)p;
		p = p->next;
		count++;
	}

	/* Sanity check */
	if (unlikely(p)) {
		vlog_printf(VLOG_ERROR, "Number of buffers in request exceed  %d, so silently dropped.", max_count);
		return ERR_OK;
	}

	attr.flags = (vma_wr_tx_packet_attr)flags;
	attr.mss = p_si_tcp->m_pcb.mss;
	if (likely((p_dst->is_valid()))) {
		p_dst->fast_send((struct iovec *)lwip_iovec, count, attr);
	} else {
		p_dst->slow_send((struct iovec *)lwip_iovec, count, attr, p_si_tcp->m_so_ratelimit);
	}

	if (p_dst->try_migrate_ring(p_si_tcp->m_tcp_con_lock)) {
		p_si_tcp->m_p_socket_stats->counters.n_tx_migrations++;
	}

	if (is_set(attr.flags, VMA_TX_PACKET_REXMIT)) {
		p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;
	}

	return ERR_OK;
}

err_t sockinfo_tcp::ip_output_syn_ack(struct pbuf *p, void* v_p_conn, uint16_t flags)
{
	iovec iovec[64];
	struct iovec* p_iovec = iovec;
	tcp_iovec tcp_iovec_temp; //currently we pass p_desc only for 1 size iovec, since for bigger size we allocate new buffers
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)v_p_conn)->my_container);
	dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
	int count = 1;
	vma_wr_tx_packet_attr attr;

	//ASSERT_NOT_LOCKED(p_si_tcp->m_tcp_con_lock);

	if (likely(!p->next)) { // We should hit this case 99% of cases
		tcp_iovec_temp.iovec.iov_base = p->payload;
		tcp_iovec_temp.iovec.iov_len = p->len;
		tcp_iovec_temp.p_desc = (mem_buf_desc_t*)p;
		__log_dbg("p_desc=%p,p->len=%d ", p, p->len);
		p_iovec = (struct iovec*)&tcp_iovec_temp;
	} else {
		for (count = 0; count < 64 && p; ++count) {
			iovec[count].iov_base = p->payload;
			iovec[count].iov_len = p->len;
			p = p->next;
		}

		// We don't expect pbuf chain at all
		if (p) {
			vlog_printf(VLOG_ERROR, "pbuf chain size > 64!!! silently dropped.");
			return ERR_OK;
		}
	}

	attr = (vma_wr_tx_packet_attr)flags;
	if (is_set(attr, VMA_TX_PACKET_REXMIT))
		p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;

	((dst_entry_tcp*)p_dst)->slow_send_neigh(p_iovec, count, p_si_tcp->m_so_ratelimit);

	return ERR_OK;
}
#else
err_t sockinfo_tcp::ip_output(struct pbuf *p, void* v_p_conn, int is_rexmit, uint8_t is_dummy)
{
	iovec iovec[64];
	struct iovec* p_iovec = iovec;
	tcp_iovec tcp_iovec_temp; //currently we pass p_desc only for 1 size iovec, since for bigger size we allocate new buffers
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)v_p_conn)->my_container);
	dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
	int count = 1;

	if (likely(!p->next)) { // We should hit this case 99% of cases
		tcp_iovec_temp.iovec.iov_base = p->payload;
		tcp_iovec_temp.iovec.iov_len = p->len;
		tcp_iovec_temp.p_desc = (mem_buf_desc_t*)p;
		p_iovec = (struct iovec*)&tcp_iovec_temp;
	} else {
		for (count = 0; count < 64 && p; ++count) {
			iovec[count].iov_base = p->payload;
			iovec[count].iov_len = p->len;
			p = p->next;
		}

		// We don't expect pbuf chain at all
		if (p) {
			vlog_printf(VLOG_ERROR, "pbuf chain size > 64!!! silently dropped.");
			return ERR_OK;
		}
	}

	if (likely((p_dst->is_valid()))) {
		p_dst->fast_send(p_iovec, count, is_dummy, false, is_rexmit);
	} else {
		p_dst->slow_send(p_iovec, count, is_dummy, p_si_tcp->m_so_ratelimit, false, is_rexmit);
	}

	if (p_dst->try_migrate_ring(p_si_tcp->m_tcp_con_lock)) {
		p_si_tcp->m_p_socket_stats->counters.n_tx_migrations++;
	}

	if (is_rexmit) {
		p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;
	}

	return ERR_OK;
}

err_t sockinfo_tcp::ip_output_syn_ack(struct pbuf *p, void* v_p_conn, int is_rexmit, uint8_t is_dummy)
{
	NOT_IN_USE(is_dummy);

	iovec iovec[64];
	struct iovec* p_iovec = iovec;
	tcp_iovec tcp_iovec_temp; //currently we pass p_desc only for 1 size iovec, since for bigger size we allocate new buffers
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)v_p_conn)->my_container);
	dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
	int count = 1;

	//ASSERT_NOT_LOCKED(p_si_tcp->m_tcp_con_lock);

	if (likely(!p->next)) { // We should hit this case 99% of cases
		tcp_iovec_temp.iovec.iov_base = p->payload;
		tcp_iovec_temp.iovec.iov_len = p->len;
		tcp_iovec_temp.p_desc = (mem_buf_desc_t*)p;
		__log_dbg("p_desc=%p,p->len=%d ", p, p->len);
		p_iovec = (struct iovec*)&tcp_iovec_temp;
	} else {
		for (count = 0; count < 64 && p; ++count) {
			iovec[count].iov_base = p->payload;
			iovec[count].iov_len = p->len;
			p = p->next;
		}

		// We don't expect pbuf chain at all
		if (p) {
			vlog_printf(VLOG_ERROR, "pbuf chain size > 64!!! silently dropped.");
			return ERR_OK;
		}
	}

	if (is_rexmit)
		p_si_tcp->m_p_socket_stats->counters.n_tx_retransmits++;

	((dst_entry_tcp*)p_dst)->slow_send_neigh(p_iovec, count, p_si_tcp->m_so_ratelimit);

	return ERR_OK;
}
#endif /* DEFINED_TSO */

/*static*/void sockinfo_tcp::tcp_state_observer(void* pcb_container, enum tcp_state new_state)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)pcb_container;
	p_si_tcp->m_p_socket_stats->tcp_state = new_state;

	/* Update daemon about actual state for offloaded connection */
	if (likely(p_si_tcp->m_sock_offload == TCP_SOCK_LWIP)) {
		p_si_tcp->put_agent_msg((void *)p_si_tcp);
	}
}

uint16_t sockinfo_tcp::get_route_mtu(struct tcp_pcb *pcb)
{
	sockinfo_tcp *tcp_sock = (sockinfo_tcp *)pcb->my_container;
	// in case of listen m_p_connected_dst_entry is still NULL
	if (tcp_sock->m_p_connected_dst_entry) {
		return tcp_sock->m_p_connected_dst_entry->get_route_mtu();
	}
	route_result res;

	g_p_route_table_mgr->route_resolve(route_rule_table_key(pcb->local_ip.addr, pcb->remote_ip.addr, pcb->tos), res);

	if (res.mtu) {
		vlog_printf(VLOG_DEBUG, "Using route mtu %u\n", res.mtu);
		return res.mtu;
	}
	net_device_val* ndv = g_p_net_device_table_mgr->get_net_device_val(res.p_src);
	if (ndv && ndv->get_mtu() > 0) {
		return ndv->get_mtu();
	}
	vlog_printf(VLOG_DEBUG, "Could not find device, mtu 0 is used\n");
	return 0;
}

void sockinfo_tcp::err_lwip_cb(void *pcb_container, err_t err)
{

	if (!pcb_container) return;
	sockinfo_tcp *conn = (sockinfo_tcp *)pcb_container;
	__log_dbg("[fd=%d] sock=%p lwip_pcb=%p err=%d\n", conn->m_fd, conn, &(conn->m_pcb), err);

	if (get_tcp_state(&conn->m_pcb) == LISTEN && err == ERR_RST) {
		vlog_printf(VLOG_ERROR, "listen socket should not receive RST");
		return;
	}

	if (conn->m_parent != NULL) {
		//in case we got RST before we accepted the connection
		int delete_fd = 0;
		sockinfo_tcp *parent = conn->m_parent;
		bool locked_by_me = false;
		if (conn->m_tcp_con_lock.is_locked_by_me()) {
			locked_by_me = true;
			conn->unlock_tcp_con();
		}
		if ((delete_fd = parent->handle_child_FIN(conn))) {
			//close will clean sockinfo_tcp object and the opened OS socket
			close(delete_fd);
			if (locked_by_me)
				conn->lock_tcp_con(); //todo sock and fd_collection destruction race? if so, conn might be invalid? delay close to internal thread?
			return;
		}
		if (locked_by_me)
			conn->lock_tcp_con();
	}

	/*
	 * In case we got RST from the other end we need to marked this socket as ready to read for epoll
	 */
	if ((conn->m_sock_state == TCP_SOCK_CONNECTED_RD
		|| conn->m_sock_state == TCP_SOCK_CONNECTED_RDWR
		|| conn->m_sock_state == TCP_SOCK_ASYNC_CONNECT
		|| conn->m_conn_state == TCP_CONN_CONNECTING)
		&& PCB_IN_ACTIVE_STATE(&conn->m_pcb)) {
		if (err == ERR_RST) {
			if (conn->m_sock_state == TCP_SOCK_ASYNC_CONNECT)
				NOTIFY_ON_EVENTS(conn, (EPOLLIN|EPOLLERR|EPOLLHUP));
			else
				NOTIFY_ON_EVENTS(conn, (EPOLLIN|EPOLLERR|EPOLLHUP|EPOLLRDHUP));
		/* TODO what about no route to host type of errors, need to add EPOLLERR in this case ? */
		} else { // ERR_TIMEOUT
			NOTIFY_ON_EVENTS(conn, (EPOLLIN|EPOLLHUP));
		}


		/* SOCKETXTREME comment:
		 * Add this fd to the ready fd list
		 * Note: No issue is expected in case socketxtreme_poll() usage because 'pv_fd_ready_array' is null
		 * in such case and as a result update_fd_array() call means nothing
		 */
		
		io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);
	}

	conn->m_conn_state = TCP_CONN_FAILED;
	if (err == ERR_TIMEOUT) {
		conn->m_conn_state = TCP_CONN_TIMEOUT;
		conn->m_error_status = ETIMEDOUT;
	} else if (err == ERR_RST) {
		if (conn->m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
			conn->m_conn_state = TCP_CONN_ERROR;
			conn->m_error_status = ECONNREFUSED;
		} else {
			conn->m_conn_state = TCP_CONN_RESETED;
		}
	}

	//Avoid binding twice in case of calling connect again after previous call failed.
	if (conn->m_sock_state != TCP_SOCK_BOUND) { //TODO: maybe we need to exclude more states?
		conn->m_sock_state = TCP_SOCK_INITED;
	}

	/* In general VMA should avoid calling unregister_timer_event() for the same timer handle twice.
	 * It is protected by checking m_timer_handle for NULL value that should be under lock.
	 * In order to save locking time a quick check is done first to ensure that indeed the specific
	 * timer has not been freed (avoiding the lock/unlock).
	 * The 2nd check is to avoid a race of the timer been freed while the lock has been taken.
	 */
	if (conn->m_timer_handle) {
		conn->lock_tcp_con();
		if (conn->m_timer_handle) {
			g_p_event_handler_manager->unregister_timer_event(conn, conn->m_timer_handle);
			conn->m_timer_handle = NULL;
		}
		conn->unlock_tcp_con();
	}

	conn->do_wakeup();
}

bool sockinfo_tcp::process_peer_ctl_packets(vma_desc_list_t &peer_packets)
{
	// 2.1 loop on packets of a peer
	while (!peer_packets.empty()) {
		// 2.1.1 get packet from list and find its pcb
		mem_buf_desc_t* desc = peer_packets.front();

		if (0 != m_tcp_con_lock.trylock()) {
			/* coverity[missing_unlock] */
			return false;
		}

		struct tcp_pcb *pcb = get_syn_received_pcb(desc->rx.src.sin_addr.s_addr,
				desc->rx.src.sin_port,
				desc->rx.dst.sin_addr.s_addr,
				desc->rx.dst.sin_port);

		// 2.1.2 get the pcb and sockinfo
		if (!pcb) {
			pcb = &m_pcb;
		}
		sockinfo_tcp *sock = (sockinfo_tcp*)pcb->my_container;

		if (sock == this) { // my socket - consider the backlog for the case I am listen socket
			if (m_syn_received.size() >= (size_t)m_backlog && desc->rx.tcp.p_tcp_h->syn) {
				m_tcp_con_lock.unlock();
				break; // skip to next peer
			} else if (safe_mce_sys().tcp_max_syn_rate && desc->rx.tcp.p_tcp_h->syn) {
				static tscval_t tsc_delay = get_tsc_rate_per_second() / safe_mce_sys().tcp_max_syn_rate;
				tscval_t tsc_now;
				gettimeoftsc(&tsc_now);
				if (tsc_now - m_last_syn_tsc < tsc_delay) {
					m_tcp_con_lock.unlock();
					break;
				} else {
					m_last_syn_tsc = tsc_now;
				}
			}
		}
		else { // child socket from a listener context - switch to child lock
			m_tcp_con_lock.unlock();
			if (sock->m_tcp_con_lock.trylock()) {
				break; // skip to next peer
			}
		}

		// 2.1.3 process the packet and remove it from list
		peer_packets.pop_front();
		sock->m_vma_thr = true;
		// -- start loop
		desc->inc_ref_count();
		L3_level_tcp_input((pbuf *)desc, pcb);

		if (desc->dec_ref_count() <= 1)
			sock->m_rx_ctl_reuse_list.push_back(desc); // under sock's lock
		// -- end loop
		sock->m_vma_thr = false;

		sock->m_tcp_con_lock.unlock();

	}
	return true;
}

void sockinfo_tcp::process_my_ctl_packets()
{
	si_tcp_logfunc("");

	// 0. fast swap of m_rx_ctl_packets_list with temp_list under lock
	vma_desc_list_t temp_list;

	m_rx_ctl_packets_list_lock.lock();
	temp_list.splice_tail(m_rx_ctl_packets_list);
	m_rx_ctl_packets_list_lock.unlock();


	if (m_backlog == INT_MAX) { // this is a child - no need to demux packets
		process_peer_ctl_packets(temp_list);

		if (!temp_list.empty()) {
			m_rx_ctl_packets_list_lock.lock();
			m_rx_ctl_packets_list.splice_head(temp_list);
			m_rx_ctl_packets_list_lock.unlock();
		}
		return;
	}

	// 1. demux packets in the listener list to map of list per peer (for child this will be skipped)
	while (!temp_list.empty()) {
		mem_buf_desc_t* desc = temp_list.get_and_pop_front();
		peer_key pk(desc->rx.src.sin_addr.s_addr, desc->rx.src.sin_port);


		static const unsigned int MAX_SYN_RCVD = m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE ? safe_mce_sys().sysctl_reader.get_tcp_max_syn_backlog() : 0;
		// NOTE: currently, in case tcp_ctl_thread is disabled, only established backlog is supported (no syn-rcvd backlog)
		unsigned int num_con_waiting = m_rx_peer_packets.size();

		if (num_con_waiting < MAX_SYN_RCVD) {
			m_rx_peer_packets[pk].push_back(desc);
		}
		else { // map is full
			peer_map_t::iterator iter = m_rx_peer_packets.find(pk);
			if(iter != m_rx_peer_packets.end())
			{
				// entry already exists, we can concatenate our packet
				iter->second.push_back(desc);
			}
			else {
				// drop the packet
				if (desc->dec_ref_count() <= 1) {
					si_tcp_logdbg("CTL packet drop. established-backlog=%d (limit=%d) num_con_waiting=%d (limit=%d)",
							(int)m_syn_received.size(), m_backlog, num_con_waiting, MAX_SYN_RCVD);
					m_rx_ctl_reuse_list.push_back(desc);
				}
			}
		}
	}

	// 2. loop on map of peers and process list of packets per peer
	peer_map_t::iterator itr = m_rx_peer_packets.begin();
	while (itr != m_rx_peer_packets.end()) {
		vma_desc_list_t &peer_packets = itr->second;
		if (!process_peer_ctl_packets(peer_packets))
			return;
		// prepare for next map iteration
		if (peer_packets.empty())
			m_rx_peer_packets.erase(itr++); // // advance itr before invalidating it by erase (itr++ returns the value before advance)
		else
			++itr;
	}
}

void sockinfo_tcp::process_children_ctl_packets()
{
	// handle children
	while (!m_ready_pcbs.empty()) {
		if (m_tcp_con_lock.trylock()) {
			return;
		}
		ready_pcb_map_t::iterator itr = m_ready_pcbs.begin();
		if (itr == m_ready_pcbs.end()) {
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_tcp_con_lock.unlock();
			break;
		}
		sockinfo_tcp *sock = (sockinfo_tcp*)itr->first->my_container;
		/* coverity[double_unlock] TODO: RM#1049980 */
		m_tcp_con_lock.unlock();

		if (sock->m_tcp_con_lock.trylock()) {
			break;
		}
		sock->m_vma_thr = true;

		while (!sock->m_rx_ctl_packets_list.empty()) {
			sock->m_rx_ctl_packets_list_lock.lock();
			if (sock->m_rx_ctl_packets_list.empty()) {
				sock->m_rx_ctl_packets_list_lock.unlock();
				break;
			}
			mem_buf_desc_t* desc = sock->m_rx_ctl_packets_list.get_and_pop_front();
			sock->m_rx_ctl_packets_list_lock.unlock();
			desc->inc_ref_count();
			L3_level_tcp_input((pbuf *)desc, &sock->m_pcb);
			if (desc->dec_ref_count() <= 1) //todo reuse needed?
				sock->m_rx_ctl_reuse_list.push_back(desc);
		}
		sock->m_vma_thr = false;
		sock->m_tcp_con_lock.unlock();

		if (m_tcp_con_lock.trylock()) {
			break;
		}

		/* coverity[double_lock] TODO: RM#1049980 */
		sock->m_rx_ctl_packets_list_lock.lock();
		if (sock->m_rx_ctl_packets_list.empty())
			m_ready_pcbs.erase(&sock->m_pcb);
		sock->m_rx_ctl_packets_list_lock.unlock();

		/* coverity[double_unlock] TODO: RM#1049980 */
		m_tcp_con_lock.unlock();
	}
}

void sockinfo_tcp::process_reuse_ctl_packets()
{
	while (!m_rx_ctl_reuse_list.empty()) {
		if (m_tcp_con_lock.trylock()) {
			return;
		}
		mem_buf_desc_t* desc = m_rx_ctl_reuse_list.get_and_pop_front();
		reuse_buffer(desc);
		/* coverity[double_unlock] TODO: RM#1049980 */
		m_tcp_con_lock.unlock();
	}
}

void sockinfo_tcp::process_rx_ctl_packets()
{
	si_tcp_logfunc("");

	process_my_ctl_packets();
	process_children_ctl_packets();
	process_reuse_ctl_packets();
}

//Execute TCP timers of this connection
void sockinfo_tcp::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	si_tcp_logfunc("");

	if (m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE)
		process_rx_ctl_packets();

	if (m_sysvar_internal_thread_tcp_timer_handling == INTERNAL_THREAD_TCP_TIMER_HANDLING_DEFERRED) {
		// DEFERRED. if Internal thread is here first and m_timer_pending is false it jsut 
		// sets it as true for its next iteration (within 100ms), letting 
		// application threads have a chance of running tcp_timer()
		if (m_timer_pending) {
			if (m_tcp_con_lock.trylock()) {
				return;
			}
			tcp_timer();
			m_tcp_con_lock.unlock();
		}
		m_timer_pending = true;
	}
	else { // IMMEDIATE
		// Set the pending flag before getting the lock, so in the rare case of
		// a race with unlock_tcp_con(), the timer will be called twice. If we set
		// the flag after trylock(), the timer may not be called in case of a race.
		
		// any thread (internal or application) will try locking 
		// and running the tcp_timer
		m_timer_pending = true;
		if (m_tcp_con_lock.trylock()) {
			return;
		}

		tcp_timer();
		m_tcp_con_lock.unlock();
	}
}

void sockinfo_tcp::abort_connection()
{
	tcp_abort(&(m_pcb));
}

int sockinfo_tcp::handle_child_FIN(sockinfo_tcp* child_conn)
{
	lock_tcp_con();

	sock_list_t::iterator conns_iter;
	for(conns_iter = m_accepted_conns.begin(); conns_iter != m_accepted_conns.end(); conns_iter++) {
		if (*(conns_iter) == child_conn) {
			unlock_tcp_con();
			return 0; //don't close conn, it can be accepted
		}
	}

	if (m_ready_pcbs.find(&child_conn->m_pcb) != m_ready_pcbs.end()) {
		m_ready_pcbs.erase(&child_conn->m_pcb);
	}

	// remove the connection from m_syn_received and close it by caller
	class flow_tuple key;
	sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(child_conn->m_pcb));
	if (!m_syn_received.erase(key)) {
		si_tcp_logfunc("Can't find the established pcb in syn received list");
	}
	else {
		si_tcp_logdbg("received FIN before accept() was called");
		m_received_syn_num--;
		child_conn->m_parent = NULL;
		unlock_tcp_con();
		child_conn->lock_tcp_con();
		child_conn->abort_connection();
		child_conn->unlock_tcp_con();
		return (child_conn->get_fd());
	}
	unlock_tcp_con();
	return 0;
}

err_t sockinfo_tcp::ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t ack)
{
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;

	NOT_IN_USE(tpcb); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	assert((uintptr_t)tpcb->my_container == (uintptr_t)arg);

	vlog_func_enter();

	ASSERT_LOCKED(conn->m_tcp_con_lock);

	conn->m_p_socket_stats->n_tx_ready_byte_count -= ack;

	NOTIFY_ON_EVENTS(conn, EPOLLOUT);

	vlog_func_exit();

	return ERR_OK;
}

err_t sockinfo_tcp::rx_lwip_cb(void *arg, struct tcp_pcb *pcb,
                        struct pbuf *p, err_t err)
{

	sockinfo_tcp *conn = (sockinfo_tcp *)arg;
	uint32_t bytes_to_tcp_recved, non_tcp_receved_bytes_remaining, bytes_to_shrink;
	int rcv_buffer_space;

	NOT_IN_USE(pcb);
	assert((uintptr_t)pcb->my_container == (uintptr_t)arg);

	vlog_func_enter();

	ASSERT_LOCKED(conn->m_tcp_con_lock);

	//if is FIN
	if (unlikely(!p)) {

		if (conn->is_server()) {
			vlog_printf(VLOG_ERROR, "listen socket should not receive FIN");
			return ERR_OK;
		}

		NOTIFY_ON_EVENTS(conn, EPOLLIN|EPOLLRDHUP);
				
		/* SOCKETXTREME comment:
		 * Add this fd to the ready fd list
		 * Note: No issue is expected in case socketxtreme_poll() usage because 'pv_fd_ready_array' is null
		 * in such case and as a result update_fd_array() call means nothing
		 */
		io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);
		conn->do_wakeup();

		//tcp_close(&(conn->m_pcb));
		//TODO: should be a move into half closed state (shut rx) instead of complete close
		tcp_shutdown(&(conn->m_pcb), 1, 0);
		__log_dbg("[fd=%d] null pbuf sock(%p %p) err=%d\n", conn->m_fd, &(conn->m_pcb), pcb, err);

		if (conn->is_rts() || ((conn->m_sock_state == TCP_SOCK_ASYNC_CONNECT) && (conn->m_conn_state == TCP_CONN_CONNECTED))) {
			conn->m_sock_state = TCP_SOCK_CONNECTED_WR;
		} else {
			conn->m_sock_state = TCP_SOCK_BOUND;
		}
		/*
		 * We got FIN, means that we will not receive any new data
		 * Need to remove the callback functions
		 */
		tcp_recv(&(conn->m_pcb), sockinfo_tcp::rx_drop_lwip_cb);

		if (conn->m_parent != NULL) {
			//in case we got FIN before we accepted the connection
			int delete_fd = 0;
			sockinfo_tcp *parent = conn->m_parent;
			/* TODO need to add some refcount inside parent in case parent and child are closed together*/
			conn->unlock_tcp_con();
			if ((delete_fd = parent->handle_child_FIN(conn))) {
				//close will clean sockinfo_tcp object and the opened OS socket
				close(delete_fd);
				conn->lock_tcp_con(); //todo sock and fd_collection destruction race? if so, conn might be invalid? delay close to internal thread?
				return ERR_ABRT;
			}
			conn->lock_tcp_con();
		}
		return ERR_OK;
	}
	if (unlikely(err != ERR_OK)) {
		// notify io_mux
		NOTIFY_ON_EVENTS(conn, EPOLLERR);
		
		conn->do_wakeup();
		vlog_printf(VLOG_ERROR, "%s:%d %s\n", __func__, __LINE__, "recv error!!!\n");
		pbuf_free(p);
		conn->m_sock_state = TCP_SOCK_INITED;
		return err;
	}
	mem_buf_desc_t *p_first_desc = (mem_buf_desc_t *)p;

	p_first_desc->rx.sz_payload = p->tot_len;
	p_first_desc->rx.n_frags = 0;

	mem_buf_desc_t *p_curr_desc = p_first_desc;

	pbuf *p_curr_buff = p;
	conn->m_connected.get_sa(p_first_desc->rx.src);

	while (p_curr_buff) {
		p_curr_desc->rx.context = conn;
		p_first_desc->rx.n_frags++;
		p_curr_desc->rx.frag.iov_base = p_curr_buff->payload;
		p_curr_desc->rx.frag.iov_len = p_curr_buff->len;
		p_curr_desc->p_next_desc = (mem_buf_desc_t *)p_curr_buff->next;
		conn->process_timestamps(p_curr_desc);
		p_curr_buff = p_curr_buff->next;
		p_curr_desc = p_curr_desc->p_next_desc;
	}
		
	vma_recv_callback_retval_t callback_retval = VMA_PACKET_RECV;
	
	if (conn->m_rx_callback && !conn->m_vma_thr && !conn->m_n_rx_pkt_ready_list_count) {
		mem_buf_desc_t *tmp;
		vma_info_t pkt_info;
		int nr_frags = 0;

		pkt_info.struct_sz = sizeof(pkt_info);
		pkt_info.packet_id = (void*)p_first_desc;
		pkt_info.src = &p_first_desc->rx.src;
		pkt_info.dst = &p_first_desc->rx.dst;
		pkt_info.socket_ready_queue_pkt_count = conn->m_p_socket_stats->n_rx_ready_pkt_count;
		pkt_info.socket_ready_queue_byte_count = conn->m_p_socket_stats->n_rx_ready_byte_count;

		if (conn->m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
			pkt_info.hw_timestamp = p_first_desc->rx.timestamps.hw;
		}
		if (p_first_desc->rx.timestamps.sw.tv_sec) {
			pkt_info.sw_timestamp = p_first_desc->rx.timestamps.sw;
		}

		// fill io vector array with data buffer pointers
		iovec iov[p_first_desc->rx.n_frags];
		nr_frags = 0;
		for (tmp = p_first_desc; tmp; tmp = tmp->p_next_desc) {
			iov[nr_frags++] = tmp->rx.frag;
		}

		// call user callback
		callback_retval = conn->m_rx_callback(conn->m_fd, nr_frags, iov, &pkt_info, conn->m_rx_callback_context);
	}
	
	if (callback_retval == VMA_PACKET_DROP) {
		conn->m_rx_cb_dropped_list.push_back(p_first_desc);

	// In ZERO COPY case we let the user's application manage the ready queue
	}
	else {
		if (conn->is_socketxtreme()) {
			/* Update vma_completion with
			 * VMA_SOCKETXTREME_PACKET related data
			 */
			struct vma_completion_t *completion;
			struct vma_buff_t *buf_lst;

			if (conn->m_socketxtreme.completion) {
				completion = conn->m_socketxtreme.completion;
				buf_lst = conn->m_socketxtreme.last_buff_lst;
			} else {
				completion = &conn->m_socketxtreme.ec.completion;
				buf_lst = conn->m_socketxtreme.ec.last_buff_lst;
			}

			if (!buf_lst) {
				completion->packet.buff_lst = (struct vma_buff_t*)p_first_desc;
				completion->packet.total_len = p->tot_len;
				completion->src = p_first_desc->rx.src;
				completion->packet.num_bufs = p_first_desc->rx.n_frags;

                	        if (conn->m_n_tsing_flags & SOF_TIMESTAMPING_RAW_HARDWARE) {
        	                        completion->packet.hw_timestamp = p_first_desc->rx.timestamps.hw;
	                        }

				NOTIFY_ON_EVENTS(conn, VMA_SOCKETXTREME_PACKET);
				conn->save_stats_rx_offload(completion->packet.total_len);
			}
			else {
				mem_buf_desc_t* prev_lst_tail_desc = (mem_buf_desc_t*)buf_lst;
				mem_buf_desc_t* list_head_desc = (mem_buf_desc_t*)completion->packet.buff_lst;
				prev_lst_tail_desc->p_next_desc = p_first_desc;
				list_head_desc->rx.n_frags += p_first_desc->rx.n_frags;
				p_first_desc->rx.n_frags = 0;
				completion->packet.total_len += p->tot_len;
				completion->packet.num_bufs += list_head_desc->rx.n_frags;
				pbuf_cat((pbuf*)completion->packet.buff_lst, p);
			}
		}
		else {
			if (callback_retval == VMA_PACKET_RECV) {
				// Save rx packet info in our ready list
				conn->m_rx_pkt_ready_list.push_back(p_first_desc);
				conn->m_n_rx_pkt_ready_list_count++;
				conn->m_rx_ready_byte_count += p->tot_len;
				conn->m_p_socket_stats->n_rx_ready_byte_count += p->tot_len;
				conn->m_p_socket_stats->n_rx_ready_pkt_count++;
				conn->m_p_socket_stats->counters.n_rx_ready_pkt_max =
						max((uint32_t)conn->m_p_socket_stats->n_rx_ready_pkt_count,
								conn->m_p_socket_stats->counters.n_rx_ready_pkt_max);
				conn->m_p_socket_stats->counters.n_rx_ready_byte_max =
						max((uint32_t)conn->m_p_socket_stats->n_rx_ready_byte_count,
								conn->m_p_socket_stats->counters.n_rx_ready_byte_max);
			}
			// notify io_mux
			NOTIFY_ON_EVENTS(conn, EPOLLIN);
		}
		io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);

		if (callback_retval != VMA_PACKET_HOLD) {
			//OLG: Now we should wakeup all threads that are sleeping on this socket.
			conn->do_wakeup();
		} else {
			conn->m_p_socket_stats->n_rx_zcopy_pkt_count++;
		}
	}

	/*
	* RCVBUFF Accounting: tcp_recved here(stream into the 'internal' buffer) only if the user buffer is not 'filled'
	*/
	rcv_buffer_space = max(0, conn->m_rcvbuff_max - conn->m_rcvbuff_current - (int)conn->m_pcb.rcv_wnd_max_desired);
	if (callback_retval == VMA_PACKET_DROP) {
		bytes_to_tcp_recved = (int)p->tot_len;
	} else {
		bytes_to_tcp_recved = min(rcv_buffer_space, (int)p->tot_len);
		conn->m_rcvbuff_current += p->tot_len;
	}
	
	if (likely(bytes_to_tcp_recved > 0)) {
	    tcp_recved(&(conn->m_pcb), bytes_to_tcp_recved);
	}

	non_tcp_receved_bytes_remaining = p->tot_len - bytes_to_tcp_recved;

	if (non_tcp_receved_bytes_remaining > 0) {
		bytes_to_shrink = 0;
		if (conn->m_pcb.rcv_wnd_max > conn->m_pcb.rcv_wnd_max_desired) {
	    	bytes_to_shrink = MIN(conn->m_pcb.rcv_wnd_max - conn->m_pcb.rcv_wnd_max_desired, non_tcp_receved_bytes_remaining);
	    	conn->m_pcb.rcv_wnd_max -= bytes_to_shrink;
		}
	    conn->m_rcvbuff_non_tcp_recved += non_tcp_receved_bytes_remaining - bytes_to_shrink;
	}

	vlog_func_exit();
	return ERR_OK;
}

err_t sockinfo_tcp::rx_drop_lwip_cb(void *arg, struct tcp_pcb *tpcb,
                        struct pbuf *p, err_t err)
{
	NOT_IN_USE(tpcb);
	NOT_IN_USE(arg);
	
	vlog_func_enter();
	
	if (!p) {		
		return ERR_OK;
	}
	if (unlikely(err != ERR_OK)) { //not suppose to get here		
		return err;
	}

	return ERR_CONN;
}

int sockinfo_tcp::handle_rx_error(bool is_blocking)
{
	int ret = -1;

	lock_tcp_con();

	if (g_b_exit) {
		errno = EINTR;
		si_tcp_logdbg("returning with: EINTR");
	} else if (!is_rtr()) {
		if (m_conn_state == TCP_CONN_INIT) {
			si_tcp_logdbg("RX on never connected socket");
			errno = ENOTCONN;
		} else if (m_conn_state == TCP_CONN_CONNECTING) {
			si_tcp_logdbg("RX while async-connect on socket");
			errno = EAGAIN;
		} else if (m_conn_state == TCP_CONN_RESETED) {
			si_tcp_logdbg("RX on reseted socket");
			m_conn_state = TCP_CONN_FAILED;
			errno = ECONNRESET;
		} else {
			si_tcp_logdbg("RX on disconnected socket - EOF");
			ret = 0;
		}
	}

	if ((errno == EBUSY || errno == EWOULDBLOCK) && !is_blocking) {
		errno = EAGAIN;
	}

#ifdef VMA_TIME_MEASURE
	INC_ERR_RX_COUNT;
#endif

	if (errno == EAGAIN) {
		m_p_socket_stats->counters.n_rx_eagain++;
	} else {
		m_p_socket_stats->counters.n_rx_errors++;
	}

	unlock_tcp_con();

	return ret;
}

//
// FIXME: we should not require lwip lock for rx
//
ssize_t sockinfo_tcp::rx(const rx_call_t call_type, iovec* p_iov, ssize_t sz_iov, int* p_flags, sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
	int errno_tmp = errno;
	int total_rx = 0;
	int poll_count = 0;
	int bytes_to_tcp_recved;
	size_t total_iov_sz = 1;
	int out_flags = 0;
	int in_flags = *p_flags;
	bool block_this_run = BLOCK_THIS_RUN(m_b_blocking, in_flags);

	m_loops_timer.start();

	si_tcp_logfuncall("");
	if (unlikely(m_sock_offload != TCP_SOCK_LWIP)) {
		int ret = 0;
#ifdef VMA_TIME_MEASURE
		INC_GO_TO_OS_RX_COUNT;
#endif
		ret = socket_fd_api::rx_os(call_type, p_iov, sz_iov, in_flags, __from, __fromlen, __msg);
		save_stats_rx_os(ret);
		return ret;
	}

#ifdef VMA_TIME_MEASURE
	TAKE_T_RX_START;
#endif

	if (unlikely((in_flags & MSG_WAITALL) && !(in_flags & MSG_PEEK))) {
		total_iov_sz = 0;
		for (int i = 0; i < sz_iov; i++) {
			total_iov_sz += p_iov[i].iov_len;
		}
		if (total_iov_sz == 0)
			return 0;
	}

	si_tcp_logfunc("rx: iov=%p niovs=%d", p_iov, sz_iov);
	 /* poll rx queue till we have something */
	lock_tcp_con();
	return_reuse_buffers_postponed();
	unlock_tcp_con();

	while (m_rx_ready_byte_count < total_iov_sz) {
		if (unlikely(g_b_exit ||!is_rtr() || (rx_wait_lockless(poll_count, block_this_run) < 0))) {
			return handle_rx_error(block_this_run);
		}
	}

	lock_tcp_con();

	si_tcp_logfunc("something in rx queues: %d %p", m_n_rx_pkt_ready_list_count, m_rx_pkt_ready_list.front());

	total_rx = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, in_flags, &out_flags);
	if (__msg) handle_cmsg(__msg);

	/*
	* RCVBUFF Accounting: Going 'out' of the internal buffer: if some bytes are not tcp_recved yet  - do that.
	* The packet might not be 'acked' (tcp_recved) 
	* 
	*/
	if (!(in_flags & (MSG_PEEK | MSG_VMA_ZCOPY))) {
		m_rcvbuff_current -= total_rx;

		// data that was not tcp_recved should do it now.
		if ( m_rcvbuff_non_tcp_recved > 0 ) {
			bytes_to_tcp_recved = min(m_rcvbuff_non_tcp_recved, total_rx);
			tcp_recved(&m_pcb, bytes_to_tcp_recved);
			m_rcvbuff_non_tcp_recved -= bytes_to_tcp_recved;
		}
	}

	unlock_tcp_con();

	si_tcp_logfunc("rx completed, %d bytes sent", total_rx);

#ifdef VMA_TIME_MEASURE
	if (0 < total_rx)
		TAKE_T_RX_END;
#endif
	/* Restore errno on function entry in case success */
	errno = errno_tmp;

	return total_rx;
}

void sockinfo_tcp::register_timer()
{
	if( m_timer_handle == NULL) {
		m_timer_handle = g_p_event_handler_manager->register_timer_event(safe_mce_sys().tcp_timer_resolution_msec , this, PERIODIC_TIMER, 0, g_tcp_timers_collection);
	}else {
		si_tcp_logdbg("register_timer was called more than once. Something might be wrong, or connect was called twice.");
	}
}

void sockinfo_tcp::queue_rx_ctl_packet(struct tcp_pcb* pcb, mem_buf_desc_t *p_desc)
{
	/* in tcp_ctl_thread mode, always lock the child first*/
	p_desc->inc_ref_count();
	if (!p_desc->rx.tcp.gro)
		init_pbuf_custom(p_desc);
	else
		p_desc->rx.tcp.gro = 0;
	sockinfo_tcp *sock = (sockinfo_tcp*)pcb->my_container;

	sock->m_rx_ctl_packets_list_lock.lock();
	sock->m_rx_ctl_packets_list.push_back(p_desc);
	sock->m_rx_ctl_packets_list_lock.unlock();

	if (sock != this) {
		m_ready_pcbs[pcb] = 1;
	}

	if (m_sysvar_tcp_ctl_thread == CTL_THREAD_WITH_WAKEUP)
		g_p_event_handler_manager->wakeup_timer_event(this, m_timer_handle);

	return;
}

bool sockinfo_tcp::rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array)
{
	struct tcp_pcb* pcb = NULL;
	int dropped_count = 0;

	lock_tcp_con();

	m_iomux_ready_fd_array = (fd_array_t*)pv_fd_ready_array;

	/* Try to process socketxtreme_poll() completion directly */
	if (p_rx_pkt_mem_buf_desc_info->rx.socketxtreme_polled) {
		m_socketxtreme.completion = m_p_rx_ring->get_comp();
		m_socketxtreme.last_buff_lst = NULL;
	}

	if (unlikely(get_tcp_state(&m_pcb) == LISTEN)) {
		pcb = get_syn_received_pcb(p_rx_pkt_mem_buf_desc_info->rx.src.sin_addr.s_addr,
				p_rx_pkt_mem_buf_desc_info->rx.src.sin_port,
				p_rx_pkt_mem_buf_desc_info->rx.dst.sin_addr.s_addr,
				p_rx_pkt_mem_buf_desc_info->rx.dst.sin_port);
		bool established_backlog_full = false;
		if (!pcb) {
			pcb = &m_pcb;

			/// respect TCP listen backlog - See redmine issue #565962
			/// distinguish between backlog of established sockets vs. backlog of syn-rcvd
			static const unsigned int MAX_SYN_RCVD = m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE ? safe_mce_sys().sysctl_reader.get_tcp_max_syn_backlog() : 0;
							// NOTE: currently, in case tcp_ctl_thread is disabled, only established backlog is supported (no syn-rcvd backlog)

			unsigned int num_con_waiting = m_rx_peer_packets.size();

			// 1st - check established backlog
			if(num_con_waiting > 0 || (m_syn_received.size() >= (size_t)m_backlog && p_rx_pkt_mem_buf_desc_info->rx.tcp.p_tcp_h->syn) ) {
				established_backlog_full = true;
			}

			// 2nd - check that we allow secondary backlog (don't check map of peer packets to avoid races)
			if (MAX_SYN_RCVD == 0 && established_backlog_full) {
				// TODO: consider check if we can now drain into Q of established
				si_tcp_logdbg("SYN/CTL packet drop. established-backlog=%d (limit=%d) num_con_waiting=%d (limit=%d)",
						(int)m_syn_received.size(), m_backlog, num_con_waiting, MAX_SYN_RCVD);
				m_socketxtreme.completion = NULL;
				m_socketxtreme.last_buff_lst = NULL;
				unlock_tcp_con();
				return false;// return without inc_ref_count() => packet will be dropped
			}
		}
		if (m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE || established_backlog_full) { /* 2nd check only worth when MAX_SYN_RCVD>0 for non tcp_ctl_thread  */
			queue_rx_ctl_packet(pcb, p_rx_pkt_mem_buf_desc_info); // TODO: need to trigger queue pulling from accept in case no tcp_ctl_thread
			m_socketxtreme.completion = NULL;
			m_socketxtreme.last_buff_lst = NULL;
			unlock_tcp_con();
			return true;
		}
	}
	else {
		pcb = &m_pcb;
	}
	p_rx_pkt_mem_buf_desc_info->inc_ref_count();

	if (!p_rx_pkt_mem_buf_desc_info->rx.tcp.gro) init_pbuf_custom(p_rx_pkt_mem_buf_desc_info);
	else p_rx_pkt_mem_buf_desc_info->rx.tcp.gro = 0;

	dropped_count = m_rx_cb_dropped_list.size();

	sockinfo_tcp *sock = (sockinfo_tcp*)pcb->my_container;
	if (sock != this) {
		sock->m_tcp_con_lock.lock();
	}

	sock->m_vma_thr = p_rx_pkt_mem_buf_desc_info->rx.is_vma_thr;
#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_READY_POLL_TO_LWIP]);
#endif //RDTSC_MEASURE_RX_READY_POLL_TO_LWIP

#ifdef RDTSC_MEASURE_RX_LWIP
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_MEASURE_RX_LWIP]);
#endif //RDTSC_MEASURE_RX_LWIP
	L3_level_tcp_input((pbuf *)p_rx_pkt_mem_buf_desc_info, pcb);

#ifdef RDTSC_MEASURE_RX_LWIP
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_MEASURE_RX_LWIP]);
#endif //RDTSC_MEASURE_RX_LWIP

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM]);
#endif //RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
	sock->m_vma_thr = false;

	if (sock != this) {
		if (unlikely(sock->m_socketxtreme.completion)) {
			sock->m_socketxtreme.completion = NULL;
			sock->m_socketxtreme.last_buff_lst = NULL;
		}
		sock->m_tcp_con_lock.unlock();
	}

	m_iomux_ready_fd_array = NULL;
	m_socketxtreme.completion = NULL;
	m_socketxtreme.last_buff_lst = NULL;
	p_rx_pkt_mem_buf_desc_info->rx.socketxtreme_polled = false;

	while (dropped_count--) {
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_cb_dropped_list.get_and_pop_front();
		reuse_buffer(p_rx_pkt_desc);
	}

	unlock_tcp_con();

	return true;
}

/**
 *  try to connect to the dest over RDMA cm
 *  try fallback to the OS connect (TODO)
 */ 
int sockinfo_tcp::connect(const sockaddr *__to, socklen_t __tolen)
{

	NOT_IN_USE(__tolen);

	lock_tcp_con();

	// Calling connect more than once should return error codes
	if (m_sock_state != TCP_SOCK_INITED && m_sock_state != TCP_SOCK_BOUND) {
		switch (m_sock_state) {
		case TCP_SOCK_CONNECTED_RD:
		case TCP_SOCK_CONNECTED_WR:
		case TCP_SOCK_CONNECTED_RDWR:
			if (report_connected) {
				report_connected = false;
				unlock_tcp_con();
				return 0;
			}
			errno = EISCONN;
			break;
		case TCP_SOCK_ASYNC_CONNECT:
			errno = EALREADY;
			break;
		default:
			// print error so we can better track apps not following our assumptions ;)
			si_tcp_logerr("socket is in wrong state for connect: %d", m_sock_state);
			errno = EADDRINUSE;
			break;
		}
		unlock_tcp_con();
		return -1;
	}

	// take local ip from new sock and local port from acceptor
	if (m_sock_state != TCP_SOCK_BOUND && bind(m_bound.get_p_sa(), m_bound.get_socklen()) == -1) {
		setPassthrough();
		unlock_tcp_con();
		si_tcp_logdbg("non offloaded socket --> connect only via OS");
		return -1;
        }

	// setup peer address
	// TODO: Currenlty we don't check the if __to is supported and legal
	// socket-redirect probably should do this
	m_connected.set(*((sockaddr *)__to));

	create_dst_entry();
	if (!m_p_connected_dst_entry) {
		setPassthrough();
		unlock_tcp_con();
		si_tcp_logdbg("non offloaded socket --> connect only via OS");
		return -1;
	}

	prepare_dst_to_send(false);

	// update it after route was resolved and device was updated
	m_p_socket_stats->bound_if = m_p_connected_dst_entry->get_src_addr();

	sockaddr_in remote_addr;
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = m_p_connected_dst_entry->get_dst_addr();
	remote_addr.sin_port = m_p_connected_dst_entry->get_dst_port();
	sock_addr local_addr(m_bound.get_p_sa());
	if (local_addr.is_anyaddr())
		local_addr.set_in_addr(m_p_connected_dst_entry->get_src_addr());

	if (!m_p_connected_dst_entry->is_offloaded()
			|| find_target_family(ROLE_TCP_CLIENT, (sockaddr*)&remote_addr, local_addr.get_p_sa()) != TRANS_VMA) {
		setPassthrough();
		unlock_tcp_con();
		si_tcp_logdbg("non offloaded socket --> connect only via OS");
		return -1;
	} else {
		notify_epoll_context_fd_is_offloaded(); //remove fd from os epoll
	}

	if (m_bound.is_anyaddr()) {
		m_bound.set_in_addr(m_p_connected_dst_entry->get_src_addr());
		in_addr_t ip = m_bound.get_in_addr();
		tcp_bind(&m_pcb, (ip_addr_t*)(&ip), (ntohs(m_bound.get_in_port())));
	}
	m_conn_state = TCP_CONN_CONNECTING;
	bool success = attach_as_uc_receiver((role_t)NULL, true);
	if (!success) {
		setPassthrough();
		unlock_tcp_con();
		si_tcp_logdbg("non offloaded socket --> connect only via OS");
		return -1;
	}

	in_addr_t peer_ip_addr = m_connected.get_in_addr();
	fit_rcv_wnd(true);

	int err = tcp_connect(&m_pcb, (ip_addr_t*)(&peer_ip_addr), ntohs(m_connected.get_in_port()), /*(tcp_connected_fn)*/sockinfo_tcp::connect_lwip_cb);
	if (err != ERR_OK) {
		//todo consider setPassthrough and go to OS
		destructor_helper();
		errno = ECONNREFUSED;
		si_tcp_logerr("bad connect, err=%d", err);
		unlock_tcp_con();
		return -1;
	}

	//Now we should register socket to TCP timer
	register_timer();

	if (!m_b_blocking) {
		errno = EINPROGRESS;
		m_error_status = EINPROGRESS;
		m_sock_state = TCP_SOCK_ASYNC_CONNECT;
		report_connected = true;
		unlock_tcp_con();
		si_tcp_logdbg("NON blocking connect");
		return -1;
	}

	// if (target_family == USE_VMA || target_family == USE_ULP || arget_family == USE_DEFAULT)
	int rc = wait_for_conn_ready();
	// handle ret from async connect
	if (rc < 0) {
		//todo consider setPassthrough and go to OS
		destructor_helper();
		unlock_tcp_con();
		// errno is set inside wait_for_conn_ready
		return -1;
	}
	setPassthrough(false);
	unlock_tcp_con();
	return 0;
}

int sockinfo_tcp::bind(const sockaddr *__addr, socklen_t __addrlen)
{
	struct sockaddr tmp_sin;
	socklen_t tmp_sin_len = sizeof(tmp_sin);

	si_tcp_logfuncall("");

        if (m_sock_state == TCP_SOCK_BOUND) {
                si_tcp_logfuncall("already bounded");
                errno = EINVAL;
                return -1;
        }

	if (m_sock_state != TCP_SOCK_INITED) {
		// print error so we can better track apps not following our assumptions ;)
		si_tcp_logdbg("socket is in wrong state for bind: %d", m_sock_state);
		errno = EINVAL; //EADDRINUSE; //todo or EINVAL for RM BGATE 1545 case 1
		return -1;
	}

	lock_tcp_con();

	uint16_t bind_to_port = (__addr && __addrlen) ? ((struct sockaddr_in*)__addr)->sin_port : INPORT_ANY; //todo verify __addr length
	bool disable_reuse_option = (bind_to_port == INPORT_ANY) && (m_pcb.so_options & SOF_REUSEADDR);
	int reuse, ret;

	if (disable_reuse_option) {
		reuse = 0;
		ret = orig_os_api.setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret) {
			si_tcp_logerr("Failed to disable SO_REUSEADDR option (ret=%d %m), connection will be handled by OS", ret);
			setPassthrough();
			si_tcp_logdbg("socket bound only via OS");
			unlock_tcp_con();
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	ret = orig_os_api.bind(m_fd, __addr, __addrlen);

	if (disable_reuse_option) {
		reuse = 1;
		int rv = orig_os_api.setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
		BULLSEYE_EXCLUDE_BLOCK_START
		if (rv) {
			si_tcp_logerr("Failed to enable SO_REUSEADDR option (ret=%d %m)", rv);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (ret < 0) {
			setPassthrough();
			si_tcp_logdbg("socket bound only via OS");
		}
	}

	if (ret < 0) {
		unlock_tcp_con();
		return ret;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if(orig_os_api.getsockname(m_fd, &tmp_sin, &tmp_sin_len)) {
		si_tcp_logerr("get sockname failed");
		unlock_tcp_con();
		return -1; //error
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// TODO: mark socket as accepting both os and offloaded connections
	if (tmp_sin.sa_family != AF_INET) {
		si_tcp_logdbg("Illegal family %d", tmp_sin.sa_family);
		errno = EAFNOSUPPORT;
		unlock_tcp_con();
		return -1; //error
	}
	m_bound.set(tmp_sin);
	in_addr_t ip = m_bound.get_in_addr();

	if (!m_bound.is_anyaddr() && !g_p_net_device_table_mgr->get_net_device_val(ip)) { //if socket is not bound to INADDR_ANY and not offloaded socket- only bind OS
		setPassthrough();
		m_sock_state = TCP_SOCK_BOUND;
		si_tcp_logdbg("socket bound only via OS");
		unlock_tcp_con();
		return 0;
	}

	if (tcp_bind(&m_pcb, (ip_addr_t*)(&ip), ntohs(m_bound.get_in_port())) != ERR_OK) {
		errno = EINVAL;
		unlock_tcp_con();
		return -1; //error
	}

	m_sock_state = TCP_SOCK_BOUND;

	m_bound.set(tmp_sin);
	si_tcp_logdbg("socket bound");

	m_p_socket_stats->bound_if = m_bound.get_in_addr();
	m_p_socket_stats->bound_port = m_bound.get_in_port();

	unlock_tcp_con();
	return 0;
}

int sockinfo_tcp::prepareListen(){
	transport_t target_family;
	struct sockaddr_in tmp_sin;
	socklen_t tmp_sin_len = sizeof(sockaddr_in);
	si_tcp_logfuncall("");

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH)
		return 1;  //passthrough

	if (is_server())
		return 0;  // listen had been called before...

	if (m_sock_state != TCP_SOCK_BOUND) {
		/*It is legal application  behavior, listen was called without bind,
		 * therefore need to call for bind() to get a random port from the OS
		 */
		si_tcp_logdbg("listen was called without bind - calling for VMA bind" );

		memset(&tmp_sin, 0, tmp_sin_len);
		tmp_sin.sin_family = AF_INET;
		tmp_sin.sin_port = 0;
		tmp_sin.sin_addr.s_addr = INADDR_ANY;
		if (bind((struct sockaddr *)&tmp_sin, tmp_sin_len) < 0) {
			si_tcp_logdbg("bind failed");
			return 1;
		}
	}

	memset(&tmp_sin, 0, tmp_sin_len);
	getsockname((struct sockaddr *)&tmp_sin, &tmp_sin_len);
	lock_tcp_con();
	target_family = __vma_match_tcp_server(TRANS_VMA, safe_mce_sys().app_id, (struct sockaddr *) &tmp_sin, tmp_sin_len);
	si_tcp_logdbg("TRANSPORT: %s, sock state = %d", __vma_get_transport_str(target_family), get_tcp_state(&m_pcb));

	if (target_family == TRANS_OS || m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		setPassthrough();
		m_sock_state = TCP_SOCK_ACCEPT_READY;
	}
	else {

		// if (target_family == USE_VMA || target_family == USE_ULP || arget_family == USE_DEFAULT)
		setPassthrough(false);
		m_sock_state = TCP_SOCK_LISTEN_READY;
	}

	unlock_tcp_con();
	return isPassthrough() ? 1 : 0;
}

int sockinfo_tcp::listen(int backlog)
{
	si_tcp_logfuncall("");

	int orig_backlog = backlog;

	if (backlog > safe_mce_sys().sysctl_reader.get_listen_maxconn()) {
		si_tcp_logdbg("truncating listen backlog=%d to the maximun=%d", backlog, safe_mce_sys().sysctl_reader.get_listen_maxconn());
		backlog = safe_mce_sys().sysctl_reader.get_listen_maxconn();
	}
	else if (backlog <= 0) {
		si_tcp_logdbg("changing listen backlog=%d to the minimum=%d", backlog, 1);
		backlog = 1;
	}
	if (backlog >= 5)
		backlog = 10 + 2 * backlog; // allow grace, inspired by Linux

	lock_tcp_con();

	if (is_server()) {
		// if listen is called again - only update the backlog
		// TODO: check if need to drop item in existing queues
		m_backlog = backlog;
		unlock_tcp_con();
		return 0;
	}
	if (m_sock_state != TCP_SOCK_LISTEN_READY) {
		// print error so we can better track bugs in VMA)
		si_tcp_logerr("socket is in wrong state for listen: %d", m_sock_state);
		errno = EINVAL;
		unlock_tcp_con();
		return -1;
	}

	m_backlog = backlog;
	m_ready_conn_cnt = 0;

	if (get_tcp_state(&m_pcb) != LISTEN) {

		// Now we know that it is listen socket so we have to treat m_pcb as listen pcb
		// and update the relevant fields of tcp_listen_pcb.
		struct tcp_pcb tmp_pcb;
		memcpy(&tmp_pcb, &m_pcb, sizeof(struct tcp_pcb));
		tcp_listen((struct tcp_pcb_listen*)(&m_pcb), &tmp_pcb);
	}

	m_sock_state = TCP_SOCK_ACCEPT_READY;

	tcp_accept(&m_pcb, sockinfo_tcp::accept_lwip_cb);
	tcp_syn_handled((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::syn_received_lwip_cb);
	tcp_clone_conn((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::clone_conn_cb);

	bool success = attach_as_uc_receiver(ROLE_TCP_SERVER);

	if (!success) {
		/* we will get here if attach_as_uc_receiver failed */
		si_tcp_logdbg("Fallback the connection to os");
		setPassthrough();
		unlock_tcp_con();
		return orig_os_api.listen(m_fd, orig_backlog);
	}

	// Calling to orig_listen() by default to monitor connection requests for not offloaded sockets
	BULLSEYE_EXCLUDE_BLOCK_START
	if (orig_os_api.listen(m_fd, orig_backlog)) {
		si_tcp_logerr("orig_listen failed");
		unlock_tcp_con();
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Add the user's orig fd to the rx epfd handle
	epoll_event ev = {0, {0}};
	ev.events = EPOLLIN;
	ev.data.fd = m_fd;
	int ret = orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(ret)) {
		if (errno == EEXIST) {
			si_tcp_logdbg("failed to add user's fd to internal epfd errno=%d (%m)", errno);
		} else {
			si_tcp_logerr("failed to add user's fd to internal epfd errno=%d (%m)", errno);
			si_tcp_logdbg("Fallback the connection to os");
			destructor_helper();
			setPassthrough();
			unlock_tcp_con();
			return 0;
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE)
		m_timer_handle = g_p_event_handler_manager->register_timer_event(safe_mce_sys().timer_resolution_msec , this, PERIODIC_TIMER, 0, NULL);

	unlock_tcp_con();
	return 0;

}

int sockinfo_tcp::rx_verify_available_data()
{
	int poll_count = 0;

	// Poll cq to verify the latest amount of ready bytes
	int ret = rx_wait_helper(poll_count, false);

	if (ret >= 0 || errno == EAGAIN) {
		errno = 0;
		ret = m_p_socket_stats->n_rx_ready_byte_count;
	}

	return ret;
}

int sockinfo_tcp::accept_helper(struct sockaddr *__addr, socklen_t *__addrlen, int __flags /* = 0 */)
{
	sockinfo_tcp *ns;
	//todo do one CQ poll and go to sleep even if infinite polling was set
	int poll_count = m_n_sysvar_rx_poll_num; //do one poll and go to sleep (if blocking)
	int ret;

	si_tcp_logfuncall("");

	// if in os pathrough just redirect to os
	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		si_tcp_logdbg("passthrough - go to OS accept()");
		if (__flags)
			return orig_os_api.accept4(m_fd, __addr, __addrlen, __flags);
		else
			return orig_os_api.accept(m_fd, __addr, __addrlen);
	}

	si_tcp_logdbg("socket accept, __addr = %p, __addrlen = %p, *__addrlen = %d", __addr, __addrlen, __addrlen ? *__addrlen : 0);

	if (!is_server()) {
		// print error so we can better track apps not following our assumptions ;)
		si_tcp_logdbg("socket is in wrong state for accept: %d", m_sock_state);
		errno = EINVAL;
		return -1;
	}

	lock_tcp_con();

	si_tcp_logdbg("sock state = %d", get_tcp_state(&m_pcb));
	while (m_ready_conn_cnt == 0 && !g_b_exit) {
		if (m_sock_state != TCP_SOCK_ACCEPT_READY) {
			unlock_tcp_con();
			errno = EINVAL;
			return -1;
		}

		//todo instead of doing blind poll, check if waken-up by OS fd in rx_wait
		//
		// Always try OS accept() 

		// Poll OS socket for pending connection
		// smart bit to switch between the two
		pollfd os_fd[1];
		os_fd[0].fd = m_fd;
		os_fd[0].events = POLLIN;
		ret = orig_os_api.poll(os_fd, 1, 0); // Zero timeout - just poll and return quickly
		if (unlikely(ret == -1)) {
			m_p_socket_stats->counters.n_rx_os_errors++;
			si_tcp_logdbg("orig_os_api.poll returned with error (errno=%d %m)", errno);
			unlock_tcp_con();
			return -1;
		}
		if (ret == 1) {
			si_tcp_logdbg("orig_os_api.poll returned with packet");
			unlock_tcp_con();
			if (__flags)
				return orig_os_api.accept4(m_fd, __addr, __addrlen, __flags);
			else
				return orig_os_api.accept(m_fd, __addr, __addrlen);
		}

		if (rx_wait(poll_count, m_b_blocking) < 0) {
			si_tcp_logdbg("interrupted accept");
			unlock_tcp_con();
			return -1;
		}
	}
	if (g_b_exit) {
		si_tcp_logdbg("interrupted accept");
		unlock_tcp_con();
		errno = EINTR;
		return -1;
	}

	si_tcp_logdbg("sock state = %d", get_tcp_state(&m_pcb));
	si_tcp_logdbg("socket accept - has some!!!");
	ns = m_accepted_conns.get_and_pop_front();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!ns) {
		si_tcp_logpanic("no socket in accepted queue!!! ready count = %d", m_ready_conn_cnt);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_ready_conn_cnt--;
	tcp_accepted(m_sock);

	class flow_tuple key;
	sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(ns->m_pcb));

	//Since the pcb is already contained in connected sockinfo_tcp no need to keep it listen's socket SYN list
	if (!m_syn_received.erase(key)) {
		//Should we worry about that?
		__log_dbg("Can't find the established pcb in syn received list\n");
	}
	else {
		m_received_syn_num--;
	}

	if (m_sysvar_tcp_ctl_thread == CTL_THREAD_WITH_WAKEUP && !m_rx_peer_packets.empty())
		g_p_event_handler_manager->wakeup_timer_event(this, m_timer_handle);

	unlock_tcp_con();

	ns->lock_tcp_con();

	if (__addr && __addrlen) {
		if ((ret = ns->getpeername(__addr, __addrlen)) < 0) {
			int errno_tmp = errno;
			ns->unlock_tcp_con();
			close(ns->get_fd());
			errno = errno_tmp;

			/* According accept() man description ECONNABORTED is expected
			 * error value in case connection was aborted.
			 */
			switch (errno) {
			case ENOTCONN:
				/* accept() expected result
				 * If connection was established in background and client
				 * closed connection forcibly (using RST)
				 */
				errno = ECONNABORTED;
				break;
			default:
				break;
			}

			return ret;
		}
	}

	ns->m_p_socket_stats->connected_ip = ns->m_connected.get_in_addr();
	ns->m_p_socket_stats->connected_port = ns->m_connected.get_in_port();

	ns->m_p_socket_stats->bound_if = ns->m_bound.get_in_addr();
	ns->m_p_socket_stats->bound_port = ns->m_bound.get_in_port();

	if (__flags & SOCK_NONBLOCK)
		ns->fcntl(F_SETFL, O_NONBLOCK);
	if (__flags & SOCK_CLOEXEC)
		ns->fcntl(F_SETFD, FD_CLOEXEC);

	ns->unlock_tcp_con();

        si_tcp_logdbg("CONN ACCEPTED: TCP PCB FLAGS: acceptor:0x%x newsock: fd=%d 0x%x new state: %d", m_pcb.flags, ns->m_fd, ns->m_pcb.flags, get_tcp_state(&ns->m_pcb));
	return ns->m_fd;
}

int sockinfo_tcp::accept(struct sockaddr *__addr, socklen_t *__addrlen)
{
	si_tcp_logfuncall("");

	return accept_helper(__addr, __addrlen);
}

int sockinfo_tcp::accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags)
{
	si_tcp_logfuncall("");
	si_tcp_logdbg("socket accept4, flags=%d", __flags);

	return accept_helper(__addr, __addrlen, __flags);
}

sockinfo_tcp *sockinfo_tcp::accept_clone()
{
        sockinfo_tcp *si;
        int fd;

        // note that this will call socket() replacement!!!
        // and it will force proper socket creation
        fd = socket_internal(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
                return 0;
        }
	
        si = dynamic_cast<sockinfo_tcp *>(fd_collection_get_sockfd(fd));

        if (!si) {
                si_tcp_logwarn("can not get accept socket from FD collection");
                close(fd);
                return 0;
        }

        si->m_parent = this;

        si->m_sock_state = TCP_SOCK_BOUND;
        si->setPassthrough(false);

        if (m_sysvar_tcp_ctl_thread  > CTL_THREAD_DISABLE) {
        	tcp_ip_output(&si->m_pcb, sockinfo_tcp::ip_output_syn_ack);
        }

        return si;
}

//Must be taken under parent's tcp connection lock
void sockinfo_tcp::auto_accept_connection(sockinfo_tcp *parent, sockinfo_tcp *child)
{
	tcp_accepted(parent->m_sock);

	class flow_tuple key;
	sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(child->m_pcb));

	//Since pcb is already contained in connected sockinfo_tcp no need to keep it listen's socket SYN list
	if (!parent->m_syn_received.erase(key)) {
		//Should we worry about that?
		__log_dbg("Can't find the established pcb in syn received list\n");
	}
	else {
		parent->m_received_syn_num--;
	}

	parent->unlock_tcp_con();
	child->lock_tcp_con();

	child->m_p_socket_stats->connected_ip = child->m_connected.get_in_addr();
	child->m_p_socket_stats->connected_port = child->m_connected.get_in_port();
	child->m_p_socket_stats->bound_if = child->m_bound.get_in_addr();
	child->m_p_socket_stats->bound_port = child->m_bound.get_in_port();
	if (child->m_socketxtreme.completion) {
		child->m_connected.get_sa(parent->m_socketxtreme.completion->src);
	} else {
		child->m_connected.get_sa(parent->m_socketxtreme.ec.completion.src);
	}

	/* Update vma_completion with
	 * VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED related data
	 */
	if (likely(child->m_parent)) {
		if (child->m_socketxtreme.completion) {
			child->m_socketxtreme.completion->src = parent->m_socketxtreme.completion->src;
			child->m_socketxtreme.completion->listen_fd = child->m_parent->get_fd();
		} else {
			child->m_socketxtreme.ec.completion.src = parent->m_socketxtreme.ec.completion.src;
			child->m_socketxtreme.ec.completion.listen_fd = child->m_parent->get_fd();
		}
		child->set_events(VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED);
	}
	else {
		vlog_printf(VLOG_ERROR, "VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED: can't find listen socket for new connected socket with [fd=%d]",
				__func__, __LINE__, child->get_fd());
	}

	child->unlock_tcp_con();
	parent->lock_tcp_con();

	__log_dbg("CONN AUTO ACCEPTED: TCP PCB FLAGS: acceptor:0x%x newsock: fd=%d 0x%x new state: %d\n", parent->m_pcb.flags, child->m_fd, child->m_pcb.flags, get_tcp_state(&child->m_pcb));
}

err_t sockinfo_tcp::accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err)
{
	sockinfo_tcp *conn = (sockinfo_tcp *)(arg);
	sockinfo_tcp *new_sock;
	bool conn_nagle_disabled;

	if (!conn || !child_pcb) {
		return ERR_VAL;
	}

	__log_dbg("initial state=%x\n", get_tcp_state(&conn->m_pcb));
	__log_dbg("accept cb: arg=%p, new pcb=%p err=%d\n", arg, child_pcb, err);
	if (err != ERR_OK) {
		vlog_printf(VLOG_ERROR, "%s:d: accept cb failed\n", __func__, __LINE__);
		return err;
	}
	if (conn->m_sock_state != TCP_SOCK_ACCEPT_READY) {
		__log_dbg("socket is not accept ready!\n");
		return ERR_RST;
	}
	// make new socket
	__log_dbg("new stateb4clone=%x\n", get_tcp_state(child_pcb));
	new_sock = (sockinfo_tcp*)child_pcb->my_container;

	if (!new_sock) {
		vlog_printf(VLOG_ERROR, "%s:d: failed to clone socket\n", __func__, __LINE__);
		return ERR_RST;
	}

	tcp_ip_output(&(new_sock->m_pcb), sockinfo_tcp::ip_output);
	tcp_arg(&(new_sock->m_pcb), new_sock);
	tcp_recv(&(new_sock->m_pcb), sockinfo_tcp::rx_lwip_cb);
	tcp_err(&(new_sock->m_pcb), sockinfo_tcp::err_lwip_cb);

	ASSERT_LOCKED(new_sock->m_tcp_con_lock);

	new_sock->m_sock_state = TCP_SOCK_CONNECTED_RDWR;

	__log_dbg("listen(fd=%d) state=%x: new sock(fd=%d) state=%x\n", conn->m_fd, get_tcp_state(&conn->m_pcb), new_sock->m_fd, get_tcp_state(&new_sock->m_pcb));

	/* Configure Nagle algorithm settings as they were set at the parent socket.
	   This can happened if VMA_TCP_NAGLE flag was set, but we disabled it for the parent socket. */
	if ((conn_nagle_disabled = tcp_nagle_disabled(&conn->m_pcb)) != tcp_nagle_disabled(&new_sock->m_pcb)) {
		conn_nagle_disabled ? tcp_nagle_disable(&new_sock->m_pcb) : tcp_nagle_enable(&new_sock->m_pcb);
		new_sock->fit_snd_bufs_to_nagle(conn_nagle_disabled);
	}

	if (new_sock->m_conn_state == TCP_CONN_INIT) { //in case m_conn_state is not in one of the error states
		new_sock->m_conn_state = TCP_CONN_CONNECTED;
	}
	
	/* if attach failed, we should continue getting traffic through the listen socket */
	// todo register as 3-tuple rule for the case the listener is gone?
	new_sock->attach_as_uc_receiver(role_t (NULL), true);

	if (new_sock->m_sysvar_tcp_ctl_thread > CTL_THREAD_DISABLE) {
		new_sock->m_vma_thr = true;

		// Before handling packets from flow steering the child should process everything it got from parent
		while (!new_sock->m_rx_ctl_packets_list.empty()) {
			vma_desc_list_t temp_list;
			new_sock->m_rx_ctl_packets_list_lock.lock();
			temp_list.splice_tail(new_sock->m_rx_ctl_packets_list);
			new_sock->m_rx_ctl_packets_list_lock.unlock();

			while (!temp_list.empty()) {
				mem_buf_desc_t* desc = temp_list.get_and_pop_front();
				desc->inc_ref_count();
				L3_level_tcp_input((pbuf *)desc, &new_sock->m_pcb);
				if (desc->dec_ref_count() <= 1) //todo reuse needed?
					new_sock->m_rx_ctl_reuse_list.push_back(desc);
			}
		}
		new_sock->m_vma_thr = false;
	}

	new_sock->unlock_tcp_con();

	conn->lock_tcp_con();

	//todo check that listen socket was not closed by now ? (is_server())
	conn->m_ready_pcbs.erase(&new_sock->m_pcb);

	if (conn->is_socketxtreme()) {
		auto_accept_connection(conn, new_sock);
	} else {
		conn->m_accepted_conns.push_back(new_sock);
		conn->m_ready_conn_cnt++;

		NOTIFY_ON_EVENTS(conn, EPOLLIN);
	}

	//OLG: Now we should wakeup all threads that are sleeping on this socket.
	conn->do_wakeup();
	//Now we should register the child socket to TCP timer

	conn->unlock_tcp_con();

	/* Do this after auto_accept_connection() call */
	new_sock->m_parent = NULL;

	new_sock->lock_tcp_con();

	return ERR_OK;
}

void sockinfo_tcp::create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb)
{
	key = flow_tuple(pcb->local_ip.addr, htons(pcb->local_port), pcb->remote_ip.addr, htons(pcb->remote_port), PROTO_TCP);
}

mem_buf_desc_t* sockinfo_tcp::get_front_m_rx_pkt_ready_list(){
	return m_rx_pkt_ready_list.front();
}

size_t sockinfo_tcp::get_size_m_rx_pkt_ready_list(){
	return m_rx_pkt_ready_list.size();
}

void sockinfo_tcp::pop_front_m_rx_pkt_ready_list(){
	m_rx_pkt_ready_list.pop_front();
}

void sockinfo_tcp::push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff){
	m_rx_pkt_ready_list.push_back(buff);
}



struct tcp_pcb* sockinfo_tcp::get_syn_received_pcb(const flow_tuple &key) const
{
	struct tcp_pcb* ret_val = NULL;
	syn_received_map_t::const_iterator itr;

	itr = m_syn_received.find(key);
	if (itr != m_syn_received.end()) {
		ret_val = itr->second;
	}
	return ret_val;
}

struct tcp_pcb* sockinfo_tcp::get_syn_received_pcb(in_addr_t peer_ip, in_port_t peer_port, in_addr_t local_ip, in_port_t local_port)
{
	flow_tuple key(local_ip, local_port, peer_ip, peer_port, PROTO_TCP);
	return get_syn_received_pcb(key);
}

err_t sockinfo_tcp::clone_conn_cb(void *arg, struct tcp_pcb **newpcb, err_t err)
{
	sockinfo_tcp *new_sock;
	err_t ret_val = ERR_OK;

	sockinfo_tcp *conn = (sockinfo_tcp *)((arg));
	NOT_IN_USE(err);

	if (!conn || !newpcb) {
		return ERR_VAL;
	}

	ASSERT_LOCKED(conn->m_tcp_con_lock);
	conn->m_tcp_con_lock.unlock();

	new_sock = conn->accept_clone();

	if (new_sock) {
		/* cppcheck-suppress autoVariables */
		*newpcb = (struct tcp_pcb*)(&new_sock->m_pcb);
		new_sock->m_pcb.my_container = (void*)new_sock;
	}
	else {
		ret_val = ERR_MEM;
	}

	conn->m_tcp_con_lock.lock();

	return ret_val;
}

err_t sockinfo_tcp::syn_received_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	sockinfo_tcp *listen_sock = (sockinfo_tcp *)((arg));

	if (!listen_sock || !newpcb) {
		return ERR_VAL;
	}

	sockinfo_tcp *new_sock = (sockinfo_tcp *)((newpcb->my_container));

	NOT_IN_USE(err);

	ASSERT_LOCKED(listen_sock->m_tcp_con_lock);

	/* Inherite properties from the parent */
	new_sock->set_conn_properties_from_pcb();

	new_sock->m_rcvbuff_max = MAX(listen_sock->m_rcvbuff_max, 2 * new_sock->m_pcb.mss);
	new_sock->fit_rcv_wnd(true);

	// Socket socket options
	listen_sock->set_sock_options(new_sock);

	listen_sock->m_tcp_con_lock.unlock();

	new_sock->create_dst_entry();
	bool is_new_offloaded = new_sock->m_p_connected_dst_entry && new_sock->prepare_dst_to_send(true); // pass true for passive socket to skip the transport rules checking

	/* this can happen if there is no route back to the syn sender.
	 * so we just need to ignore it.
	 * we set the state to close so we won't try to send fin when we don't
	 * have route. */
	if (!is_new_offloaded) {
		new_sock->setPassthrough();
		set_tcp_state(&new_sock->m_pcb, CLOSED);
		close(new_sock->get_fd());
		listen_sock->m_tcp_con_lock.lock();
		return ERR_ABRT;
	}

	new_sock->register_timer();

	listen_sock->m_tcp_con_lock.lock();

	flow_tuple key;
	create_flow_tuple_key_from_pcb(key, newpcb);

	listen_sock->m_syn_received[key] =  newpcb;

	listen_sock->m_received_syn_num++;

	return ERR_OK;
}

err_t sockinfo_tcp::syn_received_drop_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	sockinfo_tcp *listen_sock = (sockinfo_tcp *)((arg));

	if (!listen_sock || !newpcb) {
		return ERR_VAL;
	}

	sockinfo_tcp *new_sock = (sockinfo_tcp *)((newpcb->my_container));

	NOT_IN_USE(err);

	ASSERT_LOCKED(listen_sock->m_tcp_con_lock);
	listen_sock->m_tcp_con_lock.unlock();

	new_sock->set_conn_properties_from_pcb();
	new_sock->create_dst_entry();
	if (new_sock->m_p_connected_dst_entry) {
		new_sock->prepare_dst_to_send(true); // true for passive socket to skip the transport rules checking
		tcp_arg(&(new_sock->m_pcb), new_sock);
		new_sock->abort_connection();
	}
	close(new_sock->get_fd());

	listen_sock->m_tcp_con_lock.lock();

	return ERR_ABRT;
}

void sockinfo_tcp::set_conn_properties_from_pcb()
{
	// setup peer address and local address

	m_connected.set_in_addr(m_pcb.remote_ip.addr);
	m_connected.set_in_port(htons(m_pcb.remote_port));
	m_connected.set_sa_family(AF_INET);

	m_bound.set_in_addr(m_pcb.local_ip.addr);
	m_bound.set_in_port(htons(m_pcb.local_port));
	m_bound.set_sa_family(AF_INET);
}

void sockinfo_tcp::set_sock_options(sockinfo_tcp *new_sock)
{
	si_tcp_logdbg("Applying all socket options on %p, fd %d", new_sock, new_sock->get_fd());

	socket_options_list_t::iterator options_iter;
	for (options_iter = m_socket_options_list.begin(); options_iter != m_socket_options_list.end(); options_iter++) {
		socket_option_t* opt = *options_iter;
		new_sock->setsockopt(opt->level, opt->optname, opt->optval, opt->optlen);
	}
	errno = 0;

	si_tcp_logdbg("set_sock_options completed");
}

err_t sockinfo_tcp::connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;
	NOT_IN_USE(tpcb);

	__log_dbg("connect cb: arg=%p, pcp=%p err=%d\n", arg, tpcb, err);

	if (!conn || !tpcb) {
		return ERR_VAL;
	}

	conn->lock_tcp_con();

	if (conn->m_conn_state == TCP_CONN_TIMEOUT) {
		//tcp_si_logdbg("conn timeout");
		conn->m_error_status = ETIMEDOUT;
		conn->unlock_tcp_con();
		return ERR_OK;
	}
	if (err == ERR_OK) {
		conn->m_conn_state = TCP_CONN_CONNECTED;
		conn->m_sock_state = TCP_SOCK_CONNECTED_RDWR; // async connect verification
		conn->m_error_status = 0;
		if (conn->m_rcvbuff_max <  2 * conn->m_pcb.mss) {
			conn->m_rcvbuff_max = 2 * conn->m_pcb.mss;
		}
		conn->fit_rcv_wnd(false);
	}
	else {
		conn->m_error_status = ECONNREFUSED;
		conn->m_conn_state = TCP_CONN_FAILED;
	}
	
	NOTIFY_ON_EVENTS(conn, EPOLLOUT);
	//OLG: Now we should wakeup all threads that are sleeping on this socket.
	conn->do_wakeup();

	conn->m_p_socket_stats->connected_ip = conn->m_connected.get_in_addr();
	conn->m_p_socket_stats->connected_port = conn->m_connected.get_in_port();

	conn->unlock_tcp_con();

	return ERR_OK;
}

int sockinfo_tcp::wait_for_conn_ready()
{
	int poll_count = 0;

	si_tcp_logfuncall("");

	while(m_conn_state == TCP_CONN_CONNECTING && m_sock_state != TCP_SOCK_INITED) {
		/*In case of connect error err_lwip_cb is called and not connect_lwip_cb
		 * therefore in this case the m_conn_state will not be changed only
		 * m_sock_state
		 */
		if (rx_wait(poll_count, m_b_blocking) < 0) {
			si_tcp_logdbg("connect interrupted");
			return -1;
		}

		if (unlikely(g_b_exit)) {
			errno = EINTR;
			return -1;
		}
	}
	if (m_sock_state == TCP_SOCK_INITED) {
		//we get here if err_lwip_cb() was called and set m_sock_state=TCP_SOCK_INITED
		m_conn_state = TCP_CONN_FAILED;
		errno = ECONNREFUSED;
		si_tcp_logdbg("got connection error");
		//if we got here, bind succeeded earlier (in connect()), so change m_sock_state back to TCP_SOCK_BOUND to avoid binding again in case of recalling connect()
		m_sock_state = TCP_SOCK_BOUND;
		return -1;

	}
	if (m_conn_state != TCP_CONN_CONNECTED) {
		if (m_conn_state == TCP_CONN_TIMEOUT) {
			m_conn_state = TCP_CONN_FAILED;
			errno = ETIMEDOUT;
		} else {
			errno = ECONNREFUSED;
		}
		si_tcp_logdbg("bad connect -> timeout or none listening");
		return -1;
	}
	si_tcp_logdbg("+++ CONNECT OK!!!! ++++");
	m_sock_state = TCP_SOCK_CONNECTED_RDWR;
	si_tcp_logdbg("TCP PCB FLAGS: 0x%x", m_pcb.flags);
	return 0;
}



bool sockinfo_tcp::is_readable(uint64_t *p_poll_sn, fd_array_t* p_fd_array)
{
	int ret;

	if (is_server()) {
		bool state;
		//tcp_si_logwarn("select on accept()");
		//m_conn_cond.lock();
		state = m_ready_conn_cnt == 0 ? false : true; 
		if (state) {
			si_tcp_logdbg("accept ready");
			return true;
		}

		if (m_sock_state == TCP_SOCK_ACCEPT_SHUT) return true;

		return false;
	} 
	else if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
		// socket is not ready to read in this state!!!
		return false;
	}

	if (!is_rtr()) {
		// unconnected tcp sock is always ready for read!
		// return its fd as ready
		si_tcp_logdbg("block check on unconnected socket");
		return true;
	}

	if (m_n_rx_pkt_ready_list_count)
		return true;

	if (!p_poll_sn)
		return false;

	consider_rings_migration();

	m_rx_ring_map_lock.lock();
	while(!g_b_exit && is_rtr()) {
		if (likely(m_p_rx_ring)) {
			// likely scenario: rx socket bound to specific cq
			ret = m_p_rx_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
			if (m_n_rx_pkt_ready_list_count || ret <= 0) {
				break;
			}
		} else if (!m_rx_ring_map.empty()) {
			rx_ring_map_t::iterator rx_ring_iter;
			for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
				if (rx_ring_iter->second->refcnt <= 0) {
					continue;
				}
				ring* p_ring =  rx_ring_iter->first;
				//g_p_lwip->do_timers();
				ret = p_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
				if (m_n_rx_pkt_ready_list_count || ret <= 0) {
					break;
				}
			}
		} else {
			// No available rx rings, break loop.
			break;
		}
	}

	m_rx_ring_map_lock.unlock();
	if (!m_n_rx_pkt_ready_list_count) {
		return false;
	}

	return true;
}

bool sockinfo_tcp::is_writeable()
{
	if (m_sock_state == TCP_SOCK_ASYNC_CONNECT) {
		if (m_conn_state == TCP_CONN_CONNECTED) {
			si_tcp_logdbg("++++ async connect ready");
			m_sock_state = TCP_SOCK_CONNECTED_RDWR;
			goto noblock;
		}
		else if (m_conn_state != TCP_CONN_CONNECTING) {
			// async connect failed for some reason. Reset our state and return ready fd
			si_tcp_logerr("async connect failed");
			if(m_sock_state != TCP_SOCK_BOUND) { //Avoid binding twice
				m_sock_state = TCP_SOCK_INITED;
			}
			goto noblock;
		}
		return false;
	}
	if (!is_rts()) {
	       // unconnected tcp sock is always ready for write! - TODO: verify!
	       // return its fd as ready
		si_tcp_logdbg("block check on unconnected socket");
               goto noblock;
       }

       if (tcp_sndbuf(&m_pcb) > 0)
	       goto noblock;

       //g_p_lwip->do_timers(); //TODO: consider!
       return false;

noblock:
/*
       if (p_fd_array) {
               p_fd_array->fd_list[p_fd_array->fd_count] = m_fd;
               p_fd_array->fd_count++;
       }
*/
	__log_funcall("--->>> tcp_sndbuf(&m_pcb)=%d", tcp_sndbuf(&m_pcb));
	return true;
}

bool sockinfo_tcp::is_errorable(int *errors)
{
	*errors = 0;

	if (m_conn_state == TCP_CONN_ERROR ||
	    m_conn_state == TCP_CONN_TIMEOUT ||
	    m_conn_state == TCP_CONN_RESETED ||
	    m_conn_state == TCP_CONN_FAILED) {
		*errors |= POLLHUP;
	}

	if (m_conn_state == TCP_CONN_ERROR) {
		*errors |= POLLERR;
	}

	return *errors;
}

/*
 * FIXME: need to split sock connected state in two: TCP_SOCK_CON_TX/RX
 */
int sockinfo_tcp::shutdown(int __how)
{
	err_t err = ERR_OK;

	int shut_rx, shut_tx;

	// if in os pathrough just redirect to os
	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		si_tcp_logdbg("passthrough - go to OS shutdown()");
		return orig_os_api.shutdown(m_fd, __how);
	}

	lock_tcp_con();

	shut_tx = shut_rx = 0;
	switch (__how) {
		case SHUT_RD:
			if (is_connected()) { 
				m_sock_state = TCP_SOCK_CONNECTED_WR;
				NOTIFY_ON_EVENTS(this, EPOLLIN);
			}
			else if (is_rtr()) { 
				m_sock_state = TCP_SOCK_BOUND;
				NOTIFY_ON_EVENTS(this, EPOLLIN|EPOLLHUP);
			}
			else if (m_sock_state == TCP_SOCK_ACCEPT_READY) {
				m_sock_state = TCP_SOCK_ACCEPT_SHUT;
			}
			else goto bad_state;
			shut_rx = 1;
			break;
		case SHUT_WR:
			if (is_connected()) { 
				m_sock_state = TCP_SOCK_CONNECTED_RD;
			}
			else if (is_rts()) { 
				m_sock_state = TCP_SOCK_BOUND;
				NOTIFY_ON_EVENTS(this, EPOLLHUP);				
			}
			else if (is_server()) {
				//ignore SHUT_WR on listen socket
			}
			else goto bad_state;
			shut_tx = 1;
			break;
		case SHUT_RDWR:
			if (is_connected() || is_rts() || is_rtr()) {
				m_sock_state = TCP_SOCK_BOUND;
				NOTIFY_ON_EVENTS(this, EPOLLIN|EPOLLHUP);				
			}
			else if (m_sock_state == TCP_SOCK_ACCEPT_READY) {
				m_sock_state = TCP_SOCK_ACCEPT_SHUT;
			}
			else goto bad_state;
			shut_rx = 1;
			shut_tx = 1;
			break;
		BULLSEYE_EXCLUDE_BLOCK_START
		default:
			si_tcp_logerr("unknow shutdown option %d", __how);
			break;
		BULLSEYE_EXCLUDE_BLOCK_END
	}	

	if (is_server()) {
		if (shut_rx) {
			tcp_accept(&m_pcb, 0);
			tcp_syn_handled((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::syn_received_drop_lwip_cb);
		}
	} else {
		if (get_tcp_state(&m_pcb) != LISTEN && shut_rx && m_n_rx_pkt_ready_list_count) {
			abort_connection();
		} else {
			err = tcp_shutdown(&m_pcb, shut_rx, shut_tx);
		}
	}

	do_wakeup();

	if (err == ERR_OK) {
		unlock_tcp_con();
		return 0;
	}
	
bad_state:
	unlock_tcp_con();
	errno = ENOTCONN;
	return -1;
}

/* 
 * TCP options from netinet/tcp.h
 * including file directly conflicts with lwipopts.h (TCP_MSS define)
 */
/*
 * User-settable options (used with setsockopt).
 */
#define TCP_NODELAY      1      /* Don't delay send to coalesce packets  */
#define TCP_MAXSEG       2      /* Set maximum segment size  */
#define TCP_CORK         3      /* Control sending of partial frames  */
#define TCP_KEEPIDLE     4      /* Start keeplives after this period */
#define TCP_KEEPINTVL    5      /* Interval between keepalives */
#define TCP_KEEPCNT      6      /* Number of keepalives before death */
#define TCP_SYNCNT       7      /* Number of SYN retransmits */
#define TCP_LINGER2      8      /* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT 9      /* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP 10     /* Bound advertised window */
#define TCP_INFO         11     /* Information about this connection. */
#define TCP_QUICKACK     12     /* Block/reenable quick ACKs.  */

int sockinfo_tcp::fcntl(int __cmd, unsigned long int __arg)
{
	if (!safe_mce_sys().avoid_sys_calls_on_tcp_fd || !is_connected())
		return sockinfo::fcntl(__cmd, __arg);

	switch (__cmd) {
	case F_SETFL:		/* Set file status flags.  */
		{
			si_tcp_logdbg("cmd=F_SETFL, arg=%#x", __arg);
			if (__arg & O_NONBLOCK)
				set_blocking(false);
			else
				set_blocking(true);
			return 0;
		}
		break;
	case F_GETFL:		/* Get file status flags.  */
		{
			si_tcp_logdbg("cmd=F_GETFL");
			if (m_b_blocking)
				return 0;
			else
				return O_NONBLOCK;
		}
		break;
	default:
		break;
	}
	return sockinfo::fcntl(__cmd, __arg);
}

int sockinfo_tcp::ioctl(unsigned long int __request, unsigned long int __arg)
{
	if (!safe_mce_sys().avoid_sys_calls_on_tcp_fd || !is_connected())
		return sockinfo::ioctl(__request, __arg);

	int *p_arg = (int *)__arg;

	switch (__request) {
	case FIONBIO:
		{
			si_tcp_logdbg("request=FIONBIO, arg=%d", *p_arg);
			if (*p_arg)
				set_blocking(false);
			else
				set_blocking(true);
			return 0;
		}
		break;
	default:
		break;
	}
	return sockinfo::ioctl(__request, __arg);
}

void sockinfo_tcp::fit_rcv_wnd(bool force_fit)
{
	m_pcb.rcv_wnd_max_desired = MIN(TCP_WND_SCALED(&m_pcb), m_rcvbuff_max);

	if (force_fit) {
		int rcv_wnd_max_diff = m_pcb.rcv_wnd_max_desired - m_pcb.rcv_wnd_max;

		m_pcb.rcv_wnd_max = m_pcb.rcv_wnd_max_desired;
		m_pcb.rcv_wnd = MAX(0, (int)m_pcb.rcv_wnd + rcv_wnd_max_diff);
		m_pcb.rcv_ann_wnd = MAX(0, (int)m_pcb.rcv_ann_wnd + rcv_wnd_max_diff);

		if (!m_pcb.rcv_wnd) {
			m_rcvbuff_non_tcp_recved = m_pcb.rcv_wnd_max;
		}
	} else if (m_pcb.rcv_wnd_max_desired >  m_pcb.rcv_wnd_max) {
		uint32_t rcv_wnd_max_diff = m_pcb.rcv_wnd_max_desired - m_pcb.rcv_wnd_max;
		m_pcb.rcv_wnd_max = m_pcb.rcv_wnd_max_desired;
		m_pcb.rcv_wnd += rcv_wnd_max_diff;
		m_pcb.rcv_ann_wnd += rcv_wnd_max_diff;
	}

}

void sockinfo_tcp::fit_snd_bufs(unsigned int new_max_snd_buff)
{
	uint32_t sent_buffs_num = 0;

	sent_buffs_num = m_pcb.max_snd_buff - m_pcb.snd_buf;
	if (sent_buffs_num <= new_max_snd_buff) {
		m_pcb.max_snd_buff = new_max_snd_buff;
		if (m_pcb.mss)
			m_pcb.max_unsent_len = (16 * (m_pcb.max_snd_buff)/m_pcb.mss); 
		else
			m_pcb.max_unsent_len = (16 * (m_pcb.max_snd_buff)/536); /* should MSS be 0 use a const...very unlikely */
		/* make sure max_unsent_len is not 0 */
		m_pcb.max_unsent_len = MAX(m_pcb.max_unsent_len, 1);
		m_pcb.snd_buf = m_pcb.max_snd_buff - sent_buffs_num;
	}
}

void sockinfo_tcp::fit_snd_bufs_to_nagle(bool disable_nagle)
{
	if (m_sndbuff_max)
		return;

	if (disable_nagle) {
		fit_snd_bufs(TCP_SND_BUF_NO_NAGLE);
	} else {
		fit_snd_bufs(TCP_SND_BUF);
	}
}

////////////////////////////////////////////////////////////////////////////////
bool sockinfo_tcp::try_un_offloading() // un-offload the socket if possible
{
	// be conservative and avoid off-loading a socket after it started connecting
	return m_conn_state == TCP_CONN_INIT ? sockinfo::try_un_offloading() : false;
}

////////////////////////////////////////////////////////////////////////////////
#define SOCKOPT_HANDLE_BY_OS -2
int sockinfo_tcp::setsockopt(int __level, int __optname,
                              __const void *__optval, socklen_t __optlen)
{
	//todo check optlen and set proper errno on failure
	si_tcp_logfunc("level=%d, optname=%d", __level, __optname);

	int val, ret = 0;
	bool supported = true;
	bool allow_privileged_sock_opt = false;

	if ((ret = sockinfo::setsockopt(__level, __optname, __optval, __optlen)) != SOCKOPT_PASS_TO_OS) {
		if (ret == SOCKOPT_INTERNAL_VMA_SUPPORT &&
		    m_sock_state <= TCP_SOCK_ACCEPT_READY && __optval != NULL &&
		    is_inherited_option(__level, __optname))
			m_socket_options_list.push_back(new socket_option_t(__level, __optname,__optval, __optlen));
		return ret;
	}

	ret = 0;

	if (__level == IPPROTO_IP) {
		switch(__optname) {
		case IP_TOS: /* might be missing ECN logic */
			ret = SOCKOPT_HANDLE_BY_OS;
			if (__optlen == sizeof(int)) {
				val = *(int *)__optval;
			} else if (__optlen == sizeof(uint8_t)) {
				val = *(uint8_t *)__optval;
			} else {
				break;
			}
			val &= ~INET_ECN_MASK;
			val |= m_pcb.tos & INET_ECN_MASK;
			if (m_pcb.tos != val) {
				lock_tcp_con();
				m_pcb.tos = val;
				header_tos_updater du(m_pcb.tos);
				update_header_field(&du);
				// lists.openwall.net/netdev/2009/12/21/59
				int new_prio = ip_tos2prio[IPTOS_TOS(m_pcb.tos) >> 1];
				set_sockopt_prio(&new_prio, sizeof(new_prio));
				unlock_tcp_con();

			}
		break;
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			supported = false;
			break;
		}
	}
	if (__level == IPPROTO_TCP) {
		switch(__optname) {
		case TCP_NODELAY:
			val = *(int *)__optval;
			lock_tcp_con();
			if (val)
				tcp_nagle_disable(&m_pcb);
			else
				tcp_nagle_enable(&m_pcb);
			fit_snd_bufs_to_nagle(val);
			unlock_tcp_con();
			si_tcp_logdbg("(TCP_NODELAY) nagle: %d", val);
			break;	
		case TCP_QUICKACK:
			val = *(int *)__optval;
			lock_tcp_con();
			m_pcb.quickack = (uint8_t)(val > 0 ? val : 0);
			unlock_tcp_con();
			si_tcp_logdbg("(TCP_QUICKACK) value: %d", val);
			break;
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			supported = false;
			break;	
		}
	}
	if (__level == SOL_SOCKET) {
		switch(__optname) {
		case SO_REUSEADDR:
			val = *(int *)__optval;
			lock_tcp_con();
			if (val) 
				m_pcb.so_options |= SOF_REUSEADDR;
			else
				m_pcb.so_options &= ~SOF_REUSEADDR;
			ret = SOCKOPT_HANDLE_BY_OS; //SO_REUSEADDR is also relevant on OS
			unlock_tcp_con();
			si_tcp_logdbg("(SO_REUSEADDR) val: %d", val);
			break;
		case SO_KEEPALIVE:
			val = *(int *)__optval;
			lock_tcp_con();
			if (val) 
				m_pcb.so_options |= SOF_KEEPALIVE;
			else
				m_pcb.so_options &= ~SOF_KEEPALIVE;
			unlock_tcp_con();
			si_tcp_logdbg("(SO_KEEPALIVE) val: %d", val);
			break;
		case SO_RCVBUF:
			val = MIN(*(int *)__optval, safe_mce_sys().sysctl_reader.get_net_core_rmem_max());
			lock_tcp_con();
			// OS allocates double the size of memory requested by the application - not sure we need it.
			m_rcvbuff_max = MAX(2 * m_pcb.mss, 2 * val);

			fit_rcv_wnd(!is_connected());
			unlock_tcp_con();
			si_tcp_logdbg("setsockopt SO_RCVBUF: %d", m_rcvbuff_max);
			break;
		case SO_SNDBUF:
			val = MIN(*(int *)__optval, safe_mce_sys().sysctl_reader.get_net_core_wmem_max());
			lock_tcp_con();
			// OS allocates double the size of memory requested by the application - not sure we need it.
			m_sndbuff_max = MAX(2 * m_pcb.mss, 2 * val);
			fit_snd_bufs(m_sndbuff_max);
			unlock_tcp_con();
			si_tcp_logdbg("setsockopt SO_SNDBUF: %d", m_sndbuff_max);
			break;
		case SO_LINGER:
			if (__optlen < sizeof(struct linger)) {
				errno = EINVAL;
				break;
			}
			m_linger = *(struct linger*)__optval;
			si_tcp_logdbg("setsockopt SO_LINGER: l_onoff = %d, l_linger = %d", m_linger.l_onoff, m_linger.l_linger);
			break;
		case SO_RCVTIMEO:
		{
			if (__optlen < sizeof(struct timeval)) {
				errno = EINVAL;
				break;
			}
			struct timeval* tv = (struct timeval*)__optval;
			if (tv->tv_sec || tv->tv_usec)
				m_loops_timer.set_timeout_msec(tv->tv_sec*1000 + (tv->tv_usec ? tv->tv_usec/1000 : 0));
			else
				m_loops_timer.set_timeout_msec(-1);
			si_tcp_logdbg("SOL_SOCKET: SO_RCVTIMEO=%d", m_loops_timer.get_timeout_msec());
			break;
		}
		case SO_BINDTODEVICE:
			struct sockaddr_in sockaddr;
			allow_privileged_sock_opt = safe_mce_sys().allow_privileged_sock_opt;
			if (__optlen == 0 || ((char*)__optval)[0] == '\0') {
				m_so_bindtodevice_ip = INADDR_ANY;
			} else if (get_ipv4_from_ifname((char*)__optval, &sockaddr)) {
				si_tcp_logdbg("SOL_SOCKET, SO_BINDTODEVICE - NOT HANDLED, cannot find if_name");
				errno = EINVAL;
				ret = -1;
				break;
			} else {
				m_so_bindtodevice_ip = sockaddr.sin_addr.s_addr;

				if (!is_connected()) {
					/* Current implementation allows to create separate rings for tx and rx.
					 * tx ring is created basing on destination ip during connect() call,
					 * SO_BINDTODEVICE and routing table information
					 * whereas rx ring creation can be based on bound (local) ip
					 * As a result there are limitations in using this capability.
					 * Also we can not have bound information as
					 * (!m_bound.is_anyaddr() && !m_bound.is_local_loopback())
					 * and can not detect offload/non-offload socket
					 * Note:
					 * This inconsistency should be resolved.
					 */
					ip_address local_ip(m_so_bindtodevice_ip);

					lock_tcp_con();
					/* We need to destroy this if attach/detach receiver is not called
					 * just reference counter for p_nd_resources is updated on attach/detach
					 */
					if (NULL == create_nd_resources((const ip_address)local_ip)) {
						si_tcp_logdbg("Failed to get net device resources on ip %s", local_ip.to_str().c_str());
					}
					unlock_tcp_con();
				}
			}
			// handle TX side
			if (m_p_connected_dst_entry) {
				if (m_p_connected_dst_entry->is_offloaded()) {
					si_tcp_logdbg("SO_BINDTODEVICE will not work on already offloaded TCP socket");
					errno = EINVAL;
					return -1;
				} else {
					m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
				}
			}
			// TODO handle RX side
			si_tcp_logdbg("(SO_BINDTODEVICE) interface=%s", (char*)__optval);
			break;
		case SO_MAX_PACING_RATE: {
			struct vma_rate_limit_t rate_limit;

			if (!__optval) {
				errno = EINVAL;
				break;
			}
			if (sizeof(struct vma_rate_limit_t) == __optlen) {
				rate_limit = *(struct vma_rate_limit_t*)__optval; // value is in Kbits per second
			} else if (sizeof(uint32_t) == __optlen) {
				// value is in bytes per second
				rate_limit.rate = BYTE_TO_KB(*(uint32_t*)__optval); // value is in bytes per second
				rate_limit.max_burst_sz = 0;
				rate_limit.typical_pkt_sz = 0;
			} else {
				errno = EINVAL;
				break;
			}

			lock_tcp_con();
			ret = modify_ratelimit(m_p_connected_dst_entry, rate_limit);
			unlock_tcp_con();
			if (ret) {
				si_tcp_logdbg("error setting setsockopt SO_MAX_PACING_RATE: %d bytes/second ", rate_limit.rate);
			} else {
				si_tcp_logdbg("setsockopt SO_MAX_PACING_RATE: %d bytes/second ", rate_limit.rate);
			}
			return ret;
		}
		case SO_PRIORITY: {
			lock_tcp_con();
			if (set_sockopt_prio(__optval, __optlen)) {
				unlock_tcp_con();
				return -1;
			}
			unlock_tcp_con();
			ret = SOCKOPT_HANDLE_BY_OS;
			break;
		}
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			supported = false;
			break;
		}
	}

	if (m_sock_state <= TCP_SOCK_ACCEPT_READY && __optval != NULL && is_inherited_option(__level, __optname))
		m_socket_options_list.push_back(new socket_option_t(__level, __optname,__optval, __optlen));

	if (safe_mce_sys().avoid_sys_calls_on_tcp_fd && ret != SOCKOPT_HANDLE_BY_OS && is_connected())
		return ret;
	return setsockopt_kernel(__level, __optname, __optval, __optlen, supported, allow_privileged_sock_opt);
}

int sockinfo_tcp::getsockopt_offload(int __level, int __optname, void *__optval,
					socklen_t *__optlen)
{
	int ret = -1;

	if (!__optval || !__optlen) {
		errno = EFAULT;
		return ret;
	}

	if (0 == sockinfo::getsockopt(__level, __optname, __optval, __optlen)) {
		return 0;
	}

	switch (__level) {
	case IPPROTO_TCP:
		switch(__optname) {
		case TCP_NODELAY:
        		if (*__optlen >= sizeof(int)) {
        			*(int *)__optval = tcp_nagle_disabled(&m_pcb);
        			si_tcp_logdbg("(TCP_NODELAY) nagle: %d", *(int *)__optval);
        			ret = 0;
        		} else {
        			errno = EINVAL;
        		}
        		break;
		case TCP_QUICKACK:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = m_pcb.quickack;
				si_tcp_logdbg("(TCP_QUICKACK) value: %d", *(int *)__optval);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			break;
		}
		break;
	case SOL_SOCKET:
		switch(__optname) {
		case SO_ERROR:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = m_error_status;
				si_tcp_logdbg("(SO_ERROR) status: %d", m_error_status);
				m_error_status = 0;
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_REUSEADDR:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = m_pcb.so_options & SOF_REUSEADDR;
				si_tcp_logdbg("(SO_REUSEADDR) reuse: %d", *(int *)__optval);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_KEEPALIVE:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = (bool)(m_pcb.so_options & SOF_KEEPALIVE);
				si_tcp_logdbg("(SO_KEEPALIVE) keepalive: %d", *(int *)__optval);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_RCVBUF:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = m_rcvbuff_max;
				si_tcp_logdbg("(SO_RCVBUF) rcvbuf=%d", m_rcvbuff_max);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_SNDBUF:
			if (*__optlen >= sizeof(int)) {
				*(int *)__optval = m_sndbuff_max;
				si_tcp_logdbg("(SO_SNDBUF) sndbuf=%d", m_sndbuff_max);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_LINGER:
			if (*__optlen > 0) {
				memcpy(__optval, &m_linger, std::min<size_t>(*__optlen , sizeof(struct linger)));
				si_tcp_logdbg("(SO_LINGER) l_onoff = %d, l_linger = %d", m_linger.l_onoff, m_linger.l_linger);
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;
		case SO_RCVTIMEO:
			if (*__optlen >= sizeof(struct timeval)) {
				struct timeval* tv = (struct timeval*)__optval;
				tv->tv_sec = m_loops_timer.get_timeout_msec() / 1000;
				tv->tv_usec = (m_loops_timer.get_timeout_msec() % 1000) * 1000;
				si_tcp_logdbg("(SO_RCVTIMEO) msec=%d", m_loops_timer.get_timeout_msec());
				ret = 0;
			} else {
				errno = EINVAL;
			}
			break;

		case SO_BINDTODEVICE:
			//todo add support
			errno = ENOPROTOOPT;
			break;
		case SO_MAX_PACING_RATE:
			ret = sockinfo::getsockopt(__level, __optname, __optval, __optlen);
			break;
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			break;
		}
		break;
	case IPPROTO_IP:
		switch (__optname) {
		default:
			ret = SOCKOPT_HANDLE_BY_OS;
			break;
		}
		break;
	default:
		ret = SOCKOPT_HANDLE_BY_OS;
		break;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret && ret != SOCKOPT_HANDLE_BY_OS) {
		si_tcp_logdbg("getsockopt failed (ret=%d %m)", ret);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return ret;
}

int sockinfo_tcp::getsockopt(int __level, int __optname, void *__optval,
		socklen_t *__optlen)
{
	int ret = getsockopt_offload(__level, __optname, __optval, __optlen);
	if (ret != SOCKOPT_HANDLE_BY_OS)
		return ret;
	else {
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

	ret = orig_os_api.getsockopt(m_fd, __level, __optname, __optval, __optlen);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret) {
		si_tcp_logdbg("getsockopt failed (ret=%d %m)", ret);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return ret;
}

int sockinfo_tcp::getsockname(sockaddr *__name, socklen_t *__namelen)
{
	__log_info_func("");

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		si_tcp_logdbg("passthrough - go to OS getsockname");
		return orig_os_api.getsockname(m_fd, __name, __namelen);
	}

	// according to man address should be truncated if given struct is too small
	if (__name && __namelen) {
		if ((int)*__namelen < 0) {
			si_tcp_logdbg("negative __namelen is not supported: %d", *__namelen);
			errno = EINVAL;
			return -1;
		}

		if (*__namelen) {
			m_bound.get_sa(__name, *__namelen);
		}

		*__namelen = m_bound.get_socklen();
	}

	return 0;
}

int sockinfo_tcp::getpeername(sockaddr *__name, socklen_t *__namelen)
{
	__log_info_func("");

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		si_tcp_logdbg("passthrough - go to OS getpeername");
		return orig_os_api.getpeername(m_fd, __name, __namelen);
	}

	if (m_conn_state != TCP_CONN_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	// according to man address should be truncated if given struct is too small
	if (__name && __namelen) {
		if ((int)*__namelen < 0) {
			si_tcp_logdbg("negative __namelen is not supported: %d", *__namelen);
			errno = EINVAL;
			return -1;
		}

		if (*__namelen) {
			m_connected.get_sa(__name, *__namelen);
		}

		*__namelen = m_connected.get_socklen();
	}

	return 0;
}

int sockinfo_tcp::rx_wait_helper(int &poll_count, bool is_blocking)
{
	int ret;
	int n;
	uint64_t poll_sn = 0;
	rx_ring_map_t::iterator rx_ring_iter;
	epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];

	// poll for completion
	__log_info_func("");


	poll_count++;
	n  = 0;
	// if in listen state go directly to wait part

	consider_rings_migration();

	// There's only one CQ
	m_rx_ring_map_lock.lock();
	if (likely(m_p_rx_ring)) {
		n =  m_p_rx_ring->poll_and_process_element_rx(&poll_sn);
	}
	else { //There's more than one CQ, go over each one
		for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
			if (unlikely(rx_ring_iter->second->refcnt <= 0)) {
				__log_err("Attempt to poll illegal cq");
				continue;
			}
			ring* p_ring =  rx_ring_iter->first;
			//g_p_lwip->do_timers();
			n += p_ring->poll_and_process_element_rx(&poll_sn);
		}
	}
	m_rx_ring_map_lock.unlock();
	if (likely(n > 0)) { // got completions from CQ
		__log_entry_funcall("got %d elements sn=%llu", n, (unsigned long long)poll_sn);

		if (m_n_rx_pkt_ready_list_count)
			m_p_socket_stats->counters.n_rx_poll_hit++;
		return n;
	}

	// if in blocking accept state skip poll phase and go to sleep directly
        if (m_loops_timer.is_timeout() || !is_blocking) {
		errno = EAGAIN;
		return -1;
        }

	if (poll_count < m_n_sysvar_rx_poll_num || m_n_sysvar_rx_poll_num == -1) {
		return 0;
	}

	m_p_socket_stats->counters.n_rx_poll_miss++;
	// if we polling too much - go to sleep
	si_tcp_logfuncall("%d: too many polls without data blocking=%d", m_fd, is_blocking);
	if (g_b_exit) {
		errno = EINTR;
		return -1;
	}

	//arming CQs
	m_rx_ring_map_lock.lock();
	if (likely(m_p_rx_ring)) {
		ret = m_p_rx_ring->request_notification(CQT_RX, poll_sn);
		if (ret !=  0) {
			m_rx_ring_map_lock.unlock();
			return 0;
		}
	}
	else {
		for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
			if (rx_ring_iter->second->refcnt <= 0) {
				continue;
			}
			ring* p_ring = rx_ring_iter->first;
			if (p_ring) {
				ret = p_ring->request_notification(CQT_RX, poll_sn);
				if (ret !=  0) {
					m_rx_ring_map_lock.unlock();
					return 0;
				}
			}
		}
	}
	m_rx_ring_map_lock.unlock();

	//Check if we have a packet in receive queue before we going to sleep and
	//update is_sleeping flag under the same lock to synchronize between
	//this code and wakeup mechanism.

	lock_tcp_con();
	if (!m_n_rx_pkt_ready_list_count && !m_ready_conn_cnt)
	{
		going_to_sleep();
		unlock_tcp_con();
	}
	else
	{
		unlock_tcp_con();
		return 0;
	}

	//sleep on different CQs and OS listen socket
	ret = orig_os_api.epoll_wait(m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, m_loops_timer.time_left_msec());

	lock_tcp_con();
	return_from_sleep();
	unlock_tcp_con();

	if (ret <= 0)
		return ret;

	//If there is a ready packet in a queue we want to return to user as quickest as possible
	if(m_n_rx_pkt_ready_list_count)
		return 0;

	for (int event_idx = 0; event_idx < ret; event_idx++)
	{
		int fd = rx_epfd_events[event_idx].data.fd;
		if (is_wakeup_fd(fd))
		{ // wakeup event
			lock_tcp_con();
			remove_wakeup_fd();
			unlock_tcp_con();
			continue;
		}

		// Check if OS fd is ready for reading
		if (fd == m_fd) {
			continue;
		}

		// poll cq. fd == cq channel fd.
		cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
		if (p_cq_ch_info) {
			ring* p_ring = p_cq_ch_info->get_ring();
			if (p_ring) {
				p_ring->wait_for_notification_and_process_element(fd, &poll_sn);
			}
		}
	}
	return ret;
}

mem_buf_desc_t* sockinfo_tcp::get_next_desc(mem_buf_desc_t *p_desc)
{
	m_rx_pkt_ready_list.pop_front();
	m_p_socket_stats->n_rx_ready_pkt_count--;

	m_n_rx_pkt_ready_list_count--;
	if (p_desc->p_next_desc) {
		//vlog_printf(VLOG_ERROR, "detected chained pbufs! REF %u", p_desc->lwip_pbuf.pbuf.ref);
		mem_buf_desc_t *prev = p_desc;
		p_desc = p_desc->p_next_desc;
		prev->rx.sz_payload = prev->lwip_pbuf.pbuf.len;
		p_desc->rx.sz_payload = p_desc->lwip_pbuf.pbuf.tot_len = prev->lwip_pbuf.pbuf.tot_len - prev->lwip_pbuf.pbuf.len;
		p_desc->rx.n_frags = --prev->rx.n_frags;
		p_desc->rx.src = prev->rx.src;
		p_desc->inc_ref_count();
		m_rx_pkt_ready_list.push_front(p_desc);
		m_n_rx_pkt_ready_list_count++;
		m_p_socket_stats->n_rx_ready_pkt_count++;
		prev->lwip_pbuf.pbuf.next = NULL;
		prev->p_next_desc = NULL;
		prev->rx.n_frags = 1;
		reuse_buffer(prev);
	}
	else
		reuse_buffer(p_desc);
	if (m_n_rx_pkt_ready_list_count)
		return m_rx_pkt_ready_list.front();
	else
		return NULL;
}

mem_buf_desc_t* sockinfo_tcp::get_next_desc_peek(mem_buf_desc_t *pdesc, int& rx_pkt_ready_list_idx)
{

	if (unlikely(pdesc->p_next_desc)) {
		pdesc = pdesc->p_next_desc;
	}else if (rx_pkt_ready_list_idx < m_n_rx_pkt_ready_list_count) {
		pdesc = m_rx_pkt_ready_list[rx_pkt_ready_list_idx];
		rx_pkt_ready_list_idx++;
	}else {
		pdesc = NULL;
	}

	return pdesc;
}

timestamps_t* sockinfo_tcp::get_socket_timestamps()
{
	return &m_rx_timestamps;
}

void sockinfo_tcp::post_deqeue(bool release_buff)
{
	NOT_IN_USE(release_buff);
}

int sockinfo_tcp::zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) {
	NOT_IN_USE(p_flags);
	int total_rx = 0, offset = 0;
	int len = p_iov[0].iov_len - sizeof(vma_packets_t) - sizeof(vma_packet_t) - sizeof(iovec);
	mem_buf_desc_t* p_desc_iter;
	mem_buf_desc_t* prev;

	// Make sure there is enough room for the header
	if (len  < 0) {
		errno = ENOBUFS;
		return -1;
	}
	
	pdesc->rx.frag.iov_base 	= (uint8_t*)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
	pdesc->rx.frag.iov_len 	-= m_rx_pkt_ready_offset;
	p_desc_iter = pdesc;
	
	// Copy iov pointers to user buffer
	vma_packets_t *p_packets = (vma_packets_t*)p_iov[0].iov_base;
	p_packets->n_packet_num = 0;

	offset += sizeof(p_packets->n_packet_num); // skip n_packet_num size
	
	while(len >= 0 && m_n_rx_pkt_ready_list_count) {
		vma_packet_t *p_pkts = (vma_packet_t *)((char *)p_packets + offset);
		p_packets->n_packet_num++;
		p_pkts->packet_id = (void*)p_desc_iter;
		p_pkts->sz_iov = 0;
		while(len >= 0 && p_desc_iter) {
		
			p_pkts->iov[p_pkts->sz_iov++] = p_desc_iter->rx.frag;
			total_rx += p_desc_iter->rx.frag.iov_len;
			
			prev 		= p_desc_iter;
			p_desc_iter = p_desc_iter->p_next_desc;	
			if (p_desc_iter) {
				p_desc_iter->lwip_pbuf.pbuf.tot_len = prev->lwip_pbuf.pbuf.tot_len - prev->lwip_pbuf.pbuf.len;
				p_desc_iter->rx.n_frags = --prev->rx.n_frags;
				p_desc_iter->rx.src = prev->rx.src;
				p_desc_iter->inc_ref_count();
				prev->lwip_pbuf.pbuf.next = NULL;
				prev->p_next_desc = NULL;
				prev->rx.n_frags = 1;
			}
			len -= sizeof(iovec);
			offset += sizeof(iovec);
		}
		
		if (len < 0 && p_desc_iter){
			m_rx_pkt_ready_list.pop_front();
			m_rx_pkt_ready_list.push_front(p_desc_iter);
			break;
		}	
		m_rx_pkt_ready_list.pop_front();
		m_n_rx_pkt_ready_list_count--;
		m_p_socket_stats->n_rx_ready_pkt_count--;
		m_p_socket_stats->n_rx_zcopy_pkt_count++;

		if (m_n_rx_pkt_ready_list_count) 	
			p_desc_iter = m_rx_pkt_ready_list.front();
			
		len -= sizeof(vma_packet_t);
		offset += sizeof(vma_packet_t);
	}

	return total_rx;
}

void sockinfo_tcp::statistics_print(vlog_levels_t log_level /* = VLOG_DEBUG */)
{
	const char * const tcp_sock_state_str[] = {
	  "NA",
	  "TCP_SOCK_INITED",
	  "TCP_SOCK_BOUND",
	  "TCP_SOCK_LISTEN_READY",
	  "TCP_SOCK_ACCEPT_READY",
	  "TCP_SOCK_CONNECTED_RD",
	  "TCP_SOCK_CONNECTED_WR",
	  "TCP_SOCK_CONNECTED_RDWR",
	  "TCP_SOCK_ASYNC_CONNECT",
	  "TCP_SOCK_ACCEPT_SHUT",
	};

	const char * const tcp_conn_state_str[] = {
	  "TCP_CONN_INIT",
	  "TCP_CONN_CONNECTING",
	  "TCP_CONN_CONNECTED",
	  "TCP_CONN_FAILED",
	  "TCP_CONN_TIMEOUT",
	  "TCP_CONN_ERROR",
	  "TCP_CONN_RESETED",
	};
	struct tcp_pcb pcb;
	tcp_sock_state_e sock_state;
	tcp_conn_state_e conn_state;
	u32_t last_unsent_seqno = 0 , last_unacked_seqno = 0, first_unsent_seqno = 0, first_unacked_seqno = 0;
	u16_t last_unsent_len = 0 , last_unacked_len = 0, first_unsent_len = 0, first_unacked_len = 0;
	int rcvbuff_max, rcvbuff_current, rcvbuff_non_tcp_recved, rx_pkt_ready_list_size, rx_ctl_packets_list_size, rx_ctl_reuse_list_size;

	sockinfo::statistics_print(log_level);

	// Prepare data
	lock_tcp_con();

	pcb = m_pcb;

	if (m_pcb.unsent) {
		first_unsent_seqno = m_pcb.unsent->seqno;
		first_unsent_len = m_pcb.unsent->len;

		if (m_pcb.last_unsent) {
			last_unsent_seqno = m_pcb.last_unsent->seqno;
			last_unsent_len = m_pcb.last_unsent->len;
		}
	}

	if (m_pcb.unacked) {
		first_unacked_seqno = m_pcb.unacked->seqno;
		first_unacked_len = m_pcb.unacked->len;

		if (m_pcb.last_unacked) {
			last_unacked_seqno = m_pcb.last_unacked->seqno;
			last_unacked_len = m_pcb.last_unacked->len;
		}
	}

	sock_state = m_sock_state;
	conn_state = m_conn_state;
	rcvbuff_max = m_rcvbuff_max;
	rcvbuff_current = m_rcvbuff_current;
	rcvbuff_non_tcp_recved = m_rcvbuff_non_tcp_recved;
	rx_pkt_ready_list_size = m_rx_pkt_ready_list.size();
	rx_ctl_packets_list_size = m_rx_ctl_packets_list.size();
	rx_ctl_reuse_list_size = m_rx_ctl_reuse_list.size();

	unlock_tcp_con();

	// Socket data
	vlog_printf(log_level, "Socket state : %s\n", tcp_sock_state_str[sock_state]);
	vlog_printf(log_level, "Connection state : %s\n", tcp_conn_state_str[conn_state]);
	vlog_printf(log_level, "Receive buffer : m_rcvbuff_current %d, m_rcvbuff_max %d, m_rcvbuff_non_tcp_recved %d\n", rcvbuff_current, rcvbuff_max, rcvbuff_non_tcp_recved);
	vlog_printf(log_level, "Rx lists size : m_rx_pkt_ready_list %d, m_rx_ctl_packets_list %d, m_rx_ctl_reuse_list %d\n", rx_pkt_ready_list_size, rx_ctl_packets_list_size, rx_ctl_reuse_list_size);

	// PCB data
	vlog_printf(log_level, "PCB state : %s\n", tcp_state_str[get_tcp_state(&pcb)]);
	vlog_printf(log_level, "PCB flags : 0x%x\n", pcb.flags);
	vlog_printf(log_level, "Segment size : mss %hu, advtsd_mss %hu\n", pcb.mss, pcb.advtsd_mss);

	// Window scaling
	if (pcb.flags & TF_WND_SCALE) {
		vlog_printf(log_level, "Window scaling : ENABLED, rcv_scale %u, snd_scale %u\n", pcb.rcv_scale, pcb.snd_scale);

		// Receive and send windows
		vlog_printf(log_level, "Receive window : rcv_wnd %u (%u), rcv_ann_wnd %u (%u), rcv_wnd_max %u (%u), rcv_wnd_max_desired %u (%u)\n",
				pcb.rcv_wnd, RCV_WND_SCALE(&pcb, pcb.rcv_wnd), pcb.rcv_ann_wnd, RCV_WND_SCALE(&pcb, pcb.rcv_ann_wnd),
				pcb.rcv_wnd_max, RCV_WND_SCALE(&pcb, pcb.rcv_wnd_max),  pcb.rcv_wnd_max_desired, RCV_WND_SCALE(&pcb, pcb.rcv_wnd_max_desired));

		vlog_printf(log_level, "Send window : snd_wnd %u (%u), snd_wnd_max %u (%u)\n",
				pcb.snd_wnd, (pcb.snd_wnd >> pcb.snd_scale), pcb.snd_wnd_max, (pcb.snd_wnd_max >> pcb.snd_scale));
	} else {
		vlog_printf(log_level, "Window scaling : DISABLED\n");

		// Receive and send windows
		vlog_printf(log_level, "Receive window : rcv_wnd %u, rcv_ann_wnd %u, rcv_wnd_max %u, rcv_wnd_max_desired %u\n",
				pcb.rcv_wnd, pcb.rcv_ann_wnd, pcb.rcv_wnd_max, pcb.rcv_wnd_max_desired);

		vlog_printf(log_level, "Send window : snd_wnd %u, snd_wnd_max %u\n", pcb.snd_wnd, pcb.snd_wnd_max);
	}

	// Congestion variable
	vlog_printf(log_level, "Congestion : cwnd %u\n", pcb.cwnd);

	// Receiver variables
	vlog_printf(log_level, "Receiver data : rcv_nxt %u, rcv_ann_right_edge %u\n", pcb.rcv_nxt, pcb.rcv_ann_right_edge);

	// Sender variables
	vlog_printf(log_level, "Sender data : snd_nxt %u, snd_wl1 %u, snd_wl2 %u\n", pcb.snd_nxt, pcb.snd_wl1, pcb.snd_wl2);

	// Send buffer
	vlog_printf(log_level, "Send buffer : snd_buf %u, max_snd_buff %u\n", pcb.snd_buf, pcb.max_snd_buff);

	// Retransmission
	vlog_printf(log_level, "Retransmission : rtime %hd, rto %u, nrtx %u\n", pcb.rtime, pcb.rto, pcb.nrtx);

	// RTT
	vlog_printf(log_level, "RTT variables : rttest %u, rtseq %u\n", pcb.rttest, pcb.rtseq);

	// First unsent
	if (first_unsent_seqno) {
		vlog_printf(log_level, "First unsent : seqno %u, len %hu, seqno + len %u\n", first_unsent_seqno, first_unsent_len, first_unsent_seqno + first_unsent_len);

		// Last unsent
		if (last_unsent_seqno) {
			vlog_printf(log_level, "Last unsent : seqno %u, len %hu, seqno + len %u\n", last_unsent_seqno, last_unsent_len, last_unsent_seqno + last_unsent_len);
		}
	} else {
		vlog_printf(log_level, "First unsent : NULL\n");
	}

	// First unsent
	if (first_unacked_seqno) {
		vlog_printf(log_level, "First unacked : seqno %u, len %hu, seqno + len %u\n", first_unacked_seqno, first_unacked_len, first_unacked_seqno + first_unacked_len);

		// Last unacked
		if (last_unacked_seqno) {
			vlog_printf(log_level, "Last unacked : seqno %u, len %hu, seqno + len %u\n", last_unacked_seqno, last_unacked_len, last_unacked_seqno + last_unacked_len);
		}
	} else {
		vlog_printf(log_level, "First unacked : NULL\n");
	}

	// Acknowledge
	vlog_printf(log_level, "Acknowledge : lastack %u\n", pcb.lastack);

	// TCP timestamp
#if LWIP_TCP_TIMESTAMPS
	if (pcb.flags & TF_TIMESTAMP) {
		vlog_printf(log_level, "Timestamp : ts_lastacksent %u, ts_recent %u\n", pcb.ts_lastacksent, pcb.ts_recent);
	}
#endif
}

int sockinfo_tcp::free_packets(struct vma_packet_t *pkts, size_t count)
{
	int ret = 0;
	unsigned int 	index = 0;
	int bytes_to_tcp_recved;
	int total_rx = 0, offset = 0;
	mem_buf_desc_t 	*buff;
	char *buf = (char *)pkts;

	lock_tcp_con();
	for(index=0; index < count; index++){
		vma_packet_t *p_pkts = (vma_packet_t *)(buf + offset);
		buff = (mem_buf_desc_t*)p_pkts->packet_id;

		if (m_p_rx_ring && !m_p_rx_ring->is_member(buff->p_desc_owner)) {
			errno = ENOENT;
			ret = -1;
			break;
		}
		else if (m_rx_ring_map.find(buff->p_desc_owner->get_parent()) == m_rx_ring_map.end()) {
			errno = ENOENT;
			ret = -1;
			break;
		}

		total_rx += buff->rx.sz_payload;
		reuse_buffer(buff);
		m_p_socket_stats->n_rx_zcopy_pkt_count--;

		offset += p_pkts->sz_iov * sizeof(iovec) + sizeof(vma_packet_t);
	}

	if (total_rx > 0) {
		m_rcvbuff_current -= total_rx;
		// data that was not tcp_recved should do it now.
		if ( m_rcvbuff_non_tcp_recved > 0 ) {
			bytes_to_tcp_recved = min(m_rcvbuff_non_tcp_recved, total_rx);
			tcp_recved(&m_pcb, bytes_to_tcp_recved);
			m_rcvbuff_non_tcp_recved -= bytes_to_tcp_recved;
		}
	}
	
	unlock_tcp_con();
	return ret;
}

int sockinfo_tcp::free_buffs(uint16_t len)
{
	tcp_recved(&m_pcb, len);
	return 0;
}

struct pbuf * sockinfo_tcp::tcp_tx_pbuf_alloc(void* p_conn)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)p_conn)->my_container);
	dst_entry_tcp *p_dst = (dst_entry_tcp *)(p_si_tcp->m_p_connected_dst_entry);
	mem_buf_desc_t* p_desc = NULL;
	if (likely(p_dst)) {
		p_desc = p_dst->get_buffer();
	}
	return (struct pbuf *)p_desc;
}

//single buffer only
void sockinfo_tcp::tcp_tx_pbuf_free(void* p_conn, struct pbuf *p_buff)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)p_conn)->my_container);
	dst_entry_tcp *p_dst = (dst_entry_tcp *)(p_si_tcp->m_p_connected_dst_entry);
	if (likely(p_dst)) {
		p_dst->put_buffer((mem_buf_desc_t *)p_buff);
	} else if (p_buff){
		mem_buf_desc_t * p_desc = (mem_buf_desc_t *)p_buff;

		//potential race, ref is protected here by tcp lock, and in ring by ring_tx lock
		if (likely(p_desc->lwip_pbuf_get_ref_count()))
			p_desc->lwip_pbuf_dec_ref_count();
		else
			__log_err("ref count of %p is already zero, double free??", p_desc);

		if (p_desc->lwip_pbuf.pbuf.ref == 0) {
			p_desc->p_next_desc = NULL;
			g_buffer_pool_tx->put_buffers_thread_safe(p_desc);
		}
	}
}

struct tcp_seg * sockinfo_tcp::tcp_seg_alloc(void* p_conn)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)p_conn)->my_container);
	return p_si_tcp->get_tcp_seg();
}

void sockinfo_tcp::tcp_seg_free(void* p_conn, struct tcp_seg * seg)
{
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)p_conn)->my_container);
	p_si_tcp->put_tcp_seg(seg);
}

struct tcp_seg * sockinfo_tcp::get_tcp_seg()
{
	struct tcp_seg * head = NULL;
	if (!m_tcp_seg_list) {
		m_tcp_seg_list = g_tcp_seg_pool->get_tcp_segs(TCP_SEG_COMPENSATION);
		if (unlikely(!m_tcp_seg_list)) return NULL;
		m_tcp_seg_count += TCP_SEG_COMPENSATION;
	}

	head = m_tcp_seg_list;
	m_tcp_seg_list = head->next;
	head->next = NULL;
	m_tcp_seg_in_use++;

	return head;
}

void sockinfo_tcp::put_tcp_seg(struct tcp_seg * seg)
{
	if (unlikely(!seg)) return;

	seg->next = m_tcp_seg_list;
	m_tcp_seg_list = seg;
	m_tcp_seg_in_use--;
	if (m_tcp_seg_count > 2 * TCP_SEG_COMPENSATION && m_tcp_seg_in_use < m_tcp_seg_count / 2) {
		int count = (m_tcp_seg_count - m_tcp_seg_in_use) / 2;
		struct tcp_seg * next = m_tcp_seg_list;
		for (int i = 0; i < count - 1; i++) {
			next = next->next;
		}
		struct tcp_seg * head = m_tcp_seg_list;
		m_tcp_seg_list = next->next;
		next->next = NULL;
		g_tcp_seg_pool->put_tcp_segs(head);
		m_tcp_seg_count -= count;
	}
	return;
}

//tcp_seg_pool

tcp_seg_pool::tcp_seg_pool(int size) {
	m_tcp_segs_array = new struct tcp_seg[size];
	if (m_tcp_segs_array == NULL) {
		__log_dbg("TCP segments allocation failed");
		free_tsp_resources();
		throw_vma_exception("TCP segments allocation failed");
	}
	memset(m_tcp_segs_array, 0, sizeof(tcp_seg) * size);
	for (int i = 0; i < size - 1; i++) {
		m_tcp_segs_array[i].next = &m_tcp_segs_array[i + 1];
	}
	m_p_head = &m_tcp_segs_array[0];
}

tcp_seg_pool::~tcp_seg_pool() {
	free_tsp_resources();
}

void tcp_seg_pool::free_tsp_resources() {
	delete [] m_tcp_segs_array;
}

tcp_seg * tcp_seg_pool::get_tcp_segs(int amount) {
	tcp_seg *head, *next, *prev;
	if (unlikely(amount <= 0))
		return NULL;
	lock();
	head = next = m_p_head;
	prev = NULL;
	while (amount > 0 && next) {
		prev = next;
		next = next->next;
		amount--;
	}
	if (amount) {
		unlock();
		return NULL;
	}
	prev->next = NULL;
	m_p_head = next;
	unlock();
	return head;
}

void tcp_seg_pool::put_tcp_segs(tcp_seg * seg_list) {
	tcp_seg * next = seg_list;
	if (unlikely(!seg_list))
		return;

	while (next->next) {
		next = next->next;
	}

	lock();
	next->next = m_p_head;
	m_p_head = seg_list;
	unlock();
}


tcp_timers_collection::tcp_timers_collection(int period, int resolution)
{
	m_n_period = period;
	m_n_resolution = resolution;
	m_n_intervals_size = period/resolution;
	m_timer_handle = NULL;
	m_p_intervals = new timer_node_t*[m_n_intervals_size];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_intervals) {
		__log_dbg("failed to allocate memory");
		free_tta_resources();
		throw_vma_exception("failed to allocate memory");
	}

	BULLSEYE_EXCLUDE_BLOCK_END
	memset(m_p_intervals, 0, sizeof(timer_node_t*) * m_n_intervals_size);
	m_n_location = 0;
	m_n_next_insert_bucket = 0;
	m_n_count = 0;
}

tcp_timers_collection::~tcp_timers_collection()
{
	free_tta_resources();
}

void tcp_timers_collection::free_tta_resources(void)
{
	if (m_n_count) {
		for (int i = 0; i < m_n_intervals_size; i++) {
			if (m_p_intervals[i]) {
				remove_timer(m_p_intervals[i]);
			}
		}

		if (m_n_count) {
			__log_dbg("not all TCP timers have been removed, count=%d", m_n_count);
		}
	}

	delete[] m_p_intervals;
}

void tcp_timers_collection::clean_obj()
{
	if (is_cleaned()) {
		return ;
	}

	set_cleaned();
	m_timer_handle = NULL;
	if (g_p_event_handler_manager->is_running()) {
		g_p_event_handler_manager->unregister_timers_event_and_delete(this);
	} else {
		cleanable_obj::clean_obj();
	}
}

void tcp_timers_collection::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	timer_node_t* iter = m_p_intervals[m_n_location];
	while (iter) {
		__log_funcall("timer expired on %p", iter->handler);
		iter->handler->handle_timer_expired(iter->user_data);
		iter = iter->next;
	}
	m_n_location = (m_n_location + 1) % m_n_intervals_size;

	/* Processing all messages for the daemon */
	g_p_agent->progress();
}

void tcp_timers_collection::add_new_timer(timer_node_t* node, timer_handler* handler, void* user_data)
{
	node->handler = handler;
	node->user_data = user_data;
	node->group = this;
	node->next = NULL;
	node->prev = NULL;
	if (m_p_intervals[m_n_next_insert_bucket] != NULL) {
		m_p_intervals[m_n_next_insert_bucket]->prev = node;
		node->next = m_p_intervals[m_n_next_insert_bucket];
	}
	m_p_intervals[m_n_next_insert_bucket] = node;
	m_n_next_insert_bucket = (m_n_next_insert_bucket + 1) % m_n_intervals_size;

	if (m_n_count == 0) {
		m_timer_handle = g_p_event_handler_manager->register_timer_event(m_n_resolution , this, PERIODIC_TIMER, NULL);
	}
	m_n_count++;

	__log_dbg("new TCP timer handler [%p] was added", handler);
}

void tcp_timers_collection::remove_timer(timer_node_t* node)
{
	if (!node) return;

	node->group = NULL;

	if (node->prev) {
		node->prev->next = node->next;
	} else {
		for (int i = 0; i < m_n_intervals_size; i++) {
			if (m_p_intervals[i] == node) {
				m_p_intervals[i] = node->next;
				break;
			}
		}
	}

	if (node->next) {
		node->next->prev = node->prev;
	}

	m_n_count--;
	if (m_n_count == 0) {
		if (m_timer_handle) {
			g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
			m_timer_handle = NULL;
		}
	}

	__log_dbg("TCP timer handler [%p] was removed", node->handler);

	free(node);
}

void sockinfo_tcp::update_header_field(data_updater *updater)
{
	lock_tcp_con();

	if (m_p_connected_dst_entry) {
		updater->update_field(*m_p_connected_dst_entry);
	}

	unlock_tcp_con();
}
