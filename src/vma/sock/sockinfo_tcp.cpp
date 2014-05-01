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


#include <stdio.h>
#include <sys/time.h>
#include <net/if.h>

#include "vlogger/vlogger.h"
#include "vma/util/rdtsc.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/libvma.h"
#include "vma/event/event_handler_manager.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/vma_lwip.h"
#include "vma/iomux/io_mux_call.h"

#include "sock-redirect.h"
#include "fd_collection.h"
#include "sockinfo_tcp.h"
#include "vma/proto/dst_entry_tcp.h"
#include "vma/util/instrumentation.h"
#include "vma/util/bullseye.h"

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


#define TCP_SEG_COMPENSATION 64

tcp_seg_pool *g_tcp_seg_pool = NULL;
tcp_timers_collection* g_tcp_timers_collection = NULL;


sockinfo_tcp::sockinfo_tcp(int fd) :
        sockinfo(fd),
        m_conn_cond("tcp_sockinfo::m_conn_cond"),
        m_timer_handle(NULL),
        m_timer_pending(false)
{
	si_tcp_logfuncall("");

	m_bound.set_sa_family(AF_INET);
	m_protocol = PROTO_TCP;
	m_p_socket_stats->socket_type = SOCK_STREAM;

	m_sock_state = TCP_SOCK_INITED;
	m_conn_state = TCP_CONN_INIT;
	m_conn_timeout = CONNECT_DEFAULT_TIMEOUT_MS;
	m_sock_offload = TCP_SOCK_LWIP; // by default we try to accelerate
	si_tcp_logdbg("tcp socket created");

	tcp_pcb_init(&m_pcb, TCP_PRIO_NORMAL);

	si_tcp_logdbg("new pcb %p pcb state %d", &m_pcb, m_pcb.state);
	tcp_arg(&m_pcb, this);
	tcp_recv(&m_pcb, sockinfo_tcp::rx_lwip_cb);
	tcp_err(&m_pcb, sockinfo_tcp::err_lwip_cb);
	tcp_sent(&m_pcb, sockinfo_tcp::ack_recvd_lwip_cb);
	m_pcb.my_container = this;

	si_tcp_logdbg("TCP PCB FLAGS: 0x%x", m_pcb.flags);

	m_n_pbufs_rcvd = m_n_pbufs_freed = 0;

	m_parent = NULL;
	m_iomux_ready_fd_array = NULL;

	/* RCVBUF accounting */
	m_rcvbuff_max = 2*64*1024*1024; // defaults?
	m_rcvbuff_current = 0;
	m_rcvbuff_non_tcp_recved = 0;
	m_received_syn_num = 0;

	report_connected = false;

	m_call_orig_close_on_dtor = 0;

	m_error_status = 0;

	m_tcp_seg_count = 0;
	m_tcp_seg_in_use = 0;
	m_tcp_seg_list = g_tcp_seg_pool->get_tcp_segs(TCP_SEG_COMPENSATION);
	if (m_tcp_seg_list) m_tcp_seg_count += TCP_SEG_COMPENSATION;

	si_tcp_logfunc("done");
}

sockinfo_tcp::~sockinfo_tcp()
{
	si_tcp_logfunc("");

	if (!is_closable()) {
		//prepare to close wasn't called?
		prepare_to_close();
	}

	lock_tcp_con();
	destructor_helper();

	if (m_tcp_seg_in_use) {
		si_tcp_logwarn("still %d tcp segs in use!", m_tcp_seg_in_use);
	}
	if (m_tcp_seg_count) {
		g_tcp_seg_pool->put_tcp_segs(m_tcp_seg_list);
	}
	unlock_tcp_con();

	// hack to close conn as our tcp state machine is not really persistent
	// give a chance for remote to respond with FIN ACK or
	// else remote can be stack in LAST_ACK for about 2 min
#if 0  // can not do this now because tcp flow entry is nuked. will miss wakeup as the result
	sleep(1);
	int poll_cnt;
	poll_cnt = 0;
	rx_wait_helper(poll_cnt, false);
	//g_p_lwip->do_timers();
#endif
	//close(m_rx_epfd);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_call_orig_close_on_dtor) {
		si_tcp_logdbg("calling orig_os_close on dup %d of %d",m_call_orig_close_on_dtor, m_fd);
		orig_os_api.close(m_call_orig_close_on_dtor);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	si_tcp_logdbg("sock closed");
}

void sockinfo_tcp::clean_obj()
{
	set_cleaned();

	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
	g_p_event_handler_manager->unregister_timers_event_and_delete(this);
}

bool sockinfo_tcp::prepare_listen_to_close()
{
	//assume locked by sockinfo_tcp lock

	//remove the sockets from the accepted connections list
	while (!m_accepted_conns.empty())
	{
		sockinfo_tcp *new_sock = m_accepted_conns.front();
		new_sock->m_sock_state = TCP_SOCK_INITED;
		struct flow_tuple key;
		sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(new_sock->m_pcb));
		m_syn_received.erase(key);
		m_accepted_conns.pop_front();
		m_ready_conn_cnt--;
		new_sock->m_parent = NULL;
		new_sock->abort_connection();
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
		new_sock->m_parent = NULL;
		new_sock->abort_connection();
		close(new_sock->get_fd());
	}

	return true;
}

bool sockinfo_tcp::prepare_to_close(bool process_shutdown /* = false */)
{
	int poll_cnt;
	poll_cnt = 0;
	timeval start, current, elapsed;

	lock_tcp_con();

	si_tcp_logdbg("");

	bool is_listen_socket = is_server() || m_pcb.state == LISTEN;

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
		mem_buf_desc_t* p_rx_pkt_desc = m_rx_pkt_ready_list.front();
		m_rx_pkt_ready_list.pop_front();
		m_n_rx_pkt_ready_list_count--;
		m_p_socket_stats->n_rx_ready_pkt_count--;
		m_rx_ready_byte_count -= p_rx_pkt_desc->path.rx.sz_payload;
		m_p_socket_stats->n_rx_ready_byte_count -= p_rx_pkt_desc->path.rx.sz_payload;
		reuse_buffer(p_rx_pkt_desc);
	}

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


	notify_epoll_context(EPOLLHUP);

	//todo should we do this each time we get into prepare_to_close ?
	memset(&elapsed, 0,sizeof(timeval));
	gettime(&start);
	while (tv_to_msec(&elapsed) <= TCP_LINGER_TIME_MSEC && m_pcb.state != LISTEN && (m_pcb.unsent || m_pcb.unacked)) {
		rx_wait(poll_cnt, false);
		tcp_output(&m_pcb);
		gettime(&current);
		tv_sub(&current, &start, &elapsed);
	}

	unlock_tcp_con();

	return (is_closable());
}

// call this function if you won't be able to go through si_tcp dtor
// do not call this function twice
void sockinfo_tcp::force_close()
{
	si_tcp_logdbg("can't reach dtor - force closing the socket");

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
}

// This method will be on syn received on the passive side of a TCP connection
void sockinfo_tcp::create_dst_entry()
{
	if (!m_p_connected_dst_entry) {
		m_p_connected_dst_entry = new dst_entry_tcp(m_connected.get_in_addr(), m_connected.get_in_port(),
				m_bound.get_in_port(), m_fd);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!m_p_connected_dst_entry) {
			si_tcp_logpanic("Failed to allocate m_p_connected_dst_entry");
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
	if (m_b_closed) {
		return;
	}

	tcp_tmr(&m_pcb);
	m_timer_pending = false;
}

bool sockinfo_tcp::prepare_dst_to_send(bool is_accepted_socket)
{
	bool ret_val = false;

	if(m_p_connected_dst_entry) {
		ret_val = m_p_connected_dst_entry->prepare_to_send(is_accepted_socket);
	}
	return ret_val;
}


unsigned sockinfo_tcp::tx_wait(int & err, bool is_blocking)
{
	unsigned sz = tcp_sndbuf(&m_pcb);
	int poll_count = 0;
	si_tcp_logfunc("sz = %d rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
	err = 0;
	while(is_rts() && (sz = tcp_sndbuf(&m_pcb)) == 0) {
		err = rx_wait(poll_count, is_blocking);
		//AlexV:Avoid from going to sleep, for the blocked socket of course, since
		// progress engine may consume an arrived credit and it will not wakeup the
		//transmit thread.
		if (is_blocking) {
			poll_count = 0;
		}
		if (err < 0)
			return 0;
                if (unlikely(g_b_exit)) {
                        errno = EINTR;
                        return 0;
                }
	}
	si_tcp_logfunc("end sz=%d rx_count=%d", sz, m_n_rx_pkt_ready_list_count);
	return sz;
}

ssize_t sockinfo_tcp::tx(const tx_call_t call_type, const struct iovec* p_iov, const ssize_t sz_iov, const int flags, const struct sockaddr *__to, const socklen_t __tolen)
{
	int total_tx = 0;
	unsigned tx_size;
	err_t err;
	unsigned pos = 0;
	int ret = 0;
	int poll_count = 0;
	bool block_this_run = m_b_blocking && !(flags & MSG_DONTWAIT);

	if (m_sock_offload != TCP_SOCK_LWIP) {
#ifdef VMA_TIME_MEASURE
		INC_GO_TO_OS_TX_COUNT;
#endif
		
		ret = socket_fd_api::tx_os(call_type, p_iov, sz_iov, flags, __to, __tolen);
		save_stats_tx_os(ret);
		return ret;
	}

#ifdef VMA_TIME_MEASURE
	TAKE_T_TX_START;
#endif

retry_is_ready:

	if (!is_rts()) {

		if (m_conn_state == TCP_CONN_CONNECTING) {
			int poll_count = 0;
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
	si_tcp_logfunc("tx: iov=%p niovs=%d", p_iov, sz_iov);
	lock_tcp_con();
	for (int i = 0; i < sz_iov; i++) {
		si_tcp_logfunc("iov:%d base=%p len=%d", i, p_iov[i].iov_base, p_iov[i].iov_len);

		pos = 0;
		while (pos < p_iov[i].iov_len) {
			if (unlikely(!is_rts())) {
				si_tcp_logdbg("TX on disconnected socket");
				ret = -1;
				errno = ECONNRESET;
				goto err;
			}
			//tx_size = tx_wait();
			tx_size = tcp_sndbuf(&m_pcb);
			if (tx_size == 0) {
                                //force out TCP data before going on wait()
                                tcp_output(&m_pcb);
				// non blocking socket should return inorder not to tx_wait()
				if (!block_this_run) {
                                        if ( total_tx ) {
                                                goto done;
                                        }
                                        else {
                                                ret = -1;
                                                errno = EAGAIN;
                                                goto err;
                                        }
                                }

				tx_size = tx_wait(ret, block_this_run);
				if (ret < 0)
					goto err;
			}
			if (tx_size > p_iov[i].iov_len - pos)
				tx_size = p_iov[i].iov_len - pos;
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
			err = tcp_write(&m_pcb, (char *)p_iov[i].iov_base + pos, tx_size, 3);
			if (err != ERR_OK) {
				if (err == ERR_CONN) { // happens when remote drops during big write
					si_tcp_logdbg("connection closed: tx'ed = %d", total_tx);
					shutdown(SHUT_WR);
					if (total_tx > 0)
						goto done;
					errno = EPIPE;
					unlock_tcp_con();
#ifdef VMA_TIME_MEASURE
					INC_ERR_TX_COUNT;
#endif					
					return -1;
				}
				if (err != ERR_MEM) {
					// we should not get here...
					BULLSEYE_EXCLUDE_BLOCK_START
					si_tcp_logpanic("tcp_write return: %d", err);
					BULLSEYE_EXCLUDE_BLOCK_END
					//coverity unreachable code
					/*
					unlock_tcp_con();
#ifdef VMA_TIME_MEASURE
					INC_ERR_TX_COUNT;
#endif					
					return -1;
					*/
				}
				if (total_tx > 0) 
					goto done;

				ret = rx_wait(poll_count, block_this_run);
				if (ret < 0)
					goto err;

				//AlexV:Avoid from going to sleep, for the blocked socket of course, since
				// progress engine may consume an arrived credit and it will not wakeup the
				//transmit thread.
				if (block_this_run) {
					poll_count = 0;
				}
				//tcp_output(m_sock); // force data out
				//tcp_si_logerr("++ nomem tcp_write return: %d", err);
				goto retry_write;
			}
			pos += tx_size;
			total_tx += tx_size;
		}	
	}
done:	
	if (total_tx) {
		m_p_socket_stats->counters.n_tx_sent_byte_count += total_tx;
		m_p_socket_stats->counters.n_tx_sent_pkt_count++;
	}

	tcp_output(&m_pcb); // force data out
	unlock_tcp_con();

#ifdef VMA_TIME_MEASURE	
	TAKE_T_TX_END;
#endif

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
	
}

err_t sockinfo_tcp::ip_output(struct pbuf *p, void* v_p_conn, int is_rexmit)
{
	iovec iovec[64];
	struct iovec* p_iovec = iovec;
	tcp_iovec tcp_iovec; //currently we pass p_desc only for 1 size iovec, since for bigger size we allocate new buffers
	sockinfo_tcp *p_si_tcp = (sockinfo_tcp *)(((struct tcp_pcb*)v_p_conn)->my_container);
	dst_entry *p_dst = p_si_tcp->m_p_connected_dst_entry;
	int count = 1;

	if (likely(!p->next)) { // We should hit this case 99% of cases
		tcp_iovec.iovec.iov_base = p->payload;
		tcp_iovec.iovec.iov_len = p->len;
		tcp_iovec.p_desc = (mem_buf_desc_t*)p;
		p_iovec = (struct iovec*)&tcp_iovec;
	} else {
		for (count = 0; count < 64 && p; ++count) {
			iovec[count].iov_base = p->payload;
			iovec[count].iov_len = p->len;
			p = p->next;
		}

#if 1 // We don't expcet pbuf chain at all since we enabled  TCP_WRITE_FLAG_COPY and TCP_WRITE_FLAG_MORE in lwip
		if (p) {
			vlog_printf(VLOG_ERROR, "pbuf chain size > 64!!! silently dropped.");
			return ERR_OK;
		}
#endif
	}

	if (p_dst->try_migrate_ring(p_si_tcp->m_tcp_con_lock)) {
		p_si_tcp->m_p_socket_stats->counters.n_tx_migrations++;
	}

	if (likely((p_dst->is_valid()))) {
		p_dst->fast_send(p_iovec, count, false, is_rexmit);
	} else {
		p_dst->slow_send(p_iovec, count, false, is_rexmit);
	}
	return ERR_OK;
}

void sockinfo_tcp::err_lwip_cb(void *arg, err_t err)
{

	if (!arg) return;
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;
	vlog_printf(VLOG_DEBUG, "%s:%d [fd=%d] sock=%p lwip_pcb=%p err=%d\n", __func__, __LINE__, conn->m_fd, conn, &(conn->m_pcb), err);

	if (conn->m_pcb.state == LISTEN && err == ERR_RST) {
		vlog_printf(VLOG_ERROR, "listen socket should not receive RST");
		return;
	}

	conn->lock_tcp_con();

	if (conn->m_parent != NULL) {
		//in case we got RST before we accepted the connection
		int delete_fd = 0;
		if ((delete_fd = conn->m_parent->handle_child_FIN(conn))) {
			//close will clean sockinfo_tcp object and the opened OS socket
			conn->unlock_tcp_con();
			close(delete_fd);
			return;
		}
	}

	/*
	 * In case we got RESET from the other end we need to marked this socket as ready to read for epoll
	 */
	if ((conn->m_sock_state == TCP_SOCK_CONNECTED_RD || conn->m_sock_state == TCP_SOCK_CONNECTED_RDWR)
		&& conn->m_pcb.state != ESTABLISHED) {
		if (err == ERR_RST)
			conn->notify_epoll_context(EPOLLIN|EPOLLRDHUP);
		else
			conn->notify_epoll_context(EPOLLIN|EPOLLHUP);
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

	if (conn->m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(conn, conn->m_timer_handle);
		conn->m_timer_handle = NULL;
	}

	conn->do_wakeup();
	conn->unlock_tcp_con();
}

//Execute TCP timers of this connection
void sockinfo_tcp::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	si_tcp_logfunc("");

	// Set the pending flag before getting the lock, so in the rare case of
	// a race with unlock_tcp_con(), the timer will be called twice. If we set
	// the flag after trylock(), the timer may not be called in case of a race.
	m_timer_pending = true;
	if (m_tcp_con_lock.trylock()) {
		return;
	}

	tcp_timer();
	m_tcp_con_lock.unlock();
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
bool sockinfo_tcp::delay_orig_close_to_dtor()
{
	if (is_connected() && !m_call_orig_close_on_dtor) {
		int fd = dup(m_fd);
		if (fd != -1) {
			m_call_orig_close_on_dtor = fd;
		}
	}
	return m_call_orig_close_on_dtor;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void sockinfo_tcp::abort_connection()
{
	tcp_abort(&(m_pcb));
}

int sockinfo_tcp::handle_child_FIN(sockinfo_tcp* child_conn)
{
	lock_tcp_con();

	accepted_conns_deque_t::iterator conns_iter;
	for(conns_iter = m_accepted_conns.begin(); conns_iter != m_accepted_conns.end(); conns_iter++) {
		if (*(conns_iter) == child_conn) {
			unlock_tcp_con();
			return 0; //don't close conn, it can be accepted
		}
	}
	// remove the connection from m_syn_received and close it by caller
	struct flow_tuple key;
	sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(child_conn->m_pcb));
	if (!m_syn_received.erase(key)) {
		si_tcp_logfunc("Can't find the established pcb in syn received list");
	}
	else {
		si_tcp_logdbg("received FIN before accept() was called");
		m_received_syn_num--;
		child_conn->m_parent = NULL;
		unlock_tcp_con();
		child_conn->abort_connection();
		return (child_conn->get_fd());
	}
	unlock_tcp_con();
	return 0;
}

err_t sockinfo_tcp::ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t ack)
{
	NOT_IN_USE(ack);
	NOT_IN_USE(tpcb);
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;

	vlog_func_enter();
	conn->lock_tcp_con();

	// notify epoll
	conn->notify_epoll_context(EPOLLOUT);

	conn->unlock_tcp_con();

	vlog_func_exit();

	return ERR_OK;
}

err_t sockinfo_tcp::rx_lwip_cb(void *arg, struct tcp_pcb *tpcb,
                        struct pbuf *p, err_t err)
{

	int bytes_to_tcp_recved;
	int rcv_buffer_space;
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;

	//vlog_printf(VLOG_ERROR, "%s:%d %s\n", __func__, __LINE__, "RX CB");
	vlog_func_enter();
	conn->lock_tcp_con();

	//if is FIN
	if (unlikely(!p)) {

		if (conn->is_server()) {
			conn->unlock_tcp_con();
			vlog_printf(VLOG_ERROR, "listen socket should not receive FIN");
			if (tpcb->my_container != tpcb->callback_arg) {
				//make sure the child connection will get the fin, and will be closed properly.
				conn = (sockinfo_tcp *)(tpcb->my_container);
				conn->lock_tcp_con();
			} else {
				return ERR_OK;
			}
		}

		conn->notify_epoll_context(EPOLLIN|EPOLLRDHUP);
		io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);
		conn->do_wakeup();

		//tcp_close(&(conn->m_pcb));
		//TODO: should be a move into half closed state (shut rx) instead of complete close
		tcp_shutdown(&(conn->m_pcb), 1, 0);
		vlog_printf(VLOG_DEBUG, "%s:%d [fd=%d] null pbuf sock(%p %p) err=%d\n", __func__, __LINE__, conn->m_fd, &(conn->m_pcb), tpcb, err);

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
			if ((delete_fd = conn->m_parent->handle_child_FIN(conn))) {
				//close will clean sockinfo_tcp object and the opened OS socket
				conn->unlock_tcp_con();
				close(delete_fd);
				return ERR_ABRT;
			}
		}

		conn->unlock_tcp_con();
		return ERR_OK;
	}
	if (unlikely(err != ERR_OK)) {
		// notify io_mux
		conn->notify_epoll_context(EPOLLERR);
		conn->do_wakeup();
		vlog_printf(VLOG_ERROR, "%s:%d %s\n", __func__, __LINE__, "recv error!!!\n");
		pbuf_free(p);
		conn->m_sock_state = TCP_SOCK_INITED;
		conn->unlock_tcp_con();
		return err;
	}
	mem_buf_desc_t *p_first_desc = (mem_buf_desc_t *)p;

	p_first_desc->path.rx.sz_payload = p->tot_len;
	p_first_desc->n_frags = 0;

	mem_buf_desc_t *p_curr_desc = p_first_desc;

	pbuf *p_curr_buff = p;
	conn->m_connected.get_sa(p_first_desc->path.rx.src);

	while (p_curr_buff) {
		p_first_desc->n_frags++;
		p_curr_desc->path.rx.frag.iov_base = p_curr_buff->payload;
		p_curr_desc->path.rx.frag.iov_len = p_curr_buff->len;
		p_curr_desc->p_next_desc = (mem_buf_desc_t *)p_curr_buff->next;
		p_curr_buff = p_curr_buff->next;
		p_curr_desc = p_curr_desc->p_next_desc;
	}

	// Save rx packet info in our ready list
	conn->m_rx_pkt_ready_list.push_back(p_first_desc);
	conn->m_n_rx_pkt_ready_list_count++;
	conn->m_rx_ready_byte_count += p->tot_len;
	conn->m_p_socket_stats->n_rx_ready_byte_count += p->tot_len;
	conn->m_p_socket_stats->n_rx_ready_pkt_count++;
	conn->m_p_socket_stats->counters.n_rx_ready_pkt_max = max((uint32_t)conn->m_p_socket_stats->n_rx_ready_pkt_count, conn->m_p_socket_stats->counters.n_rx_ready_pkt_max);
	conn->m_p_socket_stats->counters.n_rx_ready_byte_max = max((uint32_t)conn->m_p_socket_stats->n_rx_ready_byte_count, conn->m_p_socket_stats->counters.n_rx_ready_byte_max);
	conn->return_rx_buffs((ring*)p_first_desc->p_desc_owner);

        // notify io_mux
	conn->notify_epoll_context(EPOLLIN);
	io_mux_call::update_fd_array(conn->m_iomux_ready_fd_array, conn->m_fd);


	//OLG: Now we should wakeup all threads that are sleeping on this socket.
	conn->do_wakeup();
	/*
	* RCVBUFF Accounting: tcp_recved here(stream into the 'internal' buffer) only if the user buffer is not 'filled'
	*/
	rcv_buffer_space = max(0, conn->m_rcvbuff_max-conn->m_rcvbuff_current);
	bytes_to_tcp_recved = min(rcv_buffer_space, (int)p->tot_len); 
        
	if (likely(bytes_to_tcp_recved > 0)) {
	    tcp_recved(&(conn->m_pcb), bytes_to_tcp_recved);
	}
	if (p->tot_len-bytes_to_tcp_recved > 0)
	    conn->m_rcvbuff_non_tcp_recved += p->tot_len-bytes_to_tcp_recved;
	conn->m_rcvbuff_current += p->tot_len;

	conn->unlock_tcp_con();

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

//
// FIXME: we should not require lwip lock for rx
//
ssize_t sockinfo_tcp::rx(const rx_call_t call_type, iovec* p_iov, ssize_t sz_iov, int* p_flags, sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
	int total_rx = 0;
	int ret = 0;
	int poll_count = 0;
	int bytes_to_tcp_recved;
	size_t total_iov_sz = 1;
	bool block_this_run = m_b_blocking && !(*p_flags & MSG_DONTWAIT);

	m_loops_timer.start();

	si_tcp_logfuncall("");
	if (unlikely(m_sock_offload != TCP_SOCK_LWIP)) {
#ifdef VMA_TIME_MEASURE
		INC_GO_TO_OS_RX_COUNT;
#endif
		ret = socket_fd_api::rx_os(call_type, p_iov, sz_iov, p_flags, __from, __fromlen, __msg);
		save_stats_rx_os(ret);
		return ret;
	}

#ifdef VMA_TIME_MEASURE
	TAKE_T_RX_START;
#endif

	if (unlikely((*p_flags & MSG_WAITALL) && !(*p_flags & MSG_PEEK))) {
		total_iov_sz = 0;
		for (int i = 0; i < sz_iov; i++) {
			total_iov_sz += p_iov[i].iov_len;
		}
	}

	si_tcp_logfunc("rx: iov=%p niovs=%d", p_iov, sz_iov);
	 /* poll rx queue till we have something */
	lock_tcp_con();

	while (m_rx_ready_byte_count < total_iov_sz) {
        	if (unlikely(g_b_exit)) {
			ret = -1;
			errno = EINTR;
			si_tcp_logdbg("returning with: EINTR");
			goto err;
		}
        	if (unlikely(!is_rtr())) {
			if (m_conn_state == TCP_CONN_INIT) {
				si_tcp_logdbg("RX on never connected socket");
				errno = ENOTCONN;
				ret = -1;
			} else if (m_conn_state == TCP_CONN_CONNECTING) {
				si_tcp_logdbg("RX while async-connect on socket");
				errno = EAGAIN;
				ret = -1;
			} else if (m_conn_state == TCP_CONN_RESETED) {
				si_tcp_logdbg("RX on reseted socket");
				m_conn_state = TCP_CONN_FAILED;
				errno = ECONNRESET;
				ret = -1;
			} else {
				si_tcp_logdbg("RX on disconnected socket - EOF");
				ret = 0;
			}
			goto err;
        	}
        	ret = rx_wait(poll_count, block_this_run);
        	if (unlikely(ret < 0)) goto err;
	}
	si_tcp_logfunc("something in rx queues: %d %p", m_n_rx_pkt_ready_list_count, m_rx_pkt_ready_list.front());

	total_rx = dequeue_packet(p_iov, sz_iov, (sockaddr_in *)__from, __fromlen, p_flags);


	/*
	* RCVBUFF Accounting: Going 'out' of the internal buffer: if some bytes are not tcp_recved yet  - do that.
	* The packet might not be 'acked' (tcp_recved) 
	* 
	*/
	if (!(*p_flags & MSG_PEEK)) {
		m_rcvbuff_current -= total_rx;


		// data that was not tcp_recved should do it now.
		if ( m_rcvbuff_non_tcp_recved > 0 ) {
			bytes_to_tcp_recved = min(m_rcvbuff_non_tcp_recved, total_rx);
			tcp_recved(&m_pcb, bytes_to_tcp_recved);
			m_rcvbuff_non_tcp_recved -= bytes_to_tcp_recved;
		}
	}

	 // do it later - may want to ack less frequently ???:

	unlock_tcp_con();
	si_tcp_logfunc("rx completed, %d bytes sent", total_rx);

#ifdef VMA_TIME_MEASURE
	if (0 < total_rx)
		TAKE_T_RX_END;
#endif

	return total_rx;
err:
#ifdef VMA_TIME_MEASURE
	INC_ERR_RX_COUNT;
#endif

	if (errno == EAGAIN)
		m_p_socket_stats->counters.n_rx_eagain++;
	else
		m_p_socket_stats->counters.n_rx_errors++;
	unlock_tcp_con();
	return ret;
}

inline void sockinfo_tcp::init_pbuf_custom(mem_buf_desc_t *p_desc)
{
	p_desc->lwip_pbuf.pbuf.flags = PBUF_FLAG_IS_CUSTOM;
	p_desc->lwip_pbuf.pbuf.len = p_desc->lwip_pbuf.pbuf.tot_len = (p_desc->sz_data - p_desc->transport_header_len);
	p_desc->lwip_pbuf.pbuf.ref = 1;
	p_desc->lwip_pbuf.pbuf.type = PBUF_REF;
	p_desc->lwip_pbuf.pbuf.next = NULL;
	p_desc->lwip_pbuf.pbuf.payload = (u8_t *)p_desc->p_buffer + p_desc->transport_header_len;
}

void sockinfo_tcp::register_timer()
{
	if( m_timer_handle == NULL) {
		m_timer_handle = g_p_event_handler_manager->register_timer_event(mce_sys.tcp_timer_resolution_msec , this, PERIODIC_TIMER, 0, g_tcp_timers_collection);
	}else {
		si_tcp_logdbg("register_timer was called more than once. Something might be wrong, or connect was called twice.");
	}
}

bool sockinfo_tcp::rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array)
{
	struct tcp_pcb* pcb = NULL;

	lock_tcp_con();
	m_iomux_ready_fd_array = (fd_array_t*)pv_fd_ready_array;

	if (unlikely(m_pcb.state == LISTEN)) {
		pcb = get_syn_received_pcb(p_rx_pkt_mem_buf_desc_info->path.rx.src.sin_addr.s_addr,
				p_rx_pkt_mem_buf_desc_info->path.rx.src.sin_port,
				p_rx_pkt_mem_buf_desc_info->path.rx.dst.sin_addr.s_addr,
				p_rx_pkt_mem_buf_desc_info->path.rx.dst.sin_port);
		if (!pcb) {
			pcb = &m_pcb;
		}
	}
	else {
		pcb = &m_pcb;
	}

	p_rx_pkt_mem_buf_desc_info->inc_ref_count();

	if (!p_rx_pkt_mem_buf_desc_info->path.rx.gro) init_pbuf_custom(p_rx_pkt_mem_buf_desc_info);
	else p_rx_pkt_mem_buf_desc_info->path.rx.gro = 0;

	L3_level_tcp_input((pbuf *)p_rx_pkt_mem_buf_desc_info, pcb);

	m_iomux_ready_fd_array = NULL;

	unlock_tcp_con();

	return true;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int sockinfo_tcp::prepareConnect(const sockaddr *, socklen_t ){
//int tcp_sockinfo::prepareConnect(const sockaddr *__to, socklen_t __tolen){

#if 0
	transport_t target_family;
	si_tcp_logfuncall("");

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH)
		return 1; //passthrough

	/* obtain the target address family */
	target_family = __vma_match_tcp_client(TRANS_VMA, __to, __tolen, mce_sys.app_id);
	si_tcp_logdbg("TRANSPORT: %s",__vma_get_transport_str(target_family));
	if (target_family == TRANS_OS) {
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
		return 1; //passthrough
	}

	// if (target_family == USE_VMA || target_family == USE_ULP || arget_family == USE_DEFAULT)

	// find our local address
	m_sock_offload = TCP_SOCK_LWIP;
#endif
	return 0; //offloaded
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

/**
 *  try to connect to the dest over RDMA cm
 *  try fallback to the OS connect (TODO)
 */ 
int sockinfo_tcp::connect(const sockaddr *__to, socklen_t __tolen)
{

	int ret;
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
		unlock_tcp_con();
		return -1;
	}
	// setup peer address
	// TODO: Currenlty we don't check the if __to is supported and legal
	// socket-redirect probably should do this
	m_connected.set(*((sockaddr *)__to));

	create_dst_entry();
	m_p_connected_dst_entry->prepare_to_send();

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
		return orig_os_api.connect(m_fd, __to, __tolen);
	} else {
		notify_epoll_context_fd_is_offloaded(); //remove fd from os epoll
	}

	if (m_bound.is_anyaddr()) {
		m_bound.set_in_addr(m_p_connected_dst_entry->get_src_addr());
		in_addr_t ip = m_bound.get_in_addr();
		tcp_bind(&m_pcb, (ip_addr_t*)(&ip), (ntohs(m_bound.get_in_port())));
	}
	m_conn_state = TCP_CONN_CONNECTING;
	attach_as_uc_receiver((role_t)NULL, true);

	if (m_rx_ring_map.size() == 1) {
		rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.begin();
		m_p_rx_ring = rx_ring_iter->first;
	}

	in_addr_t peer_ip_addr = m_connected.get_in_addr();

	int err = tcp_connect(&m_pcb, (ip_addr_t*)(&peer_ip_addr), ntohs(m_connected.get_in_port()), /*(tcp_connected_fn)*/sockinfo_tcp::connect_lwip_cb);
	if (err != ERR_OK) {
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
	ret = wait_for_conn_ready();
	// handle ret from async connect
	if (ret < 0) {
	        m_conn_state = TCP_CONN_ERROR;
                // errno is set and connect call must fail.
	        destructor_helper();
	        errno = ECONNREFUSED;
	        unlock_tcp_con();
                return -1;
	}
	m_sock_offload = TCP_SOCK_LWIP;	
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

	if (orig_os_api.bind(m_fd, __addr, __addrlen) < 0) {
		unlock_tcp_con();
		return -1;
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
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
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
			return -1;
		}
	}

	memset(&tmp_sin, 0, tmp_sin_len);
	getsockname((struct sockaddr *)&tmp_sin, &tmp_sin_len);
	lock_tcp_con();
	target_family = __vma_match_tcp_server(TRANS_VMA, mce_sys.app_id, (struct sockaddr *) &tmp_sin, tmp_sin_len);
	si_tcp_logdbg("TRANSPORT: %s, sock state = %d", __vma_get_transport_str(target_family), m_pcb.state);

	if (target_family == TRANS_OS || m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
		m_sock_state = TCP_SOCK_ACCEPT_READY;
	}
	else {

		// if (target_family == USE_VMA || target_family == USE_ULP || arget_family == USE_DEFAULT)
		m_sock_offload = TCP_SOCK_LWIP;
		m_sock_state = TCP_SOCK_LISTEN_READY;
	}

	unlock_tcp_con();
	return isPassthrough() ? 1 : 0;
}

int sockinfo_tcp::listen(int backlog)
{
	si_tcp_logfuncall("");

#if 0
	transport_t target_family;
	struct sockaddr_storage tmp_sin;
	socklen_t tmp_sinlen = sizeof(tmp_sin);

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) 
		return orig_os_api.listen(m_fd, backlog);

	if (m_sock_state != TCP_SOCK_BOUND) {
		// print error so we can better track apps not following our assumptions ;)
		si_tcp_logerr("socket is in wrong state for connect: %d", m_sock_state);
		errno = EINVAL;
		return -1;
	}

	if (orig_os_api.getsockname(m_fd, (struct sockaddr *) &tmp_sin, &tmp_sinlen)) {
		si_tcp_logerr("get sockname failed");
		return -1;
	}

	lock();
	target_family = __vma_match_tcp_server(TRANS_VMA, (struct sockaddr *) &tmp_sin, sizeof(tmp_sin), mce_sys.app_id);
	si_tcp_logdbg("TRANSPORT: %s", __vma_get_transport_str(target_family));
	si_tcp_logdbg("sock state = %d", m_sock->state);

	if (target_family == TRANS_OS) {
		if (orig_os_api.listen(m_fd, backlog) < 0) {
			unlock();
			return -1;
		}
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
		m_sock_state = TCP_SOCK_ACCEPT_READY;
		unlock();
		return 0;
	}
	// if (target_family == USE_VMA || target_family == USE_ULP || arget_family == USE_DEFAULT)
	m_sock_offload = TCP_SOCK_LWIP;
	//TODO unlock();
#endif
	//
        
	lock_tcp_con();


	if (is_server()) {
	// if listen is called again - only update the backlog
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

	if (m_pcb.state != LISTEN) {

		//Now we know that it is listen socket so we have to treate m_pcb as listen pcb
		//and update the relevant fields of tcp_listen_pcb.
		struct tcp_pcb tmp_pcb;
		memcpy(&tmp_pcb, &m_pcb, sizeof(struct tcp_pcb));
		tcp_listen_with_backlog((struct tcp_pcb_listen*)(&m_pcb), &tmp_pcb, backlog);
	}

	m_sock_state = TCP_SOCK_ACCEPT_READY;

	tcp_accept(&m_pcb, sockinfo_tcp::accept_lwip_cb);
	tcp_syn_handled((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::syn_received_lwip_cb);
	tcp_clone_conn((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::clone_conn_cb);

	attach_as_uc_receiver(ROLE_TCP_SERVER);
/*TODO ALEXR
 *
 	if (attach_as_uc_receiver(ROLE_TCP_SERVER)) {
		si_tcp_logdbg("Fallback the connection to os");
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
		return orig_os_api.listen(m_fd, backlog);
	}
//*/
	if (m_rx_ring_map.size()) {
		if (m_rx_ring_map.size() == 1) {
			rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.begin();
			m_p_rx_ring = rx_ring_iter->first;
		}
		si_tcp_logdbg("sock state = %d", m_pcb.state);
	}
	else {
		si_tcp_logdbg("Fallback the connection to os");
		m_sock_offload = TCP_SOCK_PASSTHROUGH;
		unlock_tcp_con();
		return orig_os_api.listen(m_fd, backlog);
	}

	// Calling to orig_listen() by default to monitor connection requests for not offloaded sockets
	BULLSEYE_EXCLUDE_BLOCK_START
	if (orig_os_api.listen(m_fd, backlog)) {
		si_tcp_logerr("orig_listen failed");
		unlock_tcp_con();
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Add the user's orig fd to the rx epfd handle
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = m_fd;
	int ret = orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_ADD, ev.data.fd, &ev);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(ret)) {
		if (errno == EEXIST) {
			si_tcp_logdbg("failed to add user's fd to internal epfd errno=%d (%m)", errno);
		} else {
			si_tcp_logpanic("failed to add user's fd to internal epfd errno=%d (%m)", errno);
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	unlock_tcp_con();
	return 0;

}

int sockinfo_tcp::accept_helper(struct sockaddr *__addr, socklen_t *__addrlen, int __flags /* = 0 */)
{
	sockinfo_tcp *ns;
	int poll_count = 0;
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

	if (!is_server()) {
		// print error so we can better track apps not following our assumptions ;)
		si_tcp_logdbg("socket is in wrong state for accept: %d", m_sock_state);
		errno = EINVAL;
		return -1;
	}

	si_tcp_logdbg("socket accept");

	lock_tcp_con();

	si_tcp_logdbg("sock state = %d", m_pcb.state);
	while (m_ready_conn_cnt == 0 && !g_b_exit) {
		if (m_sock_state == TCP_SOCK_ACCEPT_SHUT) {
			unlock_tcp_con();
			errno = EINVAL;
			return -1;
		}
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

	si_tcp_logdbg("sock state = %d", m_pcb.state);
	si_tcp_logdbg("socket accept - has some!!!");
	ns = m_accepted_conns.front();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!ns) {
		si_tcp_logpanic("no socket in accepted queue!!! ready count = %d", m_ready_conn_cnt);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// as long as we did not accept the new socket, the listen socket( AKA the parent) was responsible to pass all communication to the new socket.
	// once we done accepting it, we do not need the parent anymore. we set the pointer to the parent to NULL,
	// so we wont notify the parent with changes occurring to the new socket (such as receiving FIN, in rx_lwip_cb()), since the parent is not responsible for it anymore.
	ns->m_parent = NULL;

	m_accepted_conns.pop_front();
	m_ready_conn_cnt--;
	tcp_accepted(m_sock);

	//inherit TCP_NODELAY
	if (tcp_nagle_disabled(&m_pcb)) {
		tcp_nagle_disable(&(ns->m_pcb));
		ns->fit_snd_bufs_to_nagle(true);
	}

	if (ns->m_conn_state == TCP_CONN_INIT) { //in case m_conn_state is not in one of the error states
		ns->m_conn_state = TCP_CONN_CONNECTED;
	}

	unlock_tcp_con();
/*TODO ALEXR TX
	if (ns->register_as_uc_transmiter()) {
		return ERR_IF;
	}
	if (ns->attach_as_uc_receiver(role_t (NULL))) {
		//AlexV:TODO unregister the transmitter
		return ERR_IF;
	}
//*/
	ns->lock_tcp_con();
	ns->attach_as_uc_receiver(role_t (NULL), true); // TODO ALEXR
	ns->unlock_tcp_con();

	if (ns->m_rx_ring_map.size() == 1) {
		rx_ring_map_t::iterator rx_ring_iter = ns->m_rx_ring_map.begin();
		ns->m_p_rx_ring = rx_ring_iter->first;
	}

	struct flow_tuple key;
	sockinfo_tcp::create_flow_tuple_key_from_pcb(key, &(ns->m_pcb));

	//Since the pcb is already contained in connected sockinfo_tcp no need to keep it listen's socket SYN list
	if (!m_syn_received.erase(key)) {
		//Should we worry about that?
		vlog_printf(VLOG_DEBUG, "%s:%d: Can't find the established pcb in syn received list\n", __func__, __LINE__);
	}
	else {
		m_received_syn_num--;
	}

	if (__addr && __addrlen)
		ns->getpeername(__addr, __addrlen);	

	ns->m_p_socket_stats->connected_ip = ns->m_connected.get_in_addr();
	ns->m_p_socket_stats->connected_port = ns->m_connected.get_in_port();

	ns->m_p_socket_stats->bound_if = ns->m_bound.get_in_addr();
	ns->m_p_socket_stats->bound_port = ns->m_bound.get_in_port();

	if (__flags & SOCK_NONBLOCK)
		ns->fcntl(F_SETFL, O_NONBLOCK);
	if (__flags & SOCK_CLOEXEC)
		ns->fcntl(F_SETFD, FD_CLOEXEC);

        si_tcp_logdbg("CONN ACCEPTED: TCP PCB FLAGS: acceptor:0x%x newsock: fd=%d 0x%x new state: %d", m_pcb.flags, ns->m_fd, ns->m_pcb.flags, ns->m_pcb.state);
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

        BULLSEYE_EXCLUDE_BLOCK_START
        if (!si) {
                si_tcp_logerr("can not get accept socket from FD collection");
                close(fd);
                return 0;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        si->m_parent = this;

        si->m_sock_state = TCP_SOCK_BOUND;
        si->m_sock_offload = TCP_SOCK_LWIP;

        return si;
}


err_t sockinfo_tcp::accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err)
{
	sockinfo_tcp *conn = (sockinfo_tcp *)(arg);
	sockinfo_tcp *new_sock;

	if (!conn || !child_pcb) {
		return ERR_VAL;
	}
	conn->lock_tcp_con();

	vlog_printf(VLOG_DEBUG, "%s:%d: initial state=%x\n", __func__, __LINE__, conn->m_pcb.state);
	vlog_printf(VLOG_DEBUG, "%s:%d: accept cb: arg=%p, new pcb=%p err=%d\n",
			__func__, __LINE__, arg, child_pcb, err);
	if (err != ERR_OK) {
		vlog_printf(VLOG_ERROR, "%s:d: accept cb failed\n", __func__, __LINE__);
		conn->unlock_tcp_con();
		return err;
	}
	if (conn->m_sock_state != TCP_SOCK_ACCEPT_READY) {
		vlog_printf(VLOG_DEBUG, "%s:%d: socket is not accept ready!\n", __func__, __LINE__);
		conn->unlock_tcp_con();
		return ERR_RST;
	}
	// make new socket
	vlog_printf(VLOG_DEBUG, "%s:%d: new stateb4clone=%x\n", __func__, __LINE__, child_pcb->state);
	new_sock = (sockinfo_tcp*)child_pcb->my_container;

	if (!new_sock) {
		vlog_printf(VLOG_ERROR, "%s:d: failed to clone socket\n", __func__, __LINE__);
		conn->unlock_tcp_con();
		return ERR_RST;
	}

	tcp_arg(&(new_sock->m_pcb), new_sock);
	tcp_recv(&(new_sock->m_pcb), sockinfo_tcp::rx_lwip_cb);
	tcp_err(&(new_sock->m_pcb), sockinfo_tcp::err_lwip_cb);
	conn->m_accepted_conns.push_back(new_sock);
	conn->m_ready_conn_cnt++;
	new_sock->m_sock_state = TCP_SOCK_CONNECTED_RDWR;

	vlog_printf(VLOG_DEBUG, "%s:%d: listen(fd=%d) state=%x: new sock(fd=%d) state=%x\n", __func__, __LINE__, conn->m_fd, conn->m_pcb.state, new_sock->m_fd, new_sock->m_pcb.state);
	conn->notify_epoll_context(EPOLLIN);

	//OLG: Now we should wakeup all threads that are sleeping on this socket.
	conn->do_wakeup();
	//Now we should register the child socket to TCP timer
	new_sock->register_timer();

	conn->unlock_tcp_con();
	return ERR_OK;
}

void sockinfo_tcp::create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb)
{
	key = flow_tuple(pcb->local_ip.addr, htons(pcb->local_port), pcb->remote_ip.addr, htons(pcb->remote_port), PROTO_TCP);
}

struct tcp_pcb* sockinfo_tcp::get_syn_received_pcb(in_addr_t peer_ip, in_port_t peer_port, in_addr_t local_ip, in_port_t local_port)
{
	struct tcp_pcb* ret_val = NULL;
	syn_received_map_t::iterator itr;

	flow_tuple key(local_ip, local_port, peer_ip, peer_port, PROTO_TCP);

	itr = m_syn_received.find(key);
	if (itr != m_syn_received.end()) {
		ret_val = itr->second;
	}
	return ret_val;
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

	conn->lock_tcp_con();

	new_sock = conn->accept_clone();

	if (new_sock) {
		*newpcb = (struct tcp_pcb*)(&new_sock->m_pcb);
		new_sock->m_pcb.my_container = (void*)new_sock;
	}
	else {
		ret_val = ERR_MEM;
	}

	conn->unlock_tcp_con();
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

	listen_sock->lock_tcp_con();

	flow_tuple key;
	create_flow_tuple_key_from_pcb(key, newpcb);

	listen_sock->m_syn_received[key] =  newpcb;

	listen_sock->m_received_syn_num++;

	new_sock->set_conn_properties_from_pcb();
	new_sock->create_dst_entry();
	new_sock->prepare_dst_to_send(true); // true for passive socket to skip the transport rules checking

	listen_sock->unlock_tcp_con();

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

	listen_sock->lock_tcp_con();

	new_sock->set_conn_properties_from_pcb();
	new_sock->create_dst_entry();
	new_sock->prepare_dst_to_send(true); // true for passive socket to skip the transport rules checking

	tcp_arg(&(new_sock->m_pcb), new_sock);
	new_sock->abort_connection();

	listen_sock->unlock_tcp_con();

	close(new_sock->get_fd());

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

err_t sockinfo_tcp::connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
	sockinfo_tcp *conn = (sockinfo_tcp *)arg;
	NOT_IN_USE(tpcb);

	vlog_printf(VLOG_DEBUG, "%s:%d: connect cb: arg=%p, pcp=%p err=%d\n",
		__func__, __LINE__, arg, tpcb, err);

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
	}
	else {
		conn->m_error_status = ECONNREFUSED;
		conn->m_conn_state = TCP_CONN_FAILED;
	}
	
	// notify epoll
	conn->notify_epoll_context(EPOLLOUT);
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
		errno = ECONNREFUSED;
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
			goto noblock_nolock;
		}

		if (m_sock_state == TCP_SOCK_ACCEPT_SHUT) goto noblock_nolock;

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
		goto noblock_nolock;
	}

	if (m_n_rx_pkt_ready_list_count)
		goto noblock_nolock;

	if (!p_poll_sn)
		return false;

	consider_rings_migration();

	m_rx_ring_map_lock.lock();
	while(!g_b_exit && is_rtr()) {
	       if (likely(m_p_rx_ring)) {
		       // likely scenario: rx socket bound to specific cq
		       ret = m_p_rx_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
		       if (m_n_rx_pkt_ready_list_count)
			       goto noblock;
		       if (ret <= 0) {
			       break;
		       }
		}
		else {
			rx_ring_map_t::iterator rx_ring_iter;
			for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
				if (rx_ring_iter->second.refcnt <= 0) {
					continue;
				}
				ring* p_ring =  rx_ring_iter->first;
				//g_p_lwip->do_timers();
				ret = p_ring->poll_and_process_element_rx(p_poll_sn, p_fd_array);
				if (m_n_rx_pkt_ready_list_count)
					goto noblock;
				if (ret <= 0)
					break;
			}
		}
	}
	if (!m_n_rx_pkt_ready_list_count) {
		m_rx_ring_map_lock.unlock();
		return false;
	}
noblock:
	m_rx_ring_map_lock.unlock();
noblock_nolock:
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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int sockinfo_tcp::rx_request_notification(uint64_t poll_sn)
{
	NOT_IN_USE(poll_sn);
	si_tcp_logpanic("not implemented");
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif


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
				notify_epoll_context(EPOLLIN);
			}
			else if (is_rtr()) { 
				m_sock_state = TCP_SOCK_BOUND;
				notify_epoll_context(EPOLLIN|EPOLLHUP);
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
				notify_epoll_context(EPOLLHUP);
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
				notify_epoll_context(EPOLLIN|EPOLLHUP);
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
			si_tcp_logpanic("unknow shutdown option %d", __how);		
			break;
		BULLSEYE_EXCLUDE_BLOCK_END
	}	

	if (is_server()) {
		if (shut_rx) {
			tcp_accept(&m_pcb, 0);
			tcp_syn_handled((struct tcp_pcb_listen*)(&m_pcb), sockinfo_tcp::syn_received_drop_lwip_cb);
		}
	} else {
		if (m_pcb.state != LISTEN && shut_rx && m_n_rx_pkt_ready_list_count) {
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
#define TCP_QUICKACK     12     /* Bock/reenable quick ACKs.  */

void sockinfo_tcp::fit_snd_bufs_to_nagle(bool disable_nagle)
{
	uint32_t new_max_snd_buff = 0;
	uint32_t sent_buffs_num = 0;

	if (disable_nagle) {
		new_max_snd_buff = TCP_SND_BUF_NO_NAGLE;
	} else {
		new_max_snd_buff = TCP_SND_BUF;
	}
	sent_buffs_num = m_pcb.max_snd_buff - m_pcb.snd_buf;
	if (sent_buffs_num <= new_max_snd_buff) {
		m_pcb.max_snd_buff = new_max_snd_buff;
		m_pcb.max_unsent_len = (16 * (m_pcb.snd_buf)/(TCP_MSS));
		m_pcb.snd_buf = m_pcb.max_snd_buff - sent_buffs_num;
	}
}

int sockinfo_tcp::setsockopt(int __level, int __optname,
                              __const void *__optval, socklen_t __optlen)
{
	int val, ret;

	if (__level == IPPROTO_TCP) {
		switch(__optname) {
		case TCP_NODELAY:
			lock_tcp_con();
			val = *(int *)__optval;
			si_tcp_logdbg("(TCP_NODELAY) nagle: %d", val);
			if (val)
				tcp_nagle_disable(&m_pcb);
			else
				tcp_nagle_enable(&m_pcb);
			fit_snd_bufs_to_nagle(val);
			unlock_tcp_con();
			break;	
		default:
			break;	
		}
	}
	if (__level == SOL_SOCKET) {
		switch(__optname) {
		case SO_REUSEADDR:
			val = *(int *)__optval;
			if (val) 
				m_pcb.so_options |= SOF_REUSEADDR;
			else
				m_pcb.so_options &= ~SOF_REUSEADDR;
			break;
		case SO_KEEPALIVE:
			val = *(int *)__optval;
			if (val) 
				m_pcb.so_options |= SOF_KEEPALIVE;
			else
				m_pcb.so_options &= ~SOF_KEEPALIVE;
			break;
		case SO_RCVBUF:
			// OS allocates double the size of memory requested by the application - not sure we need it.
			m_rcvbuff_max = *(int*)__optval;
			si_tcp_logdbg("setsockopt SO_RCVBUF: %d", m_rcvbuff_max);
			break;

                case SO_RCVTIMEO:
                        if (__optval) {
                            struct timeval* tv = (struct timeval*)__optval;
                            if (tv->tv_sec || tv->tv_usec)
                        	    m_loops_timer.set_timeout_msec(tv->tv_sec*1000 + (tv->tv_usec ? tv->tv_usec/1000 : 0));
                            else
                        	    m_loops_timer.set_timeout_msec(-1);
                            si_tcp_logdbg("SOL_SOCKET: SO_RCVTIMEO=%d", m_loops_timer.get_timeout_msec());

                        }
			break;

                case SO_BINDTODEVICE:
                	if (__optval) {
                		struct sockaddr_in sockaddr;
                		if (__optlen == 0 || ((char*)__optval)[0] == '\0') {
                			m_so_bindtodevice_ip = 0;
                		} else if (get_ipv4_from_ifname((char*)__optval, &sockaddr)) {
                			si_tcp_logdbg("SOL_SOCKET, SO_BINDTODEVICE - NOT HANDLED, cannot find if_name");
                			break;
                		} else {
                			m_so_bindtodevice_ip = sockaddr.sin_addr.s_addr;
                		}
                		// handle TX side
                		if (m_p_connected_dst_entry) {
					if (m_p_connected_dst_entry->is_offloaded()) {
                				si_tcp_logdbg("SO_BINDTODEVICE will not work on already offloaded TCP socket");
						return -1;
                			} else {
                				m_p_connected_dst_entry->set_so_bindtodevice_addr(m_so_bindtodevice_ip);
					}
                		}
                		// TODO handle RX side
                	}
                	else {
                		si_tcp_logdbg("SOL_SOCKET, SO_BINDTODEVICE - NOT HANDLED, optval == NULL");
                	}
                	break;

		default:
			break;
		}
	}
	si_tcp_logdbg("level %d optname %d", __level, __optname);
        ret = orig_os_api.setsockopt(m_fd, __level, __optname, __optval, __optlen);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret) {
                si_tcp_logdbg("setsockopt failed (ret=%d %m)", ret);
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        return ret;
}

int sockinfo_tcp::getsockopt(int __level, int __optname, void *__optval,
                              socklen_t *__optlen)
{
        int ret = orig_os_api.getsockopt(m_fd, __level, __optname, __optval, __optlen);

        if (__level == SOL_SOCKET) {
        	switch(__optname) {
        	case SO_ERROR:
        		if (__optval && __optlen && *__optlen >= sizeof(int) && !isPassthrough()) {
        			*(int *)__optval = m_error_status;
        			m_error_status = 0;
        		}
        		break;
        	default:
        		break;
        	}
        }

        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret) {
                si_tcp_logerr("getsockopt failed (ret=%d %m)", ret);
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

/* TODO ALEXR
	if (!m_addr_local) {
		// if not a server socket get local address from LWIP
		errno = EINVAL;
		return -1;
	}
#//*/
	// according to man address should be truncated if given struct is too small
	if (__name && __namelen && (*__namelen >= m_bound.get_socklen())) {
		m_bound.get_sa(__name);
		return 0;
	}

	errno = EINVAL;
	return -1;
}

int sockinfo_tcp::getpeername(sockaddr *__name, socklen_t *__namelen)
{
	__log_info_func("");

	if (m_sock_offload == TCP_SOCK_PASSTHROUGH) {
		si_tcp_logdbg("passthrough - go to OS getpeername");
		return orig_os_api.getpeername(m_fd, __name, __namelen);
	}

	/* TODO ALEXR
	if (!m_addr_peer) {
		// if not a server socket get local address from LWIP
		errno = EINVAL;
		return -1;
	}
//*/
	if (m_conn_state != TCP_CONN_CONNECTED) {
		errno = ENOTCONN;
		return -1;
	}

	// according to man address should be truncated if given struct is too small
	if (__name && __namelen && (*__namelen >= m_connected.get_socklen())) {
		m_connected.get_sa(__name);
		return 0;
	}
	errno = EINVAL;
	return -1;
}

//code coverage
#if 0
struct sockaddr *sockinfo_tcp::sockaddr_realloc(struct sockaddr *old_addr, 
		socklen_t & old_len, socklen_t new_len)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (old_addr && old_len != new_len) {
		if (old_addr == 0) { si_tcp_logpanic("old_addr != 0"); }
		delete old_addr;
		old_addr = 0;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	if (old_addr == 0)
		old_addr = (struct sockaddr *)new char [new_len];
	old_len = new_len;
	return old_addr;
}
#endif

/* change default rx_wait impl to flow based one */
inline int sockinfo_tcp::rx_wait(int &poll_count, bool is_blocking)
{
        int ret_val = 0;
        unlock_tcp_con();
        ret_val = rx_wait_helper(poll_count, is_blocking);
        lock_tcp_con();
        return ret_val;
}

int sockinfo_tcp::rx_wait_helper(int &poll_count, bool is_blocking)
{
	int ret;
	int n;
	uint64_t poll_sn;
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
			if (unlikely(rx_ring_iter->second.refcnt <= 0)) {
				__log_panic("Attempt to poll illegal cq");
				//coverity unreachable code
				//continue;
			}
			ring* p_ring =  rx_ring_iter->first;
			//g_p_lwip->do_timers();
			n += p_ring->poll_and_process_element_rx(&poll_sn);
		}
	}
	m_rx_ring_map_lock.unlock();
	if (n > 0) { // got completions from CQ
		__log_entry_funcall("got %d elements sn=%llu", n, (unsigned long long)poll_sn);

		if (m_n_rx_pkt_ready_list_count)
			m_p_socket_stats->counters.n_rx_poll_hit++;
		return n;
	}

	// if in blocking accept state skip poll phase and go to sleep directly
#if 0
	if (unlikely(is_server() && is_blocking == true)) {
		si_tcp_logdbg("skip poll on accept!");
		goto skip_poll;
	}
#endif
        if (m_loops_timer.is_timeout() || !is_blocking) {
		errno = EAGAIN;
		return -1;
        }

	if (poll_count < mce_sys.rx_poll_num || mce_sys.rx_poll_num == -1) {
		return 0;
	}

	m_p_socket_stats->counters.n_rx_poll_miss++;
	// if we polling too much - go to sleep
	si_tcp_logfuncall("%d: too many polls without data blocking=%d", m_fd, is_blocking);
	if (g_b_exit) {
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
			if (rx_ring_iter->second.refcnt <= 0) {
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
				p_ring->wait_for_notification_and_process_element(CQT_RX, fd, &poll_sn);
			}
		}
	}
	return ret;
}

//This method should be called with the CQ manager lock.
inline void sockinfo_tcp::return_rx_buffs(ring* p_ring)
{
	if (likely(m_p_rx_ring == p_ring)) {
		if (unlikely(m_rx_reuse_buff.n_buff_num > m_rx_num_buffs_reuse)) {
			if (p_ring->reclaim_recv_buffers_no_lock(&m_rx_reuse_buff.rx_reuse)) {
				m_rx_reuse_buff.n_buff_num = 0;
			}
		}
	}
	else {
		if (likely(p_ring)) {
			rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(p_ring);

			if (likely(rx_ring_iter != m_rx_ring_map.end())) {
				std::deque<mem_buf_desc_t*> *rx_reuse = &rx_ring_iter->second.rx_reuse_info.rx_reuse;
				if (rx_ring_iter->second.rx_reuse_info.n_buff_num > m_rx_num_buffs_reuse) {
					if (p_ring->reclaim_recv_buffers_no_lock(rx_reuse)) {
						rx_ring_iter->second.rx_reuse_info.n_buff_num = 0;
					}
				}
			}
		}
	}
}

inline void sockinfo_tcp::reuse_buffer(mem_buf_desc_t *buff)
{
	if (likely(m_p_rx_ring)) {
		m_rx_reuse_buff.n_buff_num += buff->n_frags;
		m_rx_reuse_buff.rx_reuse.push_back(buff);
		if (m_rx_reuse_buff.n_buff_num > m_rx_num_buffs_reuse) {
			if (m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
				m_rx_reuse_buff.n_buff_num = 0;
	                } else if (m_rx_reuse_buff.n_buff_num > 2 * m_rx_num_buffs_reuse) {
	                	g_buffer_pool_rx->put_buffers_thread_safe(&m_rx_reuse_buff.rx_reuse, m_rx_reuse_buff.rx_reuse.size());
	                	m_rx_reuse_buff.n_buff_num = 0;
	                }
		}
	}
	else {
		sockinfo::reuse_buffer(buff);
	}
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
		p_desc->lwip_pbuf.pbuf.tot_len = prev->lwip_pbuf.pbuf.tot_len - prev->lwip_pbuf.pbuf.len;
		p_desc->n_frags = --prev->n_frags;
		p_desc->path.rx.src = prev->path.rx.src;
		p_desc->inc_ref_count();
		m_rx_pkt_ready_list.push_front(p_desc);
		m_n_rx_pkt_ready_list_count++;
		m_p_socket_stats->n_rx_ready_pkt_count++;
		prev->lwip_pbuf.pbuf.next = NULL;
		prev->p_next_desc = NULL;
		prev->n_frags = 1;
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

void sockinfo_tcp::post_deqeue(bool release_buff)
{
	NOT_IN_USE(release_buff);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int sockinfo_tcp::zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) {
	NOT_IN_USE(p_iov);
	NOT_IN_USE(pdesc);
	NOT_IN_USE(p_flags);
	return 0;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

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
		if (likely(p_desc->lwip_pbuf.pbuf.ref))
			p_desc->lwip_pbuf.pbuf.ref--;
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
		__log_panic("TCP segments allocation failed");
	}
	memset(m_tcp_segs_array, 0, sizeof(tcp_seg) * size);
	for (int i = 0; i < size - 1; i++) {
		m_tcp_segs_array[i].next = &m_tcp_segs_array[i + 1];
	}
	m_p_head = &m_tcp_segs_array[0];
}

tcp_seg_pool::~tcp_seg_pool() {
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
	m_p_intervals = new timer_node_t*[m_n_intervals_size];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_p_intervals) {
		__log_panic("failed to allocate memory");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	memset(m_p_intervals, 0, sizeof(timer_node_t*) * m_n_intervals_size);
	m_n_location = 0;
	m_n_next_insert_bucket = 0;
	m_n_count = 0;
}

tcp_timers_collection::~tcp_timers_collection()
{
	if (m_n_count) {
		__log_dbg("not all TCP timers have been removed, count=%d", m_n_count);

		for (int i = 0; i < m_n_intervals_size; i++) {
			while (m_p_intervals[i]) {
				m_p_intervals[i]->group = NULL;
				m_p_intervals[i] = m_p_intervals[i]->next;
			}
		}
	}

	delete m_p_intervals;
}

void tcp_timers_collection::clean_obj()
{
	set_cleaned();

	g_p_event_handler_manager->unregister_timers_event_and_delete(this);
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
		g_p_event_handler_manager->register_timer_event(m_n_resolution , this, PERIODIC_TIMER, NULL);
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
		g_p_event_handler_manager->unregister_timer_event(this, NULL);
	}

	__log_dbg("TCP timer handler [%p] was removed", node->handler);

	free(node);
}
