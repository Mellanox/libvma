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


#include "pipeinfo.h"

#include <vlogger/vlogger.h>
#include <vma/event/event_handler_manager.h>

#include "sock-redirect.h"

#define MODULE_NAME 	"pi"
#undef  VLOG_PRINTF
#define VLOG_PRINTF(log_level, log_fmt, log_args...) 		vlog_printf(log_level, "fd[%#x]:%s() " log_fmt "\n", m_fd, __FUNCTION__, ##log_args)
#define VLOG_PRINTF_DETAILS(log_level, log_fmt, log_args...) 	vlog_printf(log_level, MODULE_NAME ":%d:fd[%#x]:%s() " log_fmt "\n", __LINE__, m_fd, __FUNCTION__, ##log_args)

#define pi_logpanic(log_fmt, log_args...) 							VLOG_PRINTF(VLOG_PANIC, log_fmt, ##log_args);	throw;
#define pi_logerr(log_fmt, log_args...) 							VLOG_PRINTF(VLOG_ERROR, log_fmt, ##log_args)
#define pi_logwarn(log_fmt, log_args...) 							VLOG_PRINTF(VLOG_WARNING, log_fmt, ##log_args)
#define pi_loginfo(log_fmt, log_args...) 							VLOG_PRINTF(VLOG_INFO, log_fmt, ##log_args)
#define pi_logdbg_no_funcname(log_fmt, log_args...)     if (g_vlogger_level >= VLOG_DEBUG) 	vlog_printf(VLOG_DEBUG, MODULE_NAME ":%d:fd[%d]: " log_fmt "\n", __LINE__, m_fd, ##log_args)
#define pi_logdbg(log_fmt, log_args...) 		if (g_vlogger_level >= VLOG_DEBUG) 	VLOG_PRINTF_DETAILS(VLOG_DEBUG, log_fmt, ##log_args)
#define pi_logfunc(log_fmt, log_args...) 		if (g_vlogger_level >= VLOG_FUNC) 	VLOG_PRINTF_DETAILS(VLOG_FUNC, log_fmt, ##log_args)
#define pi_logfuncall(log_fmt, log_args...) 		if (g_vlogger_level >= VLOG_FUNC_ALL) 	VLOG_PRINTF_DETAILS(VLOG_FUNC_ALL, log_fmt, ##log_args)

#define si_logdbg_no_funcname(log_fmt, log_args...)	do { if (g_vlogger_level >= VLOG_DEBUG) 	vlog_printf(VLOG_DEBUG, MODULE_NAME "[fd=%d]:%d: " log_fmt "\n", m_fd, __LINE__, ##log_args); } while (0)


pipeinfo::pipeinfo(int fd) : socket_fd_api(fd),
    m_lock("pipeinfo::m_lock"),
    m_lock_rx("pipeinfo::m_lock_rx"),
    m_lock_tx("pipeinfo::m_lock_tx")
{
	pi_logfunc("");

	m_b_closed = true;
	m_timer_handle = NULL;

	m_b_blocking = true;

	m_p_socket_stats = NULL; // mce_stats_instance_create_socket_block();
	if (m_p_socket_stats == NULL) {
		// pi_logdbg("Got NULL from mce_stats_instance_create_socket_block, using local member");
		m_p_socket_stats = &m_socket_stats;
	}
	memset(m_p_socket_stats, 0, sizeof(socket_stats_t));
	m_p_socket_stats->fd = m_fd;
	m_p_socket_stats->b_blocking = m_b_blocking;
	m_p_socket_stats->n_rx_ready_pkt_count = 0;
	m_p_socket_stats->counters.n_rx_ready_pkt_max = 0;
	m_p_socket_stats->n_rx_ready_byte_count = 0;
	m_p_socket_stats->counters.n_rx_ready_byte_max = 0;
	m_p_socket_stats->n_rx_zcopy_pkt_count = 0;

	m_b_closed = false;

	m_b_lbm_event_q_pipe_timer_on = false;
	m_write_count = m_write_count_on_last_timer = 0;
	m_write_count_no_change_count = 0;


	pi_logfunc("done");
}

pipeinfo::~pipeinfo()
{
	m_b_closed = true;
	pi_logfunc("");


	// Change to non-blocking socket so calling threads can exit
	m_b_blocking = false;

	m_lock_tx.lock();
	m_lock_rx.lock();
	m_lock.lock();

	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
	
	statistics_print();

	m_lock_tx.unlock();
	m_lock_rx.unlock();
	m_lock.unlock();

	pi_logfunc("done");
}

void pipeinfo::clean_obj()
{
	set_cleaned();
	m_timer_handle = NULL;
	g_p_event_handler_manager->unregister_timers_event_and_delete(this);
}

int pipeinfo::fcntl(int __cmd, unsigned long int __arg)
{
	switch (__cmd) {
	case F_SETFL:
		{
			pi_logfunc("cmd=F_SETFL, arg=%#x", __cmd, __arg);
			if (__arg & O_NONBLOCK) {
				pi_logdbg("set to non-blocking mode");
				m_b_blocking = false;
			}
			else {
				pi_logdbg("set to blocked mode");
				m_b_blocking = true;
			}
			m_p_socket_stats->b_blocking = m_b_blocking;
		}
		break;

	case F_GETFL:		/* Get file status flags.  */
		pi_logfunc("F_GETFL, arg=%#x", __arg);
		break;

	case F_GETFD:		/* Get file descriptor flags.  */
		pi_logfunc("F_GETFD, arg=%#x", __arg);
		break;

	case F_SETFD:		/* Set file descriptor flags.  */
		pi_logfunc("F_SETFD, arg=%#x", __arg);
		break;

	default:
		pi_logfunc("cmd=%d, arg=%#x", __cmd, __arg);
		break;
	}

	return orig_os_api.fcntl(m_fd, __cmd, __arg);
}

int pipeinfo::ioctl(unsigned long int __request, unsigned long int __arg)
{
	int *p_arg = (int *)__arg;

	switch (__request) {
	case FIONBIO:
		{
			if (*p_arg) {
				pi_logdbg("FIONBIO, arg=%d - set to non-blocking mode", *p_arg);
				m_b_blocking = false;
			}
			else {
				pi_logdbg("FIONBIO, arg=%d - set to blocked mode", *p_arg);
				m_b_blocking = true;
			}

			m_p_socket_stats->b_blocking = m_b_blocking;
		}
		break;

	default:
		pi_logfunc("request=%d, arg=%#x", __request, __arg);
		break;
	}

	return orig_os_api.ioctl(m_fd, __request, __arg);
}

ssize_t pipeinfo::rx(const rx_call_t call_type, iovec* p_iov, ssize_t sz_iov,
                     int* p_flags, sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg)
{
	pi_logfunc("");
	ssize_t ret = socket_fd_api::rx_os(call_type, p_iov, sz_iov, p_flags, __from, __fromlen, __msg);
	save_stats_rx_os(ret);
	return ret;
}

void pipeinfo::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	pi_logfunc("(m_write_count=%d)", m_write_count);
	m_lock_tx.lock();
	write_lbm_pipe_enhance();
	m_lock_tx.unlock();
}

ssize_t pipeinfo::tx(const tx_call_t call_type, const iovec* p_iov, const ssize_t sz_iov,
		     const int __flags, const sockaddr *__to ,const socklen_t __tolen)
{
	pi_logfunc("");
	m_lock_tx.lock();
	ssize_t ret = -1;
	switch (call_type) {
	case  TX_WRITE:

		if ((mce_sys.mce_spec == MCE_SPEC_29WEST_LBM_29 || mce_sys.mce_spec == MCE_SPEC_WOMBAT_FH_LBM_554) && 
		    (p_iov[0].iov_len == 1) && (((char*)p_iov[0].iov_base)[0] == '\0')) {

			// We will pass one pipe write in every T usec
			//
			// 1) First signaling pipe write will go through, and triger timer logic
			// 2) Then we'll send a single pipe writes every T usec (mce_sys.mce_spec_param1)
			// 3) We'll stop the timer once we have N cycles with no pipe write
			//

			m_write_count++;
			if (m_b_lbm_event_q_pipe_timer_on == false) {
				m_timer_handle = g_p_event_handler_manager->register_timer_event(mce_sys.mce_spec_param1/1000, this, PERIODIC_TIMER, 0);
				m_b_lbm_event_q_pipe_timer_on = true;
				m_write_count_on_last_timer = 0;
				m_write_count_no_change_count = 0;

				pi_logdbg("\n\n\npipe_write DONE timer Reg\n\n\n");

				// simulate a pipe_write
				write_lbm_pipe_enhance();
			}
			else if ((int)m_write_count > (int)(m_write_count_on_last_timer + mce_sys.mce_spec_param2)) {
				// simulate a pipe_write
				write_lbm_pipe_enhance();
			}

			ret = 1;
		}
		else {
			ret = orig_os_api.write(m_fd, p_iov[0].iov_base, p_iov[0].iov_len);
		}

		break;

	case  TX_SEND:
	case  TX_SENDTO:
	case  TX_SENDMSG:
	default:
		ret = socket_fd_api::tx_os(call_type, p_iov, sz_iov, __flags, __to, __tolen);
		break;
	}

	save_stats_tx_os(ret);
	m_lock_tx.unlock();
	return ret;
}

void pipeinfo::write_lbm_pipe_enhance()
{
	pi_logfunc("(m_write_count=%d)", m_write_count);

	if (m_write_count == m_write_count_on_last_timer) {
		// No pipe write happened during the last timer_expired()
		m_write_count_no_change_count++;

		// After 3 of these stop timer
		if (m_write_count_no_change_count >= 2 && m_b_lbm_event_q_pipe_timer_on) {
			if (m_timer_handle) {
				g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
				m_timer_handle = NULL;
			}
			m_b_lbm_event_q_pipe_timer_on = false;

			pi_logfunc("pipe_write DONE timer Un-Reg");
		}
	}

	m_write_count = 0;
	m_write_count_no_change_count = 0;
	m_write_count_on_last_timer = 0;

	// Send the buffered data
	char buf[10] = "\0";
	orig_os_api.write(m_fd, buf, 1);
}

void pipeinfo::statistics_print()
{
	bool b_any_activiy = false;
	if (m_p_socket_stats->counters.n_tx_sent_byte_count || m_p_socket_stats->counters.n_tx_sent_pkt_count || m_p_socket_stats->counters.n_tx_errors || m_p_socket_stats->counters.n_tx_drops) {
		pi_logdbg_no_funcname("Tx Offload: %d KB / %d / %d / %d [bytes/packets/errors/drops]", m_p_socket_stats->counters.n_tx_sent_byte_count/1024, m_p_socket_stats->counters.n_tx_sent_pkt_count, m_p_socket_stats->counters.n_tx_errors, m_p_socket_stats->counters.n_tx_drops);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_tx_os_bytes || m_p_socket_stats->counters.n_tx_os_packets || m_p_socket_stats->counters.n_tx_os_errors) {
		pi_logdbg_no_funcname("Tx OS info: %d KB / %d / %d [bytes/packets/errors]", m_p_socket_stats->counters.n_tx_os_bytes/1024, m_p_socket_stats->counters.n_tx_os_packets, m_p_socket_stats->counters.n_tx_os_errors);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_bytes || m_p_socket_stats->counters.n_rx_packets || m_p_socket_stats->counters.n_rx_errors || m_p_socket_stats->counters.n_rx_eagain) {
		pi_logdbg_no_funcname("Rx Offload: %d KB / %d / %d / %d [bytes/packets/errors/eagains]", m_p_socket_stats->counters.n_rx_bytes/1024, m_p_socket_stats->counters.n_rx_packets, m_p_socket_stats->counters.n_rx_errors, m_p_socket_stats->counters.n_rx_eagain);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_os_bytes || m_p_socket_stats->counters.n_rx_os_packets || m_p_socket_stats->counters.n_rx_os_errors) {
		pi_logdbg_no_funcname("Rx OS info: %d KB / %d / %d [bytes/packets/errors]", m_p_socket_stats->counters.n_rx_os_bytes/1024, m_p_socket_stats->counters.n_rx_os_packets, m_p_socket_stats->counters.n_rx_os_errors);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_poll_miss || m_p_socket_stats->counters.n_rx_poll_hit) {
		float rx_poll_hit_percentage = (float)(m_p_socket_stats->counters.n_rx_poll_hit * 100) / (float)(m_p_socket_stats->counters.n_rx_poll_miss + m_p_socket_stats->counters.n_rx_poll_hit);
		pi_logdbg_no_funcname("Rx poll: %d / %d (%2.2f%%) [miss/hit]", m_p_socket_stats->counters.n_rx_poll_miss, m_p_socket_stats->counters.n_rx_poll_hit, rx_poll_hit_percentage);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_ready_byte_drop) {
		float rx_drop_percentage = 0;
		if (m_p_socket_stats->counters.n_rx_packets)
			rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_byte_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
		si_logdbg_no_funcname("Rx byte: max %d / dropped %d (%2.2f%%) [limit is %d]", m_p_socket_stats->counters.n_rx_ready_byte_max, m_p_socket_stats->counters.n_rx_ready_byte_drop, rx_drop_percentage, m_p_socket_stats->n_rx_ready_byte_limit);
		b_any_activiy = true;
	}
	if (m_p_socket_stats->counters.n_rx_ready_pkt_drop) {
		float rx_drop_percentage = 0;
		if (m_p_socket_stats->counters.n_rx_packets)
			rx_drop_percentage = (float)(m_p_socket_stats->counters.n_rx_ready_pkt_drop * 100) / (float)m_p_socket_stats->counters.n_rx_packets;
		si_logdbg_no_funcname("Rx pkt : max %d / dropped %d (%2.2f%%)", m_p_socket_stats->counters.n_rx_ready_pkt_max, m_p_socket_stats->counters.n_rx_ready_pkt_drop, rx_drop_percentage);
		b_any_activiy = true;
	}
	if (b_any_activiy == false) {
		pi_logdbg_no_funcname("Rx and Tx where not active");
	}
}

void pipeinfo::save_stats_rx_os(int bytes)
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

void pipeinfo::save_stats_tx_os(int bytes)
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


