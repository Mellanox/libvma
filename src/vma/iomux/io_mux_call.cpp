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


#include "io_mux_call.h"

#include <vlogger/vlogger.h>
#include <vma/util/sys_vars.h>
#include <vma/util/clock.h>
#include <vma/sock/fd_collection.h>
#include <vma/dev/net_device_table_mgr.h>
#include "vma/util/instrumentation.h"

//#define IOMUX_DEBUG
#ifdef IOMUX_DEBUG
#define __if_dbg(_log_args_...)			__log_dbg(_log_args_)
#else
#define __if_dbg(_log_args_...)
#endif

uint64_t g_polling_time_usec=0;		//polling time in the last second in usec
timeval g_last_zero_polling_time; 	//the last time g_polling_time_usec was zeroed
int g_n_last_checked_index = 0;		//save the last fd index we checked in check_offloaded_rsockets()

#define MODULE_NAME	"io_mux_call:"

int io_mux_call::m_n_skip_os_count = 0;

io_mux_call::io_mux_call(int *off_fds_buffer, offloaded_mode_t *off_modes_buffer, int num_fds, const sigset_t *sigmask) :
	m_check_sig_pending_ratio(0),
	m_p_all_offloaded_fds(off_fds_buffer),
	m_p_offloaded_modes(off_modes_buffer),
	m_num_all_offloaded_fds(0),
	m_cqepfd(-1),
	m_poll_sn(0),
	m_p_stats(NULL),
	m_n_all_ready_fds(0),
	m_n_ready_rfds(0),
	m_n_ready_wfds(0),
	m_sigmask(sigmask)
{
	m_p_num_all_offloaded_fds = &m_num_all_offloaded_fds;
	tv_clear(&m_start);
	tv_clear(&m_elapsed);

	if (m_p_all_offloaded_fds) memset(m_p_all_offloaded_fds, 0, num_fds*sizeof(m_p_all_offloaded_fds[0]));
	if (m_p_offloaded_modes)   memset(m_p_offloaded_modes  , 0, num_fds*sizeof(m_p_offloaded_modes[0]));

	m_fd_ready_array.fd_max = FD_ARRAY_MAX;
	m_fd_ready_array.fd_count = 0;
}

inline void io_mux_call::timer_update()
{
	if (!tv_isset(&m_start)) {
		// after first loop - set
		gettime(&m_start);
		__log_func("start timer");
	}
	else {
		timeval current;
		gettime(&current);
		tv_sub(&current, &m_start, &m_elapsed);
		__log_funcall("update timer (elapsed time: %d sec, %d usec)", m_elapsed.tv_sec, m_elapsed.tv_usec);
	}
}

inline void io_mux_call::check_rfd_ready_array(fd_array_t *fd_ready_array)
{
	int fd_index;

	for (fd_index=0; fd_index < fd_ready_array->fd_count; ++fd_index) {
		set_rfd_ready(fd_ready_array->fd_list[fd_index]);
	}
	if (m_n_ready_rfds) {
		m_p_stats->n_iomux_rx_ready += m_n_ready_rfds;
		__log_func("found ready_fds=%d", m_n_ready_rfds);
		//return true;
	}
	//return false;
}

void io_mux_call::check_offloaded_rsockets(uint64_t *p_poll_sn)
{
	int fd, offloaded_index, num_all_offloaded_fds;
	fd_array_t fd_ready_array;
	socket_fd_api *p_socket_object;

	fd_ready_array.fd_max = FD_ARRAY_MAX;

	offloaded_index = g_n_last_checked_index;
	num_all_offloaded_fds = *m_p_num_all_offloaded_fds;

	for (int i = 0; i < num_all_offloaded_fds; ++i) {

		++offloaded_index %= num_all_offloaded_fds;

		if (m_p_offloaded_modes[offloaded_index] & OFF_READ) {
			fd = m_p_all_offloaded_fds[offloaded_index];
			p_socket_object = fd_collection_get_sockfd(fd);
			if (!p_socket_object) {
				// If we can't find this previously mapped offloaded socket
				// then it was probably closed. We need to get out with error code
				errno = EBADF;
				g_n_last_checked_index = offloaded_index;
				throw io_mux_call::io_error();
			}

			fd_ready_array.fd_count = 0;

			// Poll the socket object
			if (p_socket_object->is_readable(p_poll_sn, &fd_ready_array)) {
				set_offloaded_rfd_ready(offloaded_index);
				// We have offloaded traffic. Don't sample the OS immediately
				p_socket_object->unset_immediate_os_sample();
			}

			check_rfd_ready_array(&fd_ready_array);


			//TODO: consider - m_n_all_ready_fds
			if (m_n_ready_rfds){
				g_n_last_checked_index = offloaded_index;
				return ;  
			}

		}
	}
	g_n_last_checked_index = offloaded_index;
	//return false;
}

inline void io_mux_call::check_offloaded_wsockets(uint64_t */*p_poll_sn*/)
{
	for (int offloaded_index = 0; offloaded_index < *m_p_num_all_offloaded_fds; ++offloaded_index) {

//		int fd = m_p_offloaded_wfds[offloaded_index];

		if (m_p_offloaded_modes[offloaded_index] & OFF_WRITE) {
			int fd = m_p_all_offloaded_fds[offloaded_index];
			socket_fd_api *p_socket_object = fd_collection_get_sockfd(fd);
			if (!p_socket_object) {
				// If we can't find this previously mapped offloaded socket
				// then it was probably closed. We need to get out with error code
				errno = EBADF;
				throw io_mux_call::io_error();
			}

			// Poll the socket object
			if (p_socket_object->is_writeable()) {
				set_wfd_ready(fd);
			}
		}
	}
}

inline bool io_mux_call::check_all_offloaded_sockets(uint64_t *p_poll_sn)
{
	check_offloaded_rsockets(p_poll_sn);

	if (!m_n_ready_rfds)
	{
		// check cq for acks
		ring_poll_and_process_element(&m_poll_sn, NULL);
		check_offloaded_wsockets(p_poll_sn);
	}

	__log_func("m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d", m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds);
	return m_n_all_ready_fds;
}

inline void io_mux_call::zero_polling_cpu(timeval current)
{
	timeval delta;
	int delta_time; // in usec

	// check if it's time to zero g_polling_time_usec
	tv_sub(&current, &g_last_zero_polling_time, &delta);
	delta_time=tv_to_usec(&delta);

	if (delta_time>=USEC_PER_SEC) {
		m_p_stats->n_iomux_polling_time = (g_polling_time_usec*100)/delta_time;

		__log_funcall("zero polling time: accumulated: %d usec delta=%d (%d%))", g_polling_time_usec, delta_time,  m_p_stats->n_iomux_polling_time);
		g_polling_time_usec=0;
		g_last_zero_polling_time = current;
	}
}

void io_mux_call::polling_loops()
{
	int poll_counter;
	int check_timer_countdown;
	int poll_os_countdown;
	bool multiple_polling_loops, finite_polling;
	timeval before_polling_timer, after_polling_timer, delta;
	int delta_time; // in usec

	prepare_to_poll();

	if(immidiate_return()) return;

#ifdef VMA_TIME_MEASURE
	TAKE_T_POLL_START;
	ZERO_POLL_COUNT;
#endif
			
	// Poll once before checking the time
	check_timer_countdown = 1;

	/*
	 * Give OS priority in 1 of SELECT_SKIP_OS times
	 * In all other times, OS is never polled first (even if ratio is 1).
	 */
	if (--m_n_skip_os_count <= 0) {
		m_n_skip_os_count = mce_sys.select_skip_os_fd_check;
		poll_os_countdown = 0;
	} else {
		poll_os_countdown = mce_sys.select_poll_os_ratio;
	}

	poll_counter = 0;
	finite_polling = mce_sys.select_poll_num != -1;
	multiple_polling_loops = mce_sys.select_poll_num != 0;

	timeval poll_duration;
	tv_clear(&poll_duration);
	poll_duration.tv_usec = mce_sys.select_poll_num;

	__if_dbg("2nd scenario start");

	if (mce_sys.select_handle_cpu_usage_stats) {
		// handle polling cpu statistics
		if (!tv_isset(&g_last_zero_polling_time)) {
			// after first loop - set
			gettime(&g_last_zero_polling_time);
		}

		gettime(&before_polling_timer);
		zero_polling_cpu(before_polling_timer);
	}

	do {
#ifdef VMA_TIME_MEASURE		
		INC_POLL_COUNT;
#endif
		__log_funcall("2nd scenario loop %d", poll_counter);
		__log_funcall("poll_os_countdown=%d, select_poll_os_ratio=%d, check_timer_countdown=%d, m_num_offloaded_rfds=%d,"
		              "  m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d, multiple_polling_loops=%d",
		              poll_os_countdown, mce_sys.select_poll_os_ratio, check_timer_countdown, *m_p_num_all_offloaded_fds,
		              m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds, multiple_polling_loops);

		/*
		* Poll OS when count down reaches zero. This honors CQ-OS ratio.
		* This also handles the 0 ratio case - do not poll OS at all.
		*/
		if (poll_os_countdown-- == 0 && mce_sys.select_poll_os_ratio > 0) {
			bool cq_ready = wait_os(true);
			if (cq_ready) {
				// This will empty the cqepfd
				// (most likely in case of a wakeup and probably only under epoll_wait (Not select/poll))
				ring_wait_for_notification_and_process_element(&m_poll_sn, NULL);
			}
			/* Before we exit with ready OS fd's we'll check the CQs once more and exit
			* below after calling check_all_offloaded_sockets();
			* IMPORTANT : We cannot do an opposite with current code,
			* means we cannot poll cq and then poll os (for epoll) - because poll os
			* will delete ready offloaded fds.
			*/
			if (m_n_all_ready_fds) {

				m_p_stats->n_iomux_os_rx_ready += m_n_all_ready_fds; // TODO: fix it - we only know all counter, not read counter
				ring_poll_and_process_element(&m_poll_sn, NULL);
				check_all_offloaded_sockets(&m_poll_sn);
				break;
			}
			poll_os_countdown = mce_sys.select_poll_os_ratio - 1;
		}

		/*
		 * Poll offloaded sockets.
		 * If this is successful we must exit - wait_os() might mess the results.
		 */
		//__log_func("before check_all_offloaded_sockets");
		if (check_all_offloaded_sockets(&m_poll_sn))
			break;


		/*
		 * Update elapsed time & Check for timeout or expiry of polling loops duration
		 * Update start time on first entry
		 */
		if (check_timer_countdown <= 1) {
			timer_update();
			if (is_timeout(m_elapsed)) {
				__if_dbg("2nd scenario timeout (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
				__if_dbg("timeout (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
				break;
			}

			if (finite_polling && (tv_cmp(&poll_duration, &m_elapsed, <=))) {
				__if_dbg("2nd scenario reached max poll duration (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
				__if_dbg("timeout reached max poll duration (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
				break;
			}

			// Check the timer each 512 offloaded fd's checked
			check_timer_countdown = 512;

			__if_dbg("2nd scenario timer update (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
		}

		// update timer check with referance to number of offlaoded sockets in loop
		check_timer_countdown -= *m_p_num_all_offloaded_fds;
		//check_timer_countdown -= m_num_offloaded_wfds; //TODO: consider the appropriate factor
		poll_counter++;

		if (g_b_exit || is_sig_pending()) {
			errno = EINTR;
			throw io_mux_call::io_error();
		}
	} while (m_n_all_ready_fds == 0 && multiple_polling_loops);

	if (mce_sys.select_handle_cpu_usage_stats) {
        	// handle polling cpu statistics
		gettime(&after_polling_timer);

		//calc accumulated polling time
		tv_sub(&after_polling_timer, &before_polling_timer, &delta);
		delta_time=tv_to_usec(&delta);
		g_polling_time_usec += delta_time ;

		zero_polling_cpu(after_polling_timer);
	}

	if (m_n_all_ready_fds) {//TODO: verify!
		++m_p_stats->n_iomux_poll_hit;
		__log_func("polling_loops found %d ready fds (rfds=%d, wfds=%d)", m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds);
#ifdef VMA_TIME_MEASURE				
		TAKE_T_POLL_END;
#endif
	}
	else {
		++m_p_stats->n_iomux_poll_miss;
	}

	__if_dbg("2nd scenario exit (loop %d, elapsed %d)", poll_counter, m_elapsed.tv_usec);
}

void io_mux_call::blocking_loops()
{
	int ret;
	bool cq_ready = false;
	bool woke_up_non_valid = false;
	fd_array_t fd_ready_array;
	fd_ready_array.fd_max = FD_ARRAY_MAX;

	prepare_to_block();

	/*
	 * Loop as long as no fd's are found, and cq is ready.
	 * If wait() returns without cq ready - timeout expired.
	 */
	do {
		if (g_b_exit || is_sig_pending()) {
			errno = EINTR;
			throw io_mux_call::io_error();
		}

		woke_up_non_valid = false;

		ret = ring_request_notification(m_poll_sn);
		__log_func("arming cq with poll_sn=%lx ret=%d", m_poll_sn, ret);
		if (ret < 0) {
			throw io_mux_call::io_error();
		}
		else if (ret > 0) {
			// arm failed - process pending wce
			cq_ready = true;
			fd_ready_array.fd_count = 0;
			ret = ring_poll_and_process_element(&m_poll_sn, &fd_ready_array);
			__log_func("after global_ring_poll_and_process_element poll_sn=%lxs ret=%d", m_poll_sn, ret);

			check_all_offloaded_sockets(&m_poll_sn);
		}
		else /* ret == 0 */ {

			timer_update();

			// arming was successful - block on cq
			__log_func("going to sleep (elapsed time: %d sec, %d usec)", m_elapsed.tv_sec, m_elapsed.tv_usec);
			if (check_all_offloaded_sockets(&m_poll_sn)) {
				continue;
			}

			cq_ready = wait(m_elapsed);
			__log_func("wait() returned %d, m_n_all_ready_fds=%d", cq_ready, m_n_all_ready_fds);
			if (cq_ready) {
				fd_ready_array.fd_count = 0;
				ring_wait_for_notification_and_process_element(&m_poll_sn, &fd_ready_array);
				// tcp sockets can be accept ready!
				__log_func("before check_all_offloaded_sockets");
				check_all_offloaded_sockets(&m_poll_sn);
				// This hurts epoll and doesn't seem to make a different for the rest
				//check_rfd_ready_array(&fd_ready_array);
			} else if (!m_n_all_ready_fds && !is_timeout(m_elapsed)) {
				__log_func("woke up by wake up mechanism, check current events");
				check_all_offloaded_sockets(&m_poll_sn);
				if(!m_n_all_ready_fds) {
					woke_up_non_valid = true;
					__log_func("woke up by wake up mechanism but the events are no longer valid");
				}
			}
		}
	} while (!m_n_all_ready_fds && (woke_up_non_valid || cq_ready) && !is_timeout(m_elapsed)); //TODO: consider sum r + w
}

int io_mux_call::call()
{
	//TODO: need stats adjustments for write...

	__log_funcall("");

	if (!mce_sys.select_poll_os_force  // TODO: evaluate/consider this logic
			&& (*m_p_num_all_offloaded_fds == 0))
	{
		// 1st scenario
		timer_update();
		wait_os(false);
		if (g_b_exit || is_sig_pending()) {
			errno = EINTR;
			throw io_mux_call::io_error();
		}
		m_p_stats->n_iomux_os_rx_ready += m_n_ready_rfds; //TODO: check

		//wake up mechanism can bring up events of later joined offloaded sockets
		if(*m_p_num_all_offloaded_fds) {
			check_all_offloaded_sockets(&m_poll_sn);
			if (m_n_all_ready_fds) goto done;
			else { //false wake-up, and we already discovered that we should be in 2nd scenario
				timer_update();
				if (is_timeout(m_elapsed)) goto done;
			}
		} else {
			goto done;
		}
	}

	// 2nd scenario
	polling_loops();

	// 3rd scenario
	if (!m_n_all_ready_fds && !is_timeout(m_elapsed)) {
		blocking_loops();
	}

	done:

	if (m_n_all_ready_fds == 0) {//TODO: check
		// An error throws an exception
		++m_p_stats->n_iomux_timeouts;
	}

	__log_func("return %d", m_n_all_ready_fds);
	return m_n_all_ready_fds; // TODO: consider sum r + w
}

//check if we found anything in the constructor of select and poll
//override in epoll
bool io_mux_call::immidiate_return(){
	if(m_n_all_ready_fds){
		m_n_ready_rfds = 0; //will be counted again in check_rfd_ready_array()
		m_n_all_ready_fds = 0;
		check_rfd_ready_array(&m_fd_ready_array);
		ring_poll_and_process_element(&m_poll_sn, NULL);
		return true;
	}
	return false;
}

int io_mux_call::ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array/* = NULL*/)
{
	//TODO: (select, poll) this access all CQs, it is better to check only relevant ones
	return g_p_net_device_table_mgr->global_ring_poll_and_process_element(p_poll_sn, pv_fd_ready_array);
}

int io_mux_call::ring_request_notification(uint64_t poll_sn)
{
	return g_p_net_device_table_mgr->global_ring_request_notification(poll_sn);
}

int io_mux_call::ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array /* = NULL*/)
{
	return g_p_net_device_table_mgr->global_ring_wait_for_notification_and_process_element(p_poll_sn, pv_fd_ready_array);
}

bool io_mux_call::is_sig_pending()
{
	if (!m_sigmask) return false;

	if (m_check_sig_pending_ratio >= CHECK_INTERRUPT_RATIO) {
		m_check_sig_pending_ratio = 0;
	} else {
		m_check_sig_pending_ratio++;
		return false;
	}

	sigset_t set_pending, set_andn;
	sigemptyset(&set_pending);
	sigemptyset(&set_andn);

	if (sigpending(&set_pending)) {
		__log_err("sigpending() failed (errno = %d %m)", errno);
		return false;
	}

	sigandnset(&set_andn, &set_pending, m_sigmask);

	//good flow - first option - no signals
	if (sigisemptyset(&set_andn)) {
		__log_funcall("no pending signals which the user is waiting for");
		return false;
	}

	//good flow - second options - pending signals - deliver them
	sigsuspend(m_sigmask);

	return true;
}
