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


#include "select_call.h"

#include <vlogger/vlogger.h>
#include <vma/util/vtypes.h>
#include <vma/sock/sock-redirect.h>
#include <vma/sock/fd_collection.h>
#include <vma/dev/net_device_table_mgr.h>
#include "vma/util/bullseye.h"

#define MODULE_NAME "select_call:"


#define FD_COPY(__fddst, __fdsrc, __nfds) \
		memcpy(__FDS_BITS(__fddst), __FDS_BITS(__fdsrc), ((__nfds) + 7) >> 3)

#undef  FD_ZERO // Remove select.h origianl FD_ZERO and define our own with limit size
#define FD_ZERO(__fddst, __nfds) \
		memset(__FDS_BITS(__fddst), 0, ((__nfds) + 7) >> 3)
iomux_func_stats_t g_select_stats;

select_call::select_call(int *off_fds_buffer, offloaded_mode_t *off_modes_buffer,
                         int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, timeval *timeout, const sigset_t *__sigmask /* = NULL */) :
	io_mux_call(off_fds_buffer, off_modes_buffer, nfds, __sigmask),
	m_nfds(nfds), m_readfds(readfds), m_writefds(writefds),
	m_exceptfds(exceptfds), m_timeout(timeout), m_nfds_with_cq(0), m_b_run_prepare_to_poll(false)
{
	int fd;
	//socket_fd_api* temp_sock_fd_api = NULL; 

	// create stats
	m_p_stats = &g_select_stats;
        vma_stats_instance_get_select_block(m_p_stats);

	bool offloaded_read  = !!m_readfds;
	bool offloaded_write = !!m_writefds;

	if (offloaded_read || offloaded_write) {
		FD_ZERO(&m_os_rfds, m_nfds);
		FD_ZERO(&m_os_wfds, m_nfds);

		//covers the case of select(readfds = NULL)
		if(!m_readfds) {
			FD_ZERO(&m_cq_rfds, m_nfds);
			m_readfds = &m_cq_rfds;
		}

		// get offloaded fds in read set
		for (fd = 0; fd < m_nfds; ++fd) {

                        bool check_read  = offloaded_read  && FD_ISSET(fd, m_readfds);
                        bool check_write = offloaded_write && FD_ISSET(fd, m_writefds);

			socket_fd_api* psock = fd_collection_get_sockfd(fd);

			if (psock && psock->get_type() == FD_TYPE_SOCKET) {

                                offloaded_mode_t off_mode  = OFF_NONE;
                                if (check_read)  off_mode = (offloaded_mode_t)(off_mode | OFF_READ);
                                if (check_write) off_mode = (offloaded_mode_t)(off_mode | OFF_WRITE);

				if (off_mode) {
					__log_dbg("---> fd=%d IS SET for read or write!", fd);

					m_p_all_offloaded_fds[m_num_all_offloaded_fds] = fd;
					m_p_offloaded_modes[m_num_all_offloaded_fds] = off_mode;
					m_num_all_offloaded_fds++;
					if (! psock->skip_os_select()) {
						if (check_read)  {
							FD_SET(fd, &m_os_rfds);
							if(psock->is_readable(NULL)){
								io_mux_call::update_fd_array(&m_fd_ready_array, fd);
								m_n_ready_rfds++;
								m_n_all_ready_fds++;
							}else{
								// Instructing the socket to sample the OS immediately to prevent hitting EAGAIN on recvfrom(),
								// after iomux returned a shadow fd as ready (only for non-blocking sockets)
								psock->set_immediate_os_sample();
							}
						}
						if (check_write) {
							FD_SET(fd, &m_os_wfds);
						}
					}
					else
						__log_dbg("fd=%d must be skipped from os r select()", fd);

				}
			}
                        else {
                                if (check_read)  {
                                        FD_SET(fd, &m_os_rfds);
                                }
                                if (check_write) {
                                        FD_SET(fd, &m_os_wfds);
                                }
                        }

		}
	}
	__log_dbg("num all offloaded_fds=%d", m_num_all_offloaded_fds);


#if 0 //older code
	if (m_readfds) { // TODO: consider 1 loop, for saving calls to fd_collection_get_sockfd()
		FD_COPY(&m_os_rfds, m_readfds, m_nfds);
		// get offloaded fds in read set
		for (fd = 0; fd < m_nfds; ++fd) {
			if (FD_ISSET(fd, m_readfds)) {
				__log_dbg("---> fd=%d IS SET for read!", fd);
				socket_fd_api* psock = fd_collection_get_sockfd(fd);
				if (psock && psock->get_type() == FD_TYPE_SOCKET) {
					m_p_all_offloaded_fds[m_num_all_offloaded_fds++] = fd;
					if (psock->skip_os_select()) {
						__log_dbg("fd=%d must be skipped from os r select()", fd);
						FD_CLR(fd, &m_os_rfds);
					}
				}
			}
		}
		if (! mce_sys.rx_offload_enabled) {
			// reset counter once after the loop instead of 'if'ing N times in the loop
			m_num_all_offloaded_fds = 0;
		}
	}
	if (m_writefds) { // TODO: consider 1 loop, for saving calls to fd_collection_get_sockfd()
		FD_COPY(&m_os_wfds, m_writefds, m_nfds);
		// get offloaded fds in write set
		for (fd = 0; fd < m_nfds; ++fd) {
			if (FD_ISSET(fd, m_writefds)) {
				__log_dbg("---> fd=%d IS SET for write!", fd);
				socket_fd_api* psock = fd_collection_get_sockfd(fd);
				if (psock && psock->get_type() == FD_TYPE_SOCKET) {
					m_p_offloaded_wfds[m_num_offloaded_wfds++] = fd;
					if (psock->skip_os_select()) {
						__log_dbg("fd=%d must be skipped from os w select()", fd);
						FD_CLR(fd, &m_os_wfds);
					}
				}
			}
		}
		if (! mce_sys.tx_offload_enabled) {
			// reset counter once after the loop instead of 'if'ing N times in the loop
			m_num_offloaded_wfds = 0;
		}
	}
	__log_dbg("offloaded_rfds=%d; offloaded_wfds=%d", m_num_all_offloaded_fds, m_num_offloaded_wfds);
#endif
	// coverity[uninit_member]
}


void select_call::prepare_to_poll()
{
	/* 
	 * Create copies of all sets and zero out the originals.
	 * This is needed because polling might be successful.
	 * 
	 * If the read set is zero, use the local copy every time.
	 * This is OK because it will hold only the CQ, and wait()
	 * clears the CQ from the set after orig_select() call.
	 * 
	 * m_readfds is non-NULL here because there are offloaded sockets.
	 */

	// copy sets, and zero out the originals
	if (m_readfds) {
		FD_COPY(&m_orig_readfds, m_readfds, m_nfds);
		FD_ZERO(m_readfds, m_nfds);
	}

	if (m_writefds) {
		FD_COPY(&m_orig_writefds, m_writefds, m_nfds);
		FD_ZERO(m_writefds, m_nfds);
	}
	if (m_exceptfds) {
		FD_COPY(&m_orig_exceptfds, m_exceptfds, m_nfds);
		FD_ZERO(m_exceptfds, m_nfds);
	}
	m_b_run_prepare_to_poll = true;
}

void select_call::prepare_to_block()
{
	m_cqepfd = g_p_net_device_table_mgr->global_ring_epfd_get();
	m_nfds_with_cq = max(m_cqepfd + 1, m_nfds);
}

bool select_call::wait_os(bool zero_timeout)
{
	timeval to, *pto = NULL;
	timespec to_pselect, *pto_pselect = NULL;
	
/* Avner: I put it in comment, because this logic is wrong

	// optimization: do not call os select if ALL fds are excluded
	// extend check to write/except fds
	if (m_rfd_count == m_n_exclude_fds)
		return;
//*/
	
	if (zero_timeout) {
		to.tv_sec = to.tv_usec = 0;
		pto = &to;
	}
	else {
		pto = m_timeout;
	}

	// Restore original sets
	if (m_b_run_prepare_to_poll) {
		if (m_readfds)	FD_COPY(m_readfds, &m_os_rfds, m_nfds);
		if (m_writefds)	FD_COPY(m_writefds, &m_os_wfds, m_nfds);
		if (m_exceptfds)FD_COPY(m_exceptfds, &m_orig_exceptfds, m_nfds);
	}
	__log_func("calling os select: %d", m_nfds);
	if (m_sigmask) {
		if (pto) {
			to_pselect.tv_sec = pto->tv_sec;
			to_pselect.tv_nsec = pto->tv_usec * 1000;
			pto_pselect = &to_pselect;
		}
		m_n_all_ready_fds = orig_os_api.pselect(m_nfds, m_readfds, m_writefds, m_exceptfds, pto_pselect, m_sigmask);
	} else {
		m_n_all_ready_fds = orig_os_api.select(m_nfds, m_readfds, m_writefds, m_exceptfds, pto);
	}
	if (m_n_all_ready_fds < 0) {
		throw io_mux_call::io_error();
	}
	if (m_n_all_ready_fds > 0) {
		__log_func("wait_os() returned with %d", m_n_all_ready_fds);
	}
	return false; // No cq_fd in select() event
}

bool select_call::wait(const timeval &elapsed)
{
	timeval timeout, *pto = NULL;
	timespec to_pselect, *pto_pselect = NULL;
	
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_n_all_ready_fds > 0) {
		__log_panic("wait() called when there are ready fd's!!!");
		// YossiE TODO make this and some more checks as debug assertions
		// In all functions
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Restore original sets
	if (m_b_run_prepare_to_poll) {
		if (m_readfds)	FD_COPY(m_readfds, &m_os_rfds, m_nfds);
		if (m_writefds)	FD_COPY(m_writefds, &m_os_wfds, m_nfds);
		if (m_exceptfds)FD_COPY(m_exceptfds, &m_orig_exceptfds, m_nfds);
	}

/*  - TODO: do we need some of the EOF related code from the below ?

	// remove exclusions from sets
        // check them for EOF condition
        for (int i = 0; i < m_n_exclude_fds; i++) {
                socket_fd_api* psock;
                FD_CLR(m_exclude_os_fds[i], m_readfds);
                //TODO: may need to clear from write/except sets
                psock =fd_collection_get_sockfd(m_exclude_os_fds[i]);
                if (!psock)
                        __log_panic("no socket object");

                //TODO: this code is wrong - fix it!!
                if (psock->is_eof()) {
                        __log_dbg("eof detected on fd=%d", m_exclude_os_fds[i]);
                        FD_ZERO(m_readfds, m_nfds);
                        // copy sets, and zero out the originals
                        if (m_writefds)
                                FD_ZERO(m_writefds, m_nfds);
                        if (m_exceptfds)
                                FD_ZERO(m_exceptfds, m_nfds);
                        FD_SET(m_exclude_os_fds[i], m_readfds);
                        m_n_all_ready_fds = m_n_ready_rfds = 1;
                        return false;
                }
        }
//*/

	// Call OS select() on original sets + CQ epfd in read set
	if (m_readfds)
		FD_SET(m_cqepfd, m_readfds);
	if (m_timeout) {
		tv_sub(m_timeout, &elapsed, &timeout);
		if (timeout.tv_sec < 0 || timeout.tv_usec < 0) {
			// Already reached timeout
			return false;
		}
		pto = &timeout;
	}

	__log_func("going to wait on select CQ+OS nfds=%d cqfd=%d pto=%p!!!", m_nfds_with_cq, m_cqepfd, pto);

	// ACTUAL CALL TO SELECT
	if (m_sigmask) {
		if (pto) {
			to_pselect.tv_sec = pto->tv_sec;
			to_pselect.tv_nsec = pto->tv_usec * 1000;
			pto_pselect = &to_pselect;
		}
		m_n_all_ready_fds = orig_os_api.pselect(m_nfds, m_readfds, m_writefds, m_exceptfds, pto_pselect, m_sigmask);
	} else {
		m_n_all_ready_fds = orig_os_api.select(m_nfds_with_cq, m_readfds, m_writefds, m_exceptfds, pto);
	}
	__log_func("done select CQ+OS nfds=%d cqfd=%d pto=%p ready=%d!!!", m_nfds_with_cq, m_cqepfd, pto, m_n_all_ready_fds);
	if (m_n_all_ready_fds < 0) {
		throw io_mux_call::io_error();
	}

	// Clear CQ from the set and don't count it
	if (m_readfds)
	{
		if (FD_ISSET(m_cqepfd, m_readfds)) {
			FD_CLR(m_cqepfd, m_readfds); // Not needed if m_readfds is NULL
			--m_n_all_ready_fds;
			return true;
		}
	}
	return false;
}

bool select_call::is_timeout(const timeval &elapsed)
{
	return m_timeout && tv_cmp(m_timeout, &elapsed, <=);
}

void select_call::set_offloaded_rfd_ready(int fd_index)
{
	if (m_p_offloaded_modes[fd_index] & OFF_READ) { //TODO: consider removing
		int fd = m_p_all_offloaded_fds[fd_index];
		if (!FD_ISSET(fd, m_readfds)) {
			FD_SET(fd, m_readfds);
			++m_n_ready_rfds;
			++m_n_all_ready_fds;
			__log_func("ready offloaded fd: %d", fd);
		}
	}
}

void select_call::set_rfd_ready(int fd)
{
	// This function also checks that fd was in the original read set
	if (!FD_ISSET(fd, m_readfds) && FD_ISSET(fd, &m_orig_readfds)) {
		FD_SET(fd, m_readfds);
		++m_n_ready_rfds;
//		if (!FD_ISSET(fd, m_writefds))
		++m_n_all_ready_fds;
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void select_call::set_offloaded_wfd_ready(int fd_index)
{
	if (m_p_offloaded_modes[fd_index] & OFF_WRITE) { //TODO: consider removing
		int fd = m_p_all_offloaded_fds[fd_index];
		if (!FD_ISSET(fd, m_writefds)) {
			FD_SET(fd, m_writefds);
			++m_n_ready_wfds;
			++m_n_all_ready_fds;
			__log_func("ready offloaded w fd: %d", fd);
		}
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void select_call::set_wfd_ready(int fd)
{
	// This function also checks that fd was in the original read set
	if (!FD_ISSET(fd, m_writefds) && FD_ISSET(fd, &m_orig_writefds)) { //TODO: why do we need the last 'if'??
		FD_SET(fd, m_writefds);
		++m_n_ready_wfds;
//		if (!FD_ISSET(fd, m_readfds))
		++m_n_all_ready_fds;
		__log_func("ready w fd: %d", fd);
	}
}
