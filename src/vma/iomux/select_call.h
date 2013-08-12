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


#ifndef _SELECT_CALL_H
#define _SELECT_CALL_H

#include <sys/select.h>

#include "io_mux_call.h"

/**
 * @class poll_call
 * Functor for poll()
 */
class select_call : public io_mux_call
{
public:
	/**
	 * Create a select call.
	 * @param fds_buffer Array of at least nfds ints.
	 *
	 * Rest of the arguments are the same as for select() library function.  
	 * @throws io_mux_call::io_error
	 */
	select_call(int *off_fds_buffer, offloaded_mode_t *off_modes_buffer,
	            int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, timeval *timeout, const sigset_t *__sigmask = NULL);
        
	/// @override
	virtual void set_offloaded_rfd_ready(int fd_index);
	virtual void set_offloaded_wfd_ready(int fd_index);
        
	/// @override
	virtual void prepare_to_poll();

	/// @override
	virtual void prepare_to_block();
 
	/// @override
	virtual bool wait_os(bool zero_timeout);
	
	/// @override
	virtual bool wait(const timeval &elapsed);

	/// @override
	virtual bool is_timeout(const timeval &elapsed);
        
	/// @override
	virtual void set_rfd_ready(int fd);
	virtual void set_wfd_ready(int fd);

private:
	/// Parameters for the call
	const int m_nfds;
	fd_set * m_readfds;
	fd_set * const m_writefds;
	fd_set * const m_exceptfds;
	timeval * const m_timeout;

	fd_set 	m_orig_readfds;
	fd_set 	m_orig_writefds;
	fd_set 	m_orig_exceptfds;
	int 	m_nfds_with_cq;
	bool 	m_b_run_prepare_to_poll;
//	int *m_exclude_os_fds;
//	int  m_n_exclude_fds;
//	int  m_rfd_count;

	fd_set m_os_rfds;
	fd_set m_os_wfds;

	fd_set m_cq_rfds;

};

#endif
