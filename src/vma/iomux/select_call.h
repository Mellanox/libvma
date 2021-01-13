/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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
	virtual void set_efd_ready(int fd, int errors);

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
