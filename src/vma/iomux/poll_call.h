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


#ifndef _POLL_CALL_H
#define _POLL_CALL_H

#include <poll.h>

#include "io_mux_call.h"

/**
 * @class poll_call
 * Functor for poll()
 */
class poll_call : public io_mux_call
{
public:
	/**
	 * Create a poll call.
	 * @param rfds_buffer Array of at least nfds ints.
	 * @param lookup_buffer Array of at least nfds ints.
	 * @param extra_fds_buffer Array of at least (1 + nfds) pollfd-s.
	 * 
	 * Rest of the arguments are the same as for poll() library function.  
	 * @throws io_mux_call::io_error
	 */
	poll_call(int *off_rfds_buffer, offloaded_mode_t *off_modes_buffer, int *lookup_buffer,
	          pollfd *working_fds_arr, pollfd *fds, nfds_t nfds, int timeout, const sigset_t *__sigmask = NULL);

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
        
	/// @override
	virtual void set_wfd_ready(int fd);

private:
	/// Parameters for the call
	pollfd * m_fds;
	const nfds_t m_nfds;
	int m_timeout;
	
	int * const m_lookup_buffer;
	pollfd * const m_orig_fds;

	void copy_to_orig_fds();

};

#endif
