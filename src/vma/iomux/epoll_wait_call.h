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


#ifndef _EPOLL_WAIT_CALL_H
#define _EPOLL_WAIT_CALL_H

#include <sys/epoll.h>
#include <vma/iomux/epfd_info.h>

#include "io_mux_call.h"

class epfd_info;

/**
 * @class poll_call
 * Functor for poll()
 */
class epoll_wait_call : public io_mux_call
{
public:
	/**
	 * Create an epoll_wait call.
	 * @param extra_events_buffer Array of at least maxevents size.
	 * @param ready_event_map_buffer Array of at least maxevents size.
	 * 
	 * Rest of the arguments are the same as for poll() library function.  
	 * @throws io_mux_call::io_error
	 */
	epoll_wait_call(epoll_event *extra_events_buffer, offloaded_mode_t *off_modes_buffer,
			int epfd, epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask = NULL);
	virtual ~epoll_wait_call();
        
	/// @override
	virtual void set_offloaded_rfd_ready(int fd_index);
	virtual void set_offloaded_wfd_ready(int fd_index);

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

	/// @override
	virtual void set_efd_ready(int fd, int errors);

	/// @override
	virtual void lock();

	/// @override
	virtual void unlock();

	/// @override
	virtual bool immidiate_return(int &poll_os_countdown);

	/// @override
	virtual bool check_all_offloaded_sockets();

	void init_offloaded_fds();

	int get_current_events();

	bool handle_epoll_event(bool is_ready, uint32_t events, socket_fd_api *socket_object, int index);

protected:
	virtual int ring_poll_and_process_element();

	virtual int ring_request_notification();

	virtual int ring_wait_for_notification_and_process_element(void* pv_fd_ready_array);

	virtual bool handle_os_countdown(int &poll_os_countdown);

private:
	bool _wait(int timeout);

	/// Parameters for the call
	const int m_epfd;
	epoll_event * const m_events;
	const int m_maxevents;
	const int m_timeout;

	epoll_event *m_p_ready_events;
	epfd_info *m_epfd_info;
};

#endif
