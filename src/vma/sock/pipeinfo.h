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


#ifndef PIPEINFO_H
#define PIPEINFO_H

#include "socket_fd_api.h"
#include "utils/lock_wrapper.h"
#include <vma/util/vma_stats.h>
#include <vma/event/timer_handler.h>

class pipeinfo : public socket_fd_api, public timer_handler
{
public:
	pipeinfo(int fd);
	~pipeinfo();

	virtual void clean_obj();

	int	fcntl(int __cmd, unsigned long int __arg);
	int	fcntl64(int __cmd, unsigned long int __arg);
	int 	ioctl(unsigned long int __request, unsigned long int __arg);

	// Process a Rx request, we might have a ready packet, or we might block until
	// we have one (if sockinfo::m_b_blocking == true)
	ssize_t	rx(const rx_call_t call_type, struct iovec* p_iov, ssize_t sz_iov, 
	       	   int* p_flags, struct sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);

	// Process a Tx request, handle all that is needed to send the packet, we might block
	// until the connection info is ready or a tx buffer is releast (if sockinfo::m_b_blocking == true)
	ssize_t tx(vma_tx_call_attr_t &tx_arg);

	void	statistics_print();

	virtual inline fd_type_t  get_type() {
		 return FD_TYPE_PIPE;
	}

private:
	bool			m_b_blocking;

	// Main mutex to protect from multi threaded access to sockinfo from sock-redirect
	bool			m_b_closed;
	lock_mutex		m_lock;
	lock_mutex		m_lock_rx;
	lock_mutex		m_lock_tx;

	socket_stats_t  	m_socket_stats;
	socket_stats_t* 	m_p_socket_stats;

	void*			m_timer_handle;

	int	m_write_count;
	int	m_write_count_on_last_timer;
	int	m_write_count_no_change_count;
	bool	m_b_lbm_event_q_pipe_timer_on;

	void	handle_timer_expired(void* user_data);

	void 	write_lbm_pipe_enhance();

	void 	save_stats_rx_os(int bytes);
	void 	save_stats_tx_os(int bytes);

	int	fcntl_helper(int __cmd, unsigned long int __arg, bool& bexit);
};

#endif

