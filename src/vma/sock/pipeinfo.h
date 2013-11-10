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


#ifndef PIPEINFO_H
#define PIPEINFO_H

#include "socket_fd_api.h"
#include <vma/util/lock_wrapper.h>
#include <vma/util/vma_stats.h>
#include <vma/event/timer_handler.h>

class pipeinfo : public socket_fd_api, public timer_handler
{
public:
	pipeinfo(int fd);
	~pipeinfo();

	virtual void clean_obj();

	int	fcntl(int __cmd, unsigned long int __arg);
	int 	ioctl(unsigned long int __request, unsigned long int __arg);

	// Process a Rx request, we might have a ready packet, or we might block until
	// we have one (if sockinfo::m_b_blocking == true)
	ssize_t	rx(const rx_call_t call_type, struct iovec* p_iov, ssize_t sz_iov, 
	       	   int* p_flags, struct sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);

	// Process a Tx request, handle all that is needed to send the packet, we might block
	// until the connection info is ready or a tx buffer is releast (if sockinfo::m_b_blocking == true)
	ssize_t	tx(const tx_call_t call_type, const struct iovec* p_iov, 
	       	   const ssize_t sz_iov, const int flags = 0, 
	       	   const struct sockaddr *__to = NULL, const socklen_t __tolen = 0);

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
};

#endif

