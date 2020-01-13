/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef WAKEUP_H
#define WAKEUP_H

/**
 * wakeup class that adds a wakeup functionality to socket (tcp and udp) and epoll.
 */
#include <sys/epoll.h>
#include "utils/lock_wrapper.h"

class wakeup
{
public:
	wakeup(void);
	virtual ~wakeup() {};
	virtual void do_wakeup() = 0;
	virtual bool is_wakeup_fd(int fd) = 0;
	virtual void remove_wakeup_fd() = 0;
	void going_to_sleep();
	void return_from_sleep() { --m_is_sleeping; };

protected:
	virtual void wakeup_set_epoll_fd(int epfd);
	int m_is_sleeping;

	//lock_spin_recursive m_wakeup_lock; This lock is not needed for now. Maybe we will need it for epoll.

	int m_epfd;
	struct epoll_event m_ev;
};

#endif /* WAKEUP_H */
