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


#ifndef WAKEUP_H
#define WAKEUP_H

/**
 * wakeup class that adds a wakeup functionality to socket (tcp and udp) and epoll.
 */
#include <sys/epoll.h>
#include "vma/util/lock_wrapper.h"

class wakeup
{
public:
	wakeup(void);
	void do_wakeup();
	inline bool is_wakeup_fd(int fd)
	{
		if (fd != g_wakeup_pipes[0])
			return false;
		return true;
	};
	void remove_wakeup_fd();
	void going_to_sleep();
	void return_from_sleep() { --m_is_sleeping; };

protected:
	void wakeup_set_epoll_fd(int epfd);
	int m_is_sleeping;

	//lock_spin_recursive m_wakeup_lock; This lock is not needed for now. Maybe we will need it for epoll.

private:
	int m_epfd;
	struct epoll_event m_ev;

	static int g_wakeup_pipes[2];
};

#endif /* WAKEUP_H */
