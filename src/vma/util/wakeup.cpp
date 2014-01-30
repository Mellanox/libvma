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


#include "wakeup.h"
#include <vlogger/vlogger.h>
#include <vma/sock/sock-redirect.h>
#include "vma/util/bullseye.h"

#define MODULE_NAME "wakeup"

#define wkup_logpanic             __log_info_panic
#define wkup_logerr               __log_info_err
#define wkup_logwarn              __log_info_warn
#define wkup_loginfo              __log_info_info
#define wkup_logdbg               __log_info_dbg
#define wkup_logfunc              __log_info_func
#define wkup_logfuncall           __log_info_funcall
#define wkup_entry_dbg		  __log_entry_dbg

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[epfd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__	m_epfd

int wakeup::g_wakeup_pipes[2] = {-1,-1};

wakeup::wakeup()
{
	m_epfd = 0;
        m_is_sleeping = 0;

	if (g_wakeup_pipes[0] == -1 && g_wakeup_pipes[1] == -1) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (orig_os_api.pipe(g_wakeup_pipes)) {
			wkup_logpanic("wakeup pipe create failed (errno=%d %m)", errno);
		}
		if (orig_os_api.write(g_wakeup_pipes[1], "^", 1) != 1) {
			wkup_logpanic("wakeup pipe write failed(errno=%d %m)", errno);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		wkup_logdbg("created wakeup pipe [RD=%d, WR=%d]", g_wakeup_pipes[0], g_wakeup_pipes[1]);

		// ToDo - these pipe should be closed at some point
		// orig_os_api.close(g_si_wakeup_pipes[1]);
		// orig_os_api.close(g_si_wakeup_pipes[0]);
	}

	m_ev.events = EPOLLIN;
	m_ev.data.fd = g_wakeup_pipes[0];
}
void wakeup::going_to_sleep()
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if(likely(m_epfd))
		m_is_sleeping++;
	else
	{
		wkup_logerr(" m_epfd is not initialized - cannot use wakeup mechanism\n");
                m_is_sleeping = 0;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

void wakeup::wakeup_set_epoll_fd(int epfd)
{
	m_epfd = epfd;
}

void wakeup::do_wakeup()
{
	wkup_logfuncall("");

	//m_wakeup_lock.lock();
	//This func should be called under socket / epoll lock

	//Call to wakeup only in case there is some thread that is sleeping on epoll
	if (!m_is_sleeping)
	{
		wkup_logfunc("There is no thread in epoll_wait, therefore not calling for wakeup");
		//m_wakeup_lock.unlock();
		return;
	}

	wkup_entry_dbg("");

	int errno_tmp = errno; //don't let wakeup affect errno, as this can fail with EEXIST
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_ADD, g_wakeup_pipes[0], &m_ev)) && (errno != EEXIST)) {
		wkup_logerr("Failed to add wakeup fd to internal epfd (errno=%d %m)", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	errno = errno_tmp;

	//m_wakeup_lock.unlock();
	//sched_yield();
}

void wakeup::remove_wakeup_fd()
{
	if (m_is_sleeping) return;
	wkup_entry_dbg("");
	int tmp_errno = errno;
	if (orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_DEL, g_wakeup_pipes[0], NULL))
	{
		BULLSEYE_EXCLUDE_BLOCK_START
		if (errno == ENOENT)
			wkup_logdbg("Failed to delete global pipe from internal epfd it was already deleted");
		else
			wkup_logerr("failed to delete global pipe from internal epfd (errno=%d %m)", errno);
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	errno = tmp_errno;
}
