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


#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "wakeup_pipe.h"
#include "vma/sock/sock-redirect.h"

#define MODULE_NAME "wakeup_pipe"

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
#define UNINIT_PIPE_FD (-1)

int wakeup_pipe::g_wakeup_pipes[2] = {UNINIT_PIPE_FD, UNINIT_PIPE_FD};
atomic_t wakeup_pipe::ref_count = ATOMIC_INIT(0);

wakeup_pipe::wakeup_pipe()
{
	int ref = atomic_fetch_and_inc(&ref_count);
	if (ref == 0) {
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

void wakeup_pipe::do_wakeup()
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

void wakeup_pipe::remove_wakeup_fd()
{
	if (m_is_sleeping) return;
	wkup_entry_dbg("");
	int tmp_errno = errno;
	if (orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_DEL, g_wakeup_pipes[0], NULL))
	{
		BULLSEYE_EXCLUDE_BLOCK_START
		if (errno == ENOENT) {
			wkup_logdbg("Failed to delete global pipe from internal epfd it was already deleted");
		} else {
			wkup_logerr("failed to delete global pipe from internal epfd (errno=%d %m)", errno);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	errno = tmp_errno;
}

wakeup_pipe::~wakeup_pipe()
{
	int ref = atomic_fetch_and_dec(&ref_count);
	if (ref == 1) {
		close(g_wakeup_pipes[0]);
		close(g_wakeup_pipes[1]);
		g_wakeup_pipes[0] = UNINIT_PIPE_FD;
		g_wakeup_pipes[1] = UNINIT_PIPE_FD;
	}
}
