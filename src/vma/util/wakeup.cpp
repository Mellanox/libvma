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
#include "wakeup.h"
#include <vma/sock/sock-redirect.h>

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

wakeup::wakeup()
{
	m_epfd = 0;
	m_is_sleeping = 0;
	memset(&m_ev, 0, sizeof(m_ev));
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
