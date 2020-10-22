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

#include <sys/eventfd.h>
#include "vlogger/vlogger.h"
#include "wakeup_eventfd.h"

#define MODULE_NAME "wakeup_eventfd"

#define wkup_logpanic             __log_info_panic
#define wkup_logerr               __log_info_err
#define wkup_logwarn              __log_info_warn
#define wkup_loginfo              __log_info_info
#define wkup_logdbg               __log_info_dbg
#define wkup_logfunc              __log_info_func
#define wkup_logfuncall           __log_info_funcall
#define wkup_entry_dbg		  __log_entry_dbg

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[wakeup_fd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__	m_wakeup_fd

wakeup_eventfd::wakeup_eventfd()
{
	m_wakeup_fd = eventfd(0, 0);
}

void wakeup_eventfd::do_wakeup()
{
	wkup_logfuncall("");
	if (!m_is_sleeping) {
		wkup_logfunc("There is no thread in poll_wait, therefore not calling for wakeup");
		return;
	}
	wkup_entry_dbg("");
	uint64_t inc = 1;
	if (write(m_wakeup_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
		wkup_logerr("Failed to increase counter wakeup fd");
	}
}

void wakeup_eventfd::remove_wakeup_fd()
{
	if (m_is_sleeping) return;
	wkup_entry_dbg("");
	uint64_t inc;
	if (read(m_wakeup_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
		wkup_logerr("Failed to reduce counter wakeup fd");
	}
}

wakeup_eventfd::~wakeup_eventfd()
{
	close(m_wakeup_fd);
}
