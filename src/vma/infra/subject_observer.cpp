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


#include "vlogger/vlogger.h"
#include "vma/infra/subject_observer.h"

#define MODULE_NAME "subject_observer"

#define	sub_obs_logerr               __log_info_err
#define sub_obs_logwarn              __log_info_warn
#define sub_obs_loginfo              __log_info_info
#define sub_obs_logdbg               __log_info_dbg
#define sub_obs_logfunc              __log_info_func
#define sub_obs_logfuncall           __log_info_funcall


bool subject::register_observer(IN const observer* const new_observer)
{
	if (new_observer == NULL) {
//		sub_obs_logdbg("[%s] observer (NULL)", to_str());
		return false;
	}

	auto_unlocker lock(m_lock);
	if (m_observers.count((observer *)new_observer) > 0) {
//		sub_obs_logdbg("[%s] Observer is already registered (%p)", to_str(), new_observer);
		return false;
	}
	m_observers.insert((observer *)new_observer);
//	sub_obs_logdbg("[%s] Successfully registered new_observer %s", to_str(), new_observer->to_str());
	return true;
}

bool subject::unregister_observer(IN const observer * const old_observer)
{
	if (old_observer == NULL) {
//		sub_obs_logdbg("[%s] observer (NULL)", to_str());
		return false;
	}

	auto_unlocker lock(m_lock);
	m_observers.erase((observer *)old_observer);
//	sub_obs_logdbg("[%s] Successfully unregistered old_observer %s",to_str(), old_observer->to_str());
	return true;
}

void subject::notify_observers(event* ev /*=NULL*/)
{
//	sub_obs_logdbg("[%s]", to_str());

	auto_unlocker lock(m_lock);
	for (observers_t::iterator iter = m_observers.begin(); iter != m_observers.end(); iter++) {
		if (ev)
			(*iter)->notify_cb(ev);
		else
			(*iter)->notify_cb();
	}
}
