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


#include <vlogger/vlogger.h>
#include <vma/util/vtypes.h>

#include "vlogger_timer_handler.h"
#include "timer_handler.h"
#include "event_handler_manager.h"

vlogger_timer_handler* g_p_vlogger_timer_handler = NULL;

vlogger_timer_handler::vlogger_timer_handler():m_timer_handle(NULL)
{	
	if (g_p_event_handler_manager) {
			/* failure in allocating m_timer_handle will result in throwing an exception by called methods */
			m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_VLOGGER_LEVELS_INTERVAL, this, PERIODIC_TIMER, 0);
		}
}

vlogger_timer_handler::~vlogger_timer_handler()
{
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}

void vlogger_timer_handler::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	if (g_p_vlogger_level)
		g_vlogger_level = *g_p_vlogger_level;
	if (g_p_vlogger_details)
		g_vlogger_details = *g_p_vlogger_details;			
}






