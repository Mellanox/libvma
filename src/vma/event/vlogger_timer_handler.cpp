/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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






