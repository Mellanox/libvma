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


#include <vlogger/vlogger.h>
#include <vma/util/vtypes.h>

#include "vlogger_timer_handler.h"
#include "timer_handler.h"
#include "event_handler_manager.h"

vlogger_timer_handler* g_p_vlogger_timer_handler = NULL;

vlogger_timer_handler::vlogger_timer_handler():m_timer_handle(NULL)
{	
	if (g_p_event_handler_manager)
		m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_VLOGGER_LEVELS_INTERVAL, this, PERIODIC_TIMER, 0);
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






