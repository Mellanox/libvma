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


#ifndef VLOGGER_TIMER_HANDLER_H
#define VLOGGER_TIMER_HANDLER_H

#include "timer_handler.h"

#define UPDATE_VLOGGER_LEVELS_INTERVAL	100

class vlogger_timer_handler : public timer_handler
{
public:
	vlogger_timer_handler();
	~vlogger_timer_handler();
private:
	void handle_timer_expired(void* user_data);
	
	void*	m_timer_handle;
};

extern vlogger_timer_handler* g_p_vlogger_timer_handler;

#endif /*VLOGGER_TIMER_HANDLER_H*/
