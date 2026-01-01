/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
