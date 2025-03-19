/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef V_SM_FIFO_H
#define V_SM_FIFO_H

#include <deque>
#include <stdio.h>

typedef struct {
	int	event;             
	void*	ev_data;
} sm_fifo_entry_t;

typedef std::deque<sm_fifo_entry_t> sm_event_list_t;


class sm_fifo
{
public:
	bool 		is_empty();
	void 		push_back(int element, void* ev_data);
	sm_fifo_entry_t	pop_front();
	void 		debug_print_fifo();

private:
	sm_event_list_t	m_sm_event_fifo;
};

#endif
