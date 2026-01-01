/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "sm_fifo.h"

bool sm_fifo::is_empty()
{
	return m_sm_event_fifo.empty();
}

void sm_fifo::push_back(int element, void* ev_data)
{
	sm_fifo_entry_t fe;
	fe.ev_data = ev_data;
	fe.event = element;
	m_sm_event_fifo.push_back(fe);
}

// Return the first element in the fifo.
// in case the fifo is empty: ret.event = -1
sm_fifo_entry_t sm_fifo::pop_front()
{
	sm_fifo_entry_t ret;
	ret.event = -1;
	ret.ev_data = NULL;
	if (!m_sm_event_fifo.empty()) {
		ret = m_sm_event_fifo.front();
		m_sm_event_fifo.pop_front();
	}
	return ret;
}

//code coverage
#if 0
void sm_fifo::debug_print_fifo()
{
	int i = 1;
	sm_event_list_t::iterator tmp = m_sm_event_fifo.begin();
	for (sm_event_list_t::iterator tmp = m_sm_event_fifo.begin(); tmp != m_sm_event_fifo.end(); tmp++) {
		printf("element num %d is %d\n",i , tmp->event);
		i++;
	}
}
#endif

