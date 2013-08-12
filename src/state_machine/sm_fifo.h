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
