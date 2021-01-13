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

