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


#include "sm.h"

#include <vlogger/vlogger.h>

#include "sm_fifo.h"
#include <stdio.h>
#include <stdlib.h>
#include "vma/util/bullseye.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"sm"

#define sm_logpanic		__log_info_panic
#define sm_logerr		__log_info_err
#define sm_logdbg		__log_info_dbg
#define sm_logfunc		__log_info_func

#define SM_ASSERT_POINTER(__ptr)	{ if (__ptr == NULL) sm_logpanic("problem with memory allocation"); }

state_machine::state_machine(void* 			app_hndl,
			     int 			start_state,
			     int 			max_states,
			     int 			max_events, 
			     sm_short_table_line_t* 	short_table, 
			     sm_action_cb_t 		default_entry_func, 
			     sm_action_cb_t 		default_leave_func,
			     sm_action_cb_t 		default_trans_func, 
			     sm_new_event_notify_cb_t	new_event_notify_func
			    ) :
	m_max_states(max_states), m_max_events(max_events),
	m_new_event_notify_func(new_event_notify_func),
	m_b_is_in_process(false)
{
BULLSEYE_EXCLUDE_BLOCK_START
	if (start_state < 0 || start_state >= m_max_states)
		sm_logpanic("SM start state out of range for app_hndl %p (min=%d, max=%d, start=%d)", app_hndl, 0, m_max_states, start_state);
BULLSEYE_EXCLUDE_BLOCK_END

	m_info.old_state = start_state;
	m_info.new_state = -1;
	m_info.event = -1;
	m_info.ev_data = NULL;
	m_info.app_hndl = app_hndl;

	m_sm_fifo = new sm_fifo;
	SM_ASSERT_POINTER(m_sm_fifo);

	int ret = process_sparse_table(short_table, default_entry_func, default_leave_func, default_trans_func);
BULLSEYE_EXCLUDE_BLOCK_START
	if (ret) {
		// TODO - check status
	}
BULLSEYE_EXCLUDE_BLOCK_END
}

state_machine::~state_machine()
{
	for (int st=0; st<m_max_states; st++) {
		free(m_p_sm_table[st].event_info);
	}
	free(m_p_sm_table);
	delete m_sm_fifo;
}

int state_machine::get_curr_state()
{
	return m_info.old_state;
}

int state_machine::process_sparse_table(sm_short_table_line_t* 	short_table, 
					sm_action_cb_t	default_entry_func,
					sm_action_cb_t	default_leave_func,
					sm_action_cb_t	default_trans_func)
{
	int st, ev, line;
	int next_state;
	sm_action_cb_t action_func;

	int sm_table_entries_size = 0;
	m_p_sm_table = (sm_state_info_t*)malloc(m_max_states * sizeof(sm_state_info_t));
	SM_ASSERT_POINTER(m_p_sm_table);
	sm_table_entries_size += m_max_states * sizeof(sm_state_info_t);

	// Allocate memory for the big table
	for (st=0; st<m_max_states; st++) {
		m_p_sm_table[st].event_info = (sm_event_info_t*)malloc(m_max_events * sizeof(sm_event_info_t));
		SM_ASSERT_POINTER(m_p_sm_table[st].event_info);
		sm_table_entries_size += m_max_events * sizeof(sm_event_info_t);
	}

	// Fill full SM table to default values 
	for (st=0; st < m_max_states; st++) {
		m_p_sm_table[ st ].entry_func = default_entry_func;
		m_p_sm_table[ st ].leave_func = default_leave_func;
		for (ev=0; ev < m_max_events; ev++) {
			m_p_sm_table[ st ].event_info[ ev ].next_state = SM_ST_STAY;	// in case of calling unwanted event
			m_p_sm_table[ st ].event_info[ ev ].trans_func = default_trans_func;
		}
	}

	// Fill full SM table with specific action detail values 
	line = 0;
	while (1) {
		st = short_table[ line ].state;
		if (st == SM_NO_ST) // End of table
			break;

		ev = short_table[ line ].event;
		next_state  = short_table[ line ].next_state;
		action_func = short_table[ line ].action_func;

BULLSEYE_EXCLUDE_BLOCK_START
		if (st < 0 || st >= m_max_states) {
			sm_logerr("ERROR on line [%d]: STATE bad value!! St[%d], Ev[%d] (nextSt[%d], action func[%p])", 
				    line+1, st, ev, next_state, action_func);
			return ERROR;
		}
BULLSEYE_EXCLUDE_BLOCK_END
		switch (ev) {
		case SM_STATE_ENTRY:
			sm_logfunc("line %d: St[%d], Ev[ENTRY] (action func[%p])", line+1, st, action_func);
			m_p_sm_table[ st ].entry_func = action_func;
			break;

		case SM_STATE_LEAVE:
			sm_logfunc("line %d: St[%d], Ev[LEAVE] (action func[%p])", line+1, st, action_func);
			m_p_sm_table[ st ].leave_func = action_func;
			break;

		default:
			{
				sm_logfunc("line %d: St[%d], Ev[%d] (nextSt[%d], action func[%p])", line+1, st, ev, next_state, action_func);
BULLSEYE_EXCLUDE_BLOCK_START
				if (ev < 0 || ev >= m_max_events) {
					sm_logerr("ERROR on line [%d]: EVENT bad value!! St[%d], Ev[%d] (nextSt[%d], action func[%p])",
						    line+1, st, ev, next_state, action_func);
					return ERROR;
				}

				if (next_state >= m_max_states) {
					sm_logerr("ERROR on line [%d]: next state bad value!! St[%d], Ev[%d] (nextSt[%d], action func[%p])",
						    line+1, st, ev, next_state, action_func);
					return ERROR;
				}

				if (m_p_sm_table[ st ].event_info[ ev ].trans_func != default_trans_func) {
					sm_logerr("ERROR on line [%d]: St+Ev entry re-use error!!! St[%d], Ev[%d] (nextSt[%d], action func[%p])",
						    line+1, st, ev, next_state, action_func);
					return ERROR;
				}
BULLSEYE_EXCLUDE_BLOCK_END
				m_p_sm_table[ st ].event_info[ ev ].next_state = next_state;
				m_p_sm_table[ st ].event_info[ ev ].trans_func = action_func;
			}
			break;
		}

		// Continue with next line in users short table
		line++;
	}

	sm_logdbg("SM full table processing done. Allocated memory size of %d bytes", sm_table_entries_size);
	return 0;
}



int  state_machine::lock_in_process(int event, void* ev_data)
{
	if (!m_b_is_in_process) {
		m_b_is_in_process = 1;
		sm_logfunc("lock_in_process: critical section free. Locking it");
	}
	else {
		m_sm_fifo->push_back(event, ev_data);
		sm_logfunc("lock_in_process: critical section is in use");
		return -1;
	}
	return 0;
}


void state_machine::unlock_in_process()
{
	m_b_is_in_process = 0;
	if (m_sm_fifo->is_empty()) {
		sm_logfunc("unlock_in_process: there are no pending events");
	}
	else {
		sm_logfunc("unlock_in_process: there are pending events");
		sm_fifo_entry_t ret = m_sm_fifo->pop_front();
		process_event(ret.event, ret.ev_data);
	}
}


int state_machine::process_event(int event, void* ev_data)
{
	if (lock_in_process(event, ev_data) == -1) {
		return 0;
	}

BULLSEYE_EXCLUDE_BLOCK_END
	// if we got here: State machine is free
	if ((event > m_max_events) || (event < 0)) {
		sm_logdbg("ERROR: illegal event num %d", event);
		unlock_in_process();
		return -1;
	}
BULLSEYE_EXCLUDE_BLOCK_END
	sm_state_info_t* p_sm_state_info = &m_p_sm_table[get_curr_state()];
	int next_state = p_sm_state_info->event_info[event].next_state;
	m_info.new_state = next_state;
	m_info.event = event;
	m_info.ev_data = ev_data;

	// Run print event info function
	if (m_new_event_notify_func) {
		m_new_event_notify_func(get_curr_state(), event, m_info.app_hndl);
	}

	// Run leave function
	if ((next_state != get_curr_state()) && (next_state != SM_ST_STAY) && p_sm_state_info->leave_func) {
		p_sm_state_info->leave_func(m_info); 
	}

	// Run the action function
	if (p_sm_state_info->event_info[event].trans_func) {
		p_sm_state_info->event_info[event].trans_func(m_info);
	}

	// Move to next state
	if ((next_state !=  get_curr_state()) && (next_state != SM_ST_STAY)) {

		// Run entry function
		if (m_p_sm_table[next_state].entry_func) {
			m_p_sm_table[next_state].entry_func(m_info); 
		}

		// Update current state
		m_info.old_state = next_state;
	}

	unlock_in_process();
	return 0;
}

