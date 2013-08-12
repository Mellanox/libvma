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


#ifndef SM_H
#define SM_H

#include "sm_fifo.h"
#include <vlogger/vlogger.h>

class sm_fifo;


#define ERROR 		(-1)
#define SM_NO_ST	(-2)
#define SM_NO_EV	(-2)
#define SM_ST_STAY	(-3)
#define SM_STATE_ENTRY	(-4)
#define SM_STATE_LEAVE	(-5)
#define SM_TABLE_END	{ SM_NO_ST,     SM_NO_EV,       SM_NO_ST,      NULL}


typedef struct {
	int	old_state;
	int	new_state;
	int	event;
	void*	ev_data;
	void*	app_hndl;
} sm_info_t;

// SM Callback prototypes
typedef void (*sm_action_cb_t)(const sm_info_t& info);
typedef void (*sm_new_event_notify_cb_t)(int state, int event, void* app_hndl);


// Short table line
typedef struct {
	int		state;		// State to handle event
	int		event;		// Event to handle
	int		next_state;	// New state to move to
	sm_action_cb_t	action_func;	// Do-function
} sm_short_table_line_t;


// sparse (big) table event entry
typedef struct {
	int         next_state; // New state to move to
	sm_action_cb_t      trans_func; // Do-function
} sm_event_info_t;



// sparse (big) table state entry (including all events)
typedef struct sm_state_info{
	sm_action_cb_t      entry_func; // Entry function
	sm_action_cb_t      leave_func; // Leave function
	sm_event_info_t*    event_info; // Event -> Transition function
} sm_state_info_t;

    


class state_machine
{
public:
	// get short matrix and build the sparse matrix
	state_machine(void*			app_hndl, 
		      int 			start_state,
		      int			max_states,
		      int			max_events,
		      sm_short_table_line_t*	short_table,
		      sm_action_cb_t		default_entry_func,
		      sm_action_cb_t		default_leave_func,
		      sm_action_cb_t		default_trans_func,
		      sm_new_event_notify_cb_t	new_event_notify_func
		      );
	~state_machine();

	int                     process_event(int event, void* ev_data);
	int			get_curr_state();

private:
	// convert function (from short to sparse matrix)
	int                     process_sparse_table(sm_short_table_line_t*	short_table, 
						     sm_action_cb_t		default_entry_func,
						     sm_action_cb_t		default_leave_func,
						     sm_action_cb_t		default_trans_func
						     );

	// warp internal fifo in lock/unlock logic
	int			lock_in_process(int event, void* ev_data);
	void			unlock_in_process();

	int			m_max_states;		// MAX state
	int			m_max_events;		// MAX event
	sm_state_info_t*	m_p_sm_table;		// pointer to full SM table
	sm_new_event_notify_cb_t m_new_event_notify_func;
	sm_fifo*		m_sm_fifo;		// fifo queue for the events
	bool			m_b_is_in_process;

	sm_info_t		m_info;			// SM info to provide user in all CB functions
};

#endif //SM_H
