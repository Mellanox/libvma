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


#ifndef DELTA_TIMER_H
#define DELTA_TIMER_H

#include <time.h>

#define INFINITE_TIMEOUT (-1)

class timer_handler;
class timers_group;

enum timer_req_type_t {
	// reregister itself every after timer expires. (the client doesn't need to reregister)
	// in order to stop the timer, the client needs to unregister
	PERIODIC_TIMER, 

	// after the timer expires the client doesn't need to unregister
	ONE_SHOT_TIMER,

	INVALID_TIMER
};

struct timer_node_t {
	unsigned int            delta_time_msec;/* delta time from the previous node (millisec) */
	unsigned int            orig_time_msec;	/* the orig timer requested (saved in order to re-register periodic timers) */
	timer_handler*          handler;	/* link to the context registered */  
	void*                   user_data;
	timers_group*		group;
	timer_req_type_t        req_type;
	struct timer_node_t*    next;
	struct timer_node_t*    prev;
}; // used by the list

class timer 
{
public:
	timer();
	~timer();

	// add a new timer 
	void    add_new_timer(unsigned int timeout, timer_node_t* node, timer_handler* handler,
			      void* user_data, timer_req_type_t req_type);

	// remove timer from list and free it.
	// called for stopping (unregistering) a timer
	void    remove_timer(timer_node_t* node, timer_handler* handler);

	// remove all timers from list and free it.
	// called for stopping (unregistering) all timers
	void    remove_all_timers(timer_handler* handler);

	// returns the next time to wait
	int     get_time_to_wait();

	// update the timeout in first element in the list
	// return the timeout needed. (or INFINITE_TIMEOUT if there's no timeout)
	int     update_timeout();

	// run "tick" func for all the registered timer handler that their timeout expiered
	void    process_registered_timers();

	void    debug_print_list();

private:
	void    insert_to_list(timer_node_t* node);
	void    remove_from_list(timer_node_t* node);

	timer_node_t*   m_list_head;
	timespec        m_ts_last;
};

const char* timer_req_type_str(timer_req_type_t type);

#endif //DELTA_TIMER_H
