/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef DELTA_TIMER_H
#define DELTA_TIMER_H

#include <chrono>
#include "utils/lock_wrapper.h"

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
	/* delta time from the previous node (millisec) */
	std::chrono::milliseconds            delta_time_msec;
	/* the orig timer requested (saved in order to re-register periodic timers) */
	std::chrono::milliseconds            orig_time_msec;
	/* control thread-safe access to handler. Recursive because unregister_timer_event()
	 * can be called from handle_timer_expired()
	 * that is under trylock() inside process_registered_timers
	 */
	lock_spin_recursive     lock_timer;
	/* link to the context registered */
	timer_handler*          handler;
	void*                   user_data;
	timers_group*           group;
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

	// wakeup existing timer
	void    wakeup_timer(timer_node_t* node);

	// remove timer from list and free it.
	// called for stopping (unregistering) a timer
	void    remove_timer(timer_node_t* node, timer_handler* handler);

	// remove all timers from list and free it.
	// called for stopping (unregistering) all timers
	void    remove_all_timers(timer_handler* handler);

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
	std::chrono::time_point<std::chrono::steady_clock>    m_ts_last;
};

const char* timer_req_type_str(timer_req_type_t type);

#endif //DELTA_TIMER_H
