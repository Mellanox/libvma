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


#ifndef DELTA_TIMER_H
#define DELTA_TIMER_H

#include <time.h>
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
	unsigned int            delta_time_msec;
	/* the orig timer requested (saved in order to re-register periodic timers) */
	unsigned int            orig_time_msec;
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
	timespec        m_ts_last;
};

const char* timer_req_type_str(timer_req_type_t type);

#endif //DELTA_TIMER_H
