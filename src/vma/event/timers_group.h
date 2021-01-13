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


#ifndef TIMERS_GROUP_H
#define TIMERS_GROUP_H

/*
 * This is an API for batching timers into groups.
 * Instead of registering each timer separately into the internal thread, the group is registered once,
 * and the timers are registered to the group.
 * The registration to the group is still done through the internal thread.
 * The group must be deleted through the internal thread (must implement clean_obj interface).
 * Registering to group must be used with register_timer_event() and unregister_timer_event() only.
 */
class timers_group : public timer_handler {
public:
	virtual ~timers_group() {};
	// execute all the timers registered to the group
	// according to the internal group logic.
	virtual void handle_timer_expired(void* user_data) = 0;

protected:
	friend class event_handler_manager;
	// add a new timer
	virtual void add_new_timer(timer_node_t* node, timer_handler* handler, void* user_data) = 0;

	// remove timer from list and free it.
	// called for stopping (unregistering) a timer
	virtual void remove_timer(timer_node_t* node) = 0;
};

#endif
