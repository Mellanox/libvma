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
