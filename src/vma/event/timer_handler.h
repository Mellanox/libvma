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


#ifndef TIMER_HANDLER_H
#define TIMER_HANDLER_H

/**
 * simple timer notification.
 * Any class that inherit timer_handler should also inherit cleanable_obj, and use clean_obj instead of delete.
 * It must implement the clean_obj method to delete the object from the internal thread.
 */
class timer_handler
{
public:
	virtual ~timer_handler() {};
	virtual void handle_timer_expired(void* user_data) = 0;
};

#endif
