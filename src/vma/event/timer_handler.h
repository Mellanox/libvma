/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
