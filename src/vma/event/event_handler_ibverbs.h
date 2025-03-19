/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef EVENT_HANDLER_IBVERBS_H
#define EVENT_HANDLER_IBVERBS_H

/*
 * @class event_handler
 * An object registers with event_handler_manager to get event notification callbacks for the registered HCA context.
 * This callback function will be called when an event was received on the appropritae channel with the appropritae id.
 * The channels can be shared between several objects, but the id's in each channel has to be unic.
 */
class event_handler_ibverbs
{
public:
	virtual ~event_handler_ibverbs() {};
	virtual void handle_event_ibverbs_cb(void* ev_data, void* user_data) = 0;
};

#endif //EVENT_HANDLER_IBVERBS_H
