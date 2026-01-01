/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef EVENT_HANDLER_RDMA_CM_H
#define EVENT_HANDLER_RDMA_CM_H

#include <rdma/rdma_cma.h>

/*
 * @class event_handler
 * An object registers with event_handler_manager to get event notification callbacks for the registered rdma_cm id's.
 * This callback function will be called when an event was received on the appropritae channel with the appropritae id.
 * The channels can be shared between several objects, but the id's in each channel has to be unic.
 */
class event_handler_rdma_cm
{
public:
	virtual ~event_handler_rdma_cm() {};
	virtual void handle_event_rdma_cm_cb(struct rdma_cm_event* p_event) = 0;
};

#endif //EVENT_HANDLER_RDMA_CM_H
