/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef TIME_CONVERTER_H
#define TIME_CONVERTER_H

#include <unordered_map>
#include <infiniband/verbs.h>

#include "vma/util/sys_vars.h"
#include "vma/sock/cleanable_obj.h"
#include "vma/event/timer_handler.h"

class net_device_val;
typedef std::unordered_map<int, net_device_val*> net_device_map_t;

class ctx_timestamping_params_t {
public:

	uint64_t                hca_core_clock;
	uint64_t                sync_hw_clock;
	struct timespec         sync_systime;

	ctx_timestamping_params_t() : hca_core_clock(0), sync_hw_clock(0) {
		sync_systime.tv_sec = 0;
		sync_systime.tv_nsec = 0;
	}
};

class time_converter : public timer_handler, public cleanable_obj
{
public:
	time_converter(): m_timer_handle(NULL), m_converter_status(TS_CONVERSION_MODE_DISABLE) {};
	virtual ~time_converter() = 0;

	virtual void              convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) = 0;
	virtual void              handle_timer_expired(void* user_data) = 0;
	virtual void              clean_obj();
	ts_conversion_mode_t      get_converter_status() { return m_converter_status; };

	static ts_conversion_mode_t update_device_converters_status(net_device_map_t& net_devices);

protected:
	void*                     m_timer_handle;
	ts_conversion_mode_t      m_converter_status;

	static uint32_t           get_single_converter_status(struct ibv_context* ctx);
};

// pure virtual destructor implementation
inline time_converter::~time_converter() { }

#endif //TIME_CONVERTER_H
