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
