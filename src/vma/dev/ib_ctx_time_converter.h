/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef IB_CTX_TIME_CONVERTER_H
#define IB_CTX_TIME_CONVERTER_H

#include <infiniband/verbs.h>
#include "vma/event/timer_handler.h"
#include <vma/util/sys_vars.h>

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

class ib_ctx_time_converter :  public timer_handler
{
public:

	ib_ctx_time_converter(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode);
	virtual ~ib_ctx_time_converter();

	void                      convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime);
	void                      handle_timer_expired(void* user_data);

	uint64_t                  get_hca_core_clock();
	ts_conversion_mode_t      get_converter_status();
	static ts_conversion_mode_t     get_devices_convertor_status(struct ibv_context** ibv_context_list, int num_devices);

private:

	struct ibv_context*       m_p_ibv_context;
	ctx_timestamping_params_t m_ctx_convert_parmeters[2];
	int                       m_ctx_parmeters_id;
	void*                     m_timer_handle;
	ts_conversion_mode_t      m_converter_status;

	void                      fix_hw_clock_deviation();
	bool                      sync_clocks(struct timespec* st, uint64_t* hw_clock);
	static uint32_t           get_device_convertor_status(struct ibv_context* ctx);
};


#endif
