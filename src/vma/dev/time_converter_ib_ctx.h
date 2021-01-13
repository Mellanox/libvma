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


#ifndef TIME_CONVERTER_IB_CTX_H
#define TIME_CONVERTER_IB_CTX_H

#include <infiniband/verbs.h>
#include <vma/util/sys_vars.h>
#include "time_converter.h"


class time_converter_ib_ctx : public time_converter
{
public:
	time_converter_ib_ctx(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode, uint64_t hca_core_clock);

	virtual ~time_converter_ib_ctx() {};

	void                      convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime);
	void                      handle_timer_expired(void* user_data);
	uint64_t                  get_hca_core_clock();

private:
	struct ibv_context*       m_p_ibv_context;
	ctx_timestamping_params_t m_ctx_convert_parmeters[2];
	int                       m_ctx_parmeters_id;

	void                      fix_hw_clock_deviation();
	inline void               calculate_delta(struct timespec& hw_to_timespec, uint64_t hca_core_clock, uint64_t hw_time_diff);
	bool                      sync_clocks(struct timespec* st, uint64_t* hw_clock);
};

#endif // TIME_CONVERTER_IB_CTX_H
