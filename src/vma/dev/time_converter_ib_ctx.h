/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
