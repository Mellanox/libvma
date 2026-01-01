/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef TIME_CONVERTER_PTP_H
#define TIME_CONVERTER_PTP_H

#include <infiniband/verbs.h>
#include "vma/event/timer_handler.h"
#include <vma/util/sys_vars.h>
#include "time_converter.h"

#ifdef DEFINED_IBV_CLOCK_INFO

class time_converter_ptp : public time_converter
{
public:
	time_converter_ptp(struct ibv_context* ctx);
	virtual ~time_converter_ptp() {};

	inline void               convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime);
	virtual void              handle_timer_expired(void* user_data);

private:
	struct ibv_context*       m_p_ibv_context;

	mlx5dv_clock_info         m_clock_values[2];
	int                       m_clock_values_id;
};

#endif // DEFINED_IBV_CLOCK_INFO
#endif // TIME_CONVERTER_PTP_H
