/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "utils/rdtsc.h"
#include "vma/util/instrumentation.h"
#include "vma/util/utils.h"
#include "vma/dev/time_converter_ptp.h"
#include "vma/ib/base/verbs_extra.h"


#ifdef DEFINED_IBV_CLOCK_INFO

#define MODULE_NAME             "tc_ptp"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_info_dbg
#define ibchtc_logfunc __log_info_func

#define UPDATE_HW_TIMER_PTP_PERIOD_MS 100


time_converter_ptp::time_converter_ptp(struct ibv_context* ctx) :
	m_p_ibv_context(ctx), m_clock_values_id(0)
{
	for (size_t i=0; i < ARRAY_SIZE(m_clock_values); i++) {
		memset(&m_clock_values[i], 0, sizeof(m_clock_values[i]));
		if (mlx5dv_get_clock_info(m_p_ibv_context, &m_clock_values[i])) {
			ibchtc_logerr("mlx5dv_get_clock_info failure for clock_info, (ibv context %p)", m_p_ibv_context);
		}
	}

	m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PTP_PERIOD_MS, this, PERIODIC_TIMER, 0);
	m_converter_status = TS_CONVERSION_MODE_PTP;
}

void time_converter_ptp::handle_timer_expired(void* user_data) {

	NOT_IN_USE(user_data);

	if (is_cleaned()) {
		return;
	}

	int ret = 0;
	ret = mlx5dv_get_clock_info(m_p_ibv_context, &m_clock_values[1 - m_clock_values_id]);
	if (ret)
		ibchtc_logerr("mlx5dv_get_clock_info failure for clock_info, (ibv context %p) (return value=%d)", m_p_ibv_context, ret);

	m_clock_values_id = 1 - m_clock_values_id;
}

void time_converter_ptp::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) {
	uint64_t sync_hw_clock = mlx5dv_ts_to_ns(&m_clock_values[m_clock_values_id], hwtime);
	systime->tv_sec = sync_hw_clock / NSEC_PER_SEC;
	systime->tv_nsec = sync_hw_clock % NSEC_PER_SEC;

	ibchtc_logfunc("hwtime: 	%09ld", hwtime);
	ibchtc_logfunc("systime:	%lld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif //DEFINED_IBV_CLOCK_INFO
