/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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


#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "utils/rdtsc.h"
#include "vma/util/instrumentation.h"
#include "vma/util/utils.h"
#include "vma/dev/time_converter_ptp.h"
#include "vma/ib/base/verbs_extra.h"


#ifdef DEFINED_IBV_EXP_VALUES_CLOCK_INFO

#define MODULE_NAME             "time_converter_ptp"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_dbg

#define UPDATE_HW_TIMER_PTP_PERIOD_MS 100


time_converter_ptp::time_converter_ptp(struct ibv_context* ctx) :
	m_timer_handle(NULL), m_p_ibv_context(ctx), m_ibv_exp_values_id(0)
{
	for (size_t i=0; i < ARRAY_SIZE(m_ibv_exp_values); i++) {
		memset(&m_ibv_exp_values[i], 0, sizeof(m_ibv_exp_values[i]));
		if (ibv_exp_query_values(m_p_ibv_context, IBV_EXP_VALUES_CLOCK_INFO, &m_ibv_exp_values[i])) {
			ibchtc_logerr("ibv_exp_query_values failure for clock_info, (ibv context %p)",
					m_p_ibv_context);
		}
	}

	m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PTP_PERIOD_MS, this, PERIODIC_TIMER, 0);
	m_converter_status = TS_CONVERSION_MODE_PTP;
}

time_converter_ptp::~time_converter_ptp() {
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}

void time_converter_ptp::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);

	int ret = 0;
	ret = ibv_exp_query_values(m_p_ibv_context, IBV_EXP_VALUES_CLOCK_INFO, &m_ibv_exp_values[1 - m_ibv_exp_values_id]);
	if (ret)
		ibchtc_logerr("ibv_exp_query_values failure for clock_info, (ibv context %p) (return value=%d)",
				m_p_ibv_context, ret);

	m_ibv_exp_values_id = 1 - m_ibv_exp_values_id;
}

void time_converter_ptp::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) {
	uint64_t sync_hw_clock = ibv_exp_cqe_ts_to_ns(&m_ibv_exp_values[m_ibv_exp_values_id].clock_info, hwtime);
	systime->tv_sec = sync_hw_clock / NSEC_PER_SEC;
	systime->tv_nsec = sync_hw_clock % NSEC_PER_SEC;

	ibchtc_logdbg("hwtime:	.%09ld", hwtime);
	ibchtc_logdbg("systime after clock fix:	%lld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif //DEFINED_IBV_EXP_VALUES_CLOCK_INFO
