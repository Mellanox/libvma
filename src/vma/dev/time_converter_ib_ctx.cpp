/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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
#include "time_converter_ib_ctx.h"
#include "vma/ib/base/verbs_extra.h"

#define MODULE_NAME             "time_converter_ib_ctx"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_dbg


#define UPDATE_HW_TIMER_PERIOD_MS 1000
#define UPDATE_HW_TIMER_FIRST_ONESHOT_MS 100
#define UPDATE_HW_TIMER_SECOND_ONESHOT_MS 200

#define IB_CTX_TC_DEVIATION_THRESHOLD 10

time_converter_ib_ctx::time_converter_ib_ctx(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode, uint64_t hca_core_clock) :
	m_p_ibv_context(ctx), m_ctx_parmeters_id(0)
{
#ifdef DEFINED_IBV_CQ_TIMESTAMP
	if (ctx_time_converter_mode != TS_CONVERSION_MODE_DISABLE) {
		ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];

		m_converter_status = TS_CONVERSION_MODE_RAW;
		current_parameters_set->hca_core_clock = hca_core_clock * USEC_PER_SEC;

		if (ctx_time_converter_mode != TS_CONVERSION_MODE_RAW) {
			if (sync_clocks(&current_parameters_set->sync_systime, &current_parameters_set->sync_hw_clock)) {
				m_converter_status = TS_CONVERSION_MODE_SYNC;

				g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_FIRST_ONESHOT_MS, this, ONE_SHOT_TIMER, 0);
				g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_SECOND_ONESHOT_MS, this, ONE_SHOT_TIMER, 0);
				m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PERIOD_MS, this, PERIODIC_TIMER, 0);
			}
		}
	}
#else
	NOT_IN_USE(hca_core_clock);
#endif
	if (ctx_time_converter_mode != m_converter_status) {
		ibchtc_logwarn("converter status different then expected (ibv context %p, value = %d , expected = %d)"
					, m_p_ibv_context, m_converter_status, ctx_time_converter_mode);
	}
}

void time_converter_ib_ctx::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);

	if (is_cleaned()) {
		return;
	}

	fix_hw_clock_deviation();
}

uint64_t time_converter_ib_ctx::get_hca_core_clock(){
	return m_ctx_convert_parmeters[m_ctx_parmeters_id].hca_core_clock;
}


#ifdef DEFINED_IBV_CQ_TIMESTAMP
bool time_converter_ib_ctx::sync_clocks(struct timespec* st, uint64_t* hw_clock){
	struct timespec st1, st2, diff, st_min = TIMESPEC_INITIALIZER;
	vma_ts_values queried_values;
	int64_t interval, best_interval = 0;
	uint64_t hw_clock_min = 0;

	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = VMA_IBV_VALUES_MASK_RAW_CLOCK;
	for (int i = 0 ; i < 10 ; i++) {
		clock_gettime(CLOCK_REALTIME, &st1);
		if (vma_ibv_query_values(m_p_ibv_context, &queried_values) || !vma_get_ts_val(queried_values)) {
			return false;
		}

		clock_gettime(CLOCK_REALTIME, &st2);
		interval = (st2.tv_sec - st1.tv_sec) * NSEC_PER_SEC + (st2.tv_nsec - st1.tv_nsec);

		if (!best_interval || interval < best_interval) {
			best_interval = interval;
			hw_clock_min = vma_get_ts_val(queried_values);

			interval /= 2;
			diff.tv_sec = interval / NSEC_PER_SEC;
			diff.tv_nsec = interval - (diff.tv_sec * NSEC_PER_SEC);
			ts_add(&st1, &diff, &st_min);
		}
	}
	*st = st_min;
	*hw_clock = hw_clock_min;
	return true;
}

void time_converter_ib_ctx::fix_hw_clock_deviation(){
	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];

	if (!current_parameters_set->hca_core_clock) {
		return;
	}

	struct timespec current_time, diff_systime;
	uint64_t diff_hw_time, diff_systime_nano, estimated_hw_time, hw_clock;
	int next_id = (m_ctx_parmeters_id + 1) % 2;
	ctx_timestamping_params_t* next_parameters_set = &m_ctx_convert_parmeters[next_id];
	int64_t deviation_hw;

	if (!sync_clocks(&current_time, &hw_clock)) {
		return;
	}

	ts_sub(&current_time, &current_parameters_set->sync_systime, &diff_systime);
	diff_hw_time = hw_clock - current_parameters_set->sync_hw_clock;
	diff_systime_nano = diff_systime.tv_sec * NSEC_PER_SEC + diff_systime.tv_nsec;

	estimated_hw_time = (diff_systime.tv_sec * current_parameters_set->hca_core_clock) + (diff_systime.tv_nsec * current_parameters_set->hca_core_clock / NSEC_PER_SEC);
	deviation_hw = estimated_hw_time -  diff_hw_time;

	ibchtc_logdbg("ibv device '%s' [%p] : fix_hw_clock_deviation parameters status : %ld.%09ld since last deviation fix, \nUPDATE_HW_TIMER_PERIOD_MS = %d, current_parameters_set = %p, "
			"estimated_hw_time = %ld, diff_hw_time = %ld, diff = %ld ,m_hca_core_clock = %ld", m_p_ibv_context->device->name, m_p_ibv_context->device, diff_systime.tv_sec, diff_systime.tv_nsec,
			UPDATE_HW_TIMER_PERIOD_MS, current_parameters_set, estimated_hw_time, diff_hw_time, deviation_hw, current_parameters_set->hca_core_clock);

	if (abs(deviation_hw) < IB_CTX_TC_DEVIATION_THRESHOLD) {
		return;
	}

	next_parameters_set->hca_core_clock = (diff_hw_time * NSEC_PER_SEC) / diff_systime_nano;
	next_parameters_set->sync_hw_clock = hw_clock;
	next_parameters_set->sync_systime = current_time;

	m_ctx_parmeters_id = next_id;
}

#else

void time_converter_ib_ctx::fix_hw_clock_deviation(){}
bool time_converter_ib_ctx::sync_clocks(struct timespec* ts, uint64_t* hw_clock){ NOT_IN_USE(ts); NOT_IN_USE(hw_clock); return false;}

#endif

inline void time_converter_ib_ctx::calculate_delta(struct timespec& hw_to_timespec, uint64_t hca_core_clock, uint64_t hw_time_diff) {
	hw_to_timespec.tv_sec = hw_time_diff / hca_core_clock;
	hw_time_diff -= hw_to_timespec.tv_sec * hca_core_clock;
	hw_to_timespec.tv_nsec = (hw_time_diff * NSEC_PER_SEC) / hca_core_clock;
}

void time_converter_ib_ctx::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) {

	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];
	if (current_parameters_set->hca_core_clock && hwtime) {

		struct timespec hw_to_timespec, sync_systime;
		uint64_t hca_core_clock, sync_hw_clock;

		// sync_hw_clock should be zero when m_conversion_mode is CONVERSION_MODE_RAW_OR_FAIL or CONVERSION_MODE_DISABLE
		hca_core_clock = current_parameters_set->hca_core_clock;
		sync_hw_clock = current_parameters_set->sync_hw_clock;
		sync_systime = current_parameters_set->sync_systime;

		// Handle case in which the reference point occurred after the packet has been arrived.
		if (hwtime > sync_hw_clock) {
			calculate_delta(hw_to_timespec, hca_core_clock, hwtime - sync_hw_clock);
			ts_add(&sync_systime, &hw_to_timespec, systime);
		} else {
			calculate_delta(hw_to_timespec, hca_core_clock, sync_hw_clock - hwtime);
			ts_sub(&sync_systime, &hw_to_timespec, systime);
		}
	}
}
