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


#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "vma/util/verbs_extra.h"
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "vma/dev/ib_ctx_time_converter.h"

#define MODULE_NAME             "ib_ctx_time_converter"

#define ibchtc_logerr             __log_err
#define ibchtc_logwarn            __log_warn
#define ibchtc_loginfo            __log_info
#define ibchtc_logdbg             __log_info_dbg

#define UPDATE_HW_TIMER_PERIOD_MS 10000
#define UPDATE_HW_TIMER_INIT_MS 1000

#define IB_CTX_TC_DEVIATION_THRESHOLD 10

#define	IBV_EXP_QUERY_DEVICE_SUPPORTED (1 << 0)
#define	IBV_EXP_QUERY_VALUES_SUPPORTED (1 << 1)

ib_ctx_time_converter::ib_ctx_time_converter(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode) :
	m_p_ibv_context(ctx), m_ctx_parmeters_id(0), m_timer_handle(NULL), m_converter_status(TS_CONVERSION_MODE_DISABLE)
{
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP

	if (ctx_time_converter_mode != TS_CONVERSION_MODE_DISABLE) {

		ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];
		struct ibv_exp_device_attr device_attr;
		memset(&device_attr, 0, sizeof(device_attr));
		device_attr.comp_mask = IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

		if (!ibv_exp_query_device(m_p_ibv_context ,&device_attr) && device_attr.hca_core_clock) {
			m_converter_status = TS_CONVERSION_MODE_RAW;
			current_parameters_set->hca_core_clock = device_attr.hca_core_clock * USEC_PER_SEC;

			if (ctx_time_converter_mode != TS_CONVERSION_MODE_RAW) {
				if (sync_clocks(&current_parameters_set->sync_systime, &current_parameters_set->sync_hw_clock)) {
					m_converter_status = TS_CONVERSION_MODE_SYNC;

					g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_INIT_MS, this, ONE_SHOT_TIMER, 0);
					m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PERIOD_MS, this, PERIODIC_TIMER, 0);
				}
			}
		}
	}

#endif

	if (ctx_time_converter_mode != m_converter_status) {
		ibchtc_logwarn("converter status different then expected (ibv context %p, value = %d , expected = %d)"
					, m_p_ibv_context, m_converter_status, ctx_time_converter_mode);
	}
}

ib_ctx_time_converter::~ib_ctx_time_converter() {
	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}

void ib_ctx_time_converter::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);
	fix_hw_clock_deviation();
}

uint64_t ib_ctx_time_converter::get_hca_core_clock(){
	return m_ctx_convert_parmeters[m_ctx_parmeters_id].hca_core_clock;
}

ts_conversion_mode_t ib_ctx_time_converter::get_converter_status(){
	return m_converter_status;
}

#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP

bool ib_ctx_time_converter::sync_clocks(struct timespec* st, uint64_t* hw_clock){
	struct timespec st1, st2, diff, st_min = TIMESPEC_INITIALIZER;
	struct ibv_exp_values queried_values;
	int64_t interval, best_interval = 0;
	uint64_t hw_clock_min = 0;

	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = IBV_EXP_VALUES_HW_CLOCK;
	for (int i = 0 ; i < 10 ; i++) {
		clock_gettime(CLOCK_REALTIME, &st1);
		if (ibv_exp_query_values(m_p_ibv_context,IBV_EXP_VALUES_HW_CLOCK, &queried_values) || !queried_values.hwclock) {
			return false;
		}

		clock_gettime(CLOCK_REALTIME, &st2);
		interval = (st2.tv_sec - st1.tv_sec) * NSEC_PER_SEC + (st2.tv_nsec - st1.tv_nsec);

		if (!best_interval || interval < best_interval) {
			best_interval = interval;
			hw_clock_min = queried_values.hwclock;

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

void ib_ctx_time_converter::fix_hw_clock_deviation(){
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

void ib_ctx_time_converter::fix_hw_clock_deviation(){}
bool ib_ctx_time_converter::sync_clocks(struct timespec* ts, uint64_t* hw_clock){ NOT_IN_USE(ts); NOT_IN_USE(hw_clock); return false;}

#endif

void ib_ctx_time_converter::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) {

	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];
	if (current_parameters_set->hca_core_clock && hwtime) {

		struct timespec hw_to_timespec, sync_systime;
		uint64_t hw_time_diff, hca_core_clock, sync_hw_clock;

		hca_core_clock = current_parameters_set->hca_core_clock;
		sync_hw_clock = current_parameters_set->sync_hw_clock;
		sync_systime = current_parameters_set->sync_systime;

		hw_time_diff = hwtime - sync_hw_clock; // sync_hw_clock should be zero when m_conversion_mode is CONVERSION_MODE_RAW_OR_FAIL or CONVERSION_MODE_DISABLE

		hw_to_timespec.tv_sec = hw_time_diff / hca_core_clock;
		hw_time_diff -= hw_to_timespec.tv_sec * hca_core_clock;
		hw_to_timespec.tv_nsec = (hw_time_diff * NSEC_PER_SEC) / hca_core_clock;

		ts_add(&sync_systime, &hw_to_timespec, systime);
	}
}

uint32_t ib_ctx_time_converter::get_device_convertor_status(struct ibv_context* ctx) {
	uint32_t dev_status = 0;
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP
	int rval;

	// Checking if ibv_exp_query_device() is valid
	struct ibv_exp_device_attr device_attr;
	memset(&device_attr, 0, sizeof(device_attr));
	device_attr.comp_mask = IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

	if ((rval = ibv_exp_query_device(ctx ,&device_attr)) || !device_attr.hca_core_clock) {
		vlog_printf(VLOG_DEBUG, "ib_ctx_time_converter::get_device_convertor_status :Error in querying hca core clock "
				"(ibv_exp_query_device() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= IBV_EXP_QUERY_DEVICE_SUPPORTED;
	}

	// Checking if ibv_exp_query_values() is valid
	struct ibv_exp_values queried_values;
	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = IBV_EXP_VALUES_HW_CLOCK;

	if ((rval = ibv_exp_query_values(ctx,IBV_EXP_VALUES_HW_CLOCK, &queried_values)) || !queried_values.hwclock) {
		vlog_printf(VLOG_DEBUG, "ib_ctx_time_converter::get_device_convertor_status :Error in querying hw clock, can't convert"
				" hw time to system time (ibv_exp_query_values() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= IBV_EXP_QUERY_VALUES_SUPPORTED;
	}
#else
	NOT_IN_USE(ctx);
#endif
	return dev_status;
}

ts_conversion_mode_t ib_ctx_time_converter::get_devices_convertor_status(struct ibv_context** ibv_context_list, int num_devices) {

	ts_conversion_mode_t ctx_time_conversion_mode;
	vlog_printf(VLOG_DEBUG, "ib_ctx_time_converter::get_devices_convertor_status : Checking RX UDP HW time stamp "
			"status for all devices [%d], ibv_context_list = %p\n", num_devices, ibv_context_list);
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP
	uint32_t devs_status = 0;
	if (safe_mce_sys().rx_udp_hw_ts_conversion != TS_CONVERSION_MODE_DISABLE){
		devs_status = IBV_EXP_QUERY_DEVICE_SUPPORTED | IBV_EXP_QUERY_VALUES_SUPPORTED;
		for (int i = 0; i < num_devices; i++) {
			devs_status &= get_device_convertor_status(ibv_context_list[i]);
		}
	}

	switch (safe_mce_sys().rx_udp_hw_ts_conversion) {
	case TS_CONVERSION_MODE_RAW:
		ctx_time_conversion_mode = devs_status & IBV_EXP_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
		break;
	case TS_CONVERSION_MODE_BEST_POSSIBLE:
		if (devs_status == (IBV_EXP_QUERY_DEVICE_SUPPORTED | IBV_EXP_QUERY_VALUES_SUPPORTED)) {
			ctx_time_conversion_mode = TS_CONVERSION_MODE_SYNC;
		} else {
			ctx_time_conversion_mode = devs_status & IBV_EXP_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
		}
		break;
	case TS_CONVERSION_MODE_SYNC:
		ctx_time_conversion_mode = devs_status == (IBV_EXP_QUERY_DEVICE_SUPPORTED | IBV_EXP_QUERY_VALUES_SUPPORTED) ? TS_CONVERSION_MODE_SYNC : TS_CONVERSION_MODE_DISABLE;
		break;
	default:
		ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
		break;
	}
#else
	ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
#endif

	return ctx_time_conversion_mode;
}

