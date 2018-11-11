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


#include "time_converter.h"

#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "vma/ib/base/verbs_extra.h"
#include "utils/rdtsc.h"
#include "vma/util/instrumentation.h"

#define MODULE_NAME             "time_converter"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_dbg


#define IB_CTX_TC_DEVIATION_THRESHOLD 10

#define VMA_QUERY_DEVICE_SUPPORTED (1 << 0)
#define VMA_QUERY_VALUES_SUPPORTED (1 << 1)

uint32_t time_converter::get_single_converter_status(struct ibv_context* ctx) {
	uint32_t dev_status = 0;
#ifdef DEFINED_IBV_CQ_TIMESTAMP
	int rval;

	// Checking if ibv_exp_query_device() is valid
	vma_ibv_device_attr_ex device_attr;
	memset(&device_attr, 0, sizeof(device_attr));
	device_attr.comp_mask = VMA_IBV_DEVICE_ATTR_HCA_CORE_CLOCK;

	if ((rval = vma_ibv_query_device(ctx ,&device_attr)) || !device_attr.hca_core_clock) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hca core clock "
				"(ibv_exp_query_device() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= VMA_QUERY_DEVICE_SUPPORTED;
	}

	// Checking if ibv_exp_query_values() is valid
	vma_ts_values queried_values;
	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = VMA_IBV_VALUES_MASK_RAW_CLOCK;
	if ((rval = vma_ibv_query_values(ctx, &queried_values)) || !vma_get_ts_val(queried_values)) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hw clock, can't convert"
				" hw time to system time (ibv_exp_query_values() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= VMA_QUERY_VALUES_SUPPORTED;
	}
#else
	NOT_IN_USE(ctx);
#endif
	return dev_status;
}

ts_conversion_mode_t time_converter::get_devices_converter_status(struct ibv_device** ibv_dev_list, int num_devices) {

	ts_conversion_mode_t ctx_time_conversion_mode;
#ifdef DEFINED_IBV_CQ_TIMESTAMP
	uint32_t devs_status = 0;

        ibchtc_logdbg("time_converter::get_devices_converter_status : Checking RX UDP HW time stamp "
                        "status for all devices [%d], ibv_dev_list = %p\n", num_devices, ibv_dev_list);

	if (safe_mce_sys().hw_ts_conversion_mode != TS_CONVERSION_MODE_DISABLE){
		devs_status = VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED;
		for (int i = 0; i < num_devices; i++) {
			struct ibv_context *ibv_ctx = ibv_open_device(ibv_dev_list[i]);
			if (ibv_ctx == NULL) {
				ibchtc_logdbg("ibv_ctx is invalid");
				continue;
			}
			devs_status &= get_single_converter_status(ibv_ctx);
			ibv_close_device(ibv_ctx);
		}
	}

	switch (safe_mce_sys().hw_ts_conversion_mode) {
	case TS_CONVERSION_MODE_RAW:
		ctx_time_conversion_mode = devs_status & VMA_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
		break;
	case TS_CONVERSION_MODE_BEST_POSSIBLE:
		if (devs_status == (VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED)) {
			ctx_time_conversion_mode = TS_CONVERSION_MODE_SYNC;
		} else {
			ctx_time_conversion_mode = devs_status & VMA_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
		}
		break;
	case TS_CONVERSION_MODE_SYNC:
		ctx_time_conversion_mode = devs_status == (VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED) ? TS_CONVERSION_MODE_SYNC : TS_CONVERSION_MODE_DISABLE;
		break;
	case TS_CONVERSION_MODE_PTP:
		ctx_time_conversion_mode = devs_status == (VMA_QUERY_DEVICE_SUPPORTED |
				VMA_QUERY_VALUES_SUPPORTED) ?
						TS_CONVERSION_MODE_PTP : TS_CONVERSION_MODE_DISABLE;
		break;
	default:
		ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
		break;
	}
#else
	NOT_IN_USE(ibv_dev_list);
	NOT_IN_USE(num_devices);
	ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
#endif

	return ctx_time_conversion_mode;
}

void time_converter::clean_obj()
{
	set_cleaned();

	if (m_timer_handle && g_p_event_handler_manager->is_running()) {
		g_p_event_handler_manager->unregister_timers_event_and_delete(this);
		m_timer_handle = NULL;
	} else {
		cleanable_obj::clean_obj();
	}
}
