/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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
#include "vma/util/verbs_extra.h"
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "utils/rdtsc.h"
#include "vma/util/instrumentation.h"

#define MODULE_NAME             "time_converter"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_dbg


#define IB_CTX_TC_DEVIATION_THRESHOLD 10

#define IBV_EXP_QUERY_DEVICE_SUPPORTED (1 << 0)
#define IBV_EXP_QUERY_VALUES_SUPPORTED (1 << 1)


uint32_t time_converter::get_single_converter_status(struct ibv_context* ctx) {
	uint32_t dev_status = 0;
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP
	int rval;

	// Checking if ibv_exp_query_device() is valid
	struct ibv_exp_device_attr device_attr;
	memset(&device_attr, 0, sizeof(device_attr));
	device_attr.comp_mask = IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

	if ((rval = ibv_exp_query_device(ctx ,&device_attr)) || !device_attr.hca_core_clock) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hca core clock "
				"(ibv_exp_query_device() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= IBV_EXP_QUERY_DEVICE_SUPPORTED;
	}

	// Checking if ibv_exp_query_values() is valid
	struct ibv_exp_values queried_values;
	memset(&queried_values, 0, sizeof(queried_values));
	if ((rval = ibv_exp_query_values(ctx,IBV_EXP_VALUES_HW_CLOCK, &queried_values)) || !queried_values.hwclock) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hw clock, can't convert"
				" hw time to system time (ibv_exp_query_values() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= IBV_EXP_QUERY_VALUES_SUPPORTED;
	}
#else
	NOT_IN_USE(ctx);
#endif
	return dev_status;
}

ts_conversion_mode_t time_converter::get_devices_converter_status(struct ibv_context** ibv_context_list, int num_devices) {

	ts_conversion_mode_t ctx_time_conversion_mode;
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP
	uint32_t devs_status = 0;

        ibchtc_logdbg("time_converter::get_devices_converter_status : Checking RX UDP HW time stamp "
                        "status for all devices [%d], ibv_context_list = %p\n", num_devices, ibv_context_list);

	if (safe_mce_sys().hw_ts_conversion_mode != TS_CONVERSION_MODE_DISABLE){
		devs_status = IBV_EXP_QUERY_DEVICE_SUPPORTED | IBV_EXP_QUERY_VALUES_SUPPORTED;
		for (int i = 0; i < num_devices; i++) {
			devs_status &= get_single_converter_status(ibv_context_list[i]);
		}
	}

	switch (safe_mce_sys().hw_ts_conversion_mode) {
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
	case TS_CONVERSION_MODE_PTP:
		ctx_time_conversion_mode = devs_status == (IBV_EXP_QUERY_DEVICE_SUPPORTED |
				IBV_EXP_QUERY_VALUES_SUPPORTED) ?
						TS_CONVERSION_MODE_PTP : TS_CONVERSION_MODE_DISABLE;
		break;
	default:
		ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
		break;
	}
#else
	NOT_IN_USE(ibv_context_list);
	NOT_IN_USE(num_devices);
	ctx_time_conversion_mode = TS_CONVERSION_MODE_DISABLE;
#endif

	return ctx_time_conversion_mode;
}

