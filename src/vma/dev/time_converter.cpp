/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "time_converter.h"

#include <stdlib.h>
#include "vlogger/vlogger.h"
#include "utils/rdtsc.h"

#include "vma/util/sys_vars.h"
#include "vma/util/instrumentation.h"
#include "vma/event/event_handler_manager.h"
#include "vma/ib/base/verbs_extra.h"
#include "vma/dev/net_device_table_mgr.h"

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
	device_attr.comp_mask = 0;

	if ((rval = vma_ibv_query_device(ctx ,&device_attr)) || !device_attr.hca_core_clock) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hca core clock "
				"(vma_ibv_query_device() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= VMA_QUERY_DEVICE_SUPPORTED;
	}

	// Checking if ibv_exp_query_values() is valid
	ibv_values_ex queried_values;
	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = IBV_VALUES_MASK_RAW_CLOCK;
	if ((rval = ibv_query_rt_values_ex(ctx, &queried_values)) || !vma_get_ts_val(queried_values)) {
		ibchtc_logdbg("time_converter::get_single_converter_status :Error in querying hw clock, can't convert"
				" hw time to system time (ibv_query_rt_values_ex() return value=%d ) (ibv context %p) (errno=%d %m)\n", rval, ctx, errno);
	} else {
		dev_status |= VMA_QUERY_VALUES_SUPPORTED;
	}
#else
	NOT_IN_USE(ctx);
#endif

	return dev_status;
}

ts_conversion_mode_t time_converter::update_device_converters_status(net_device_map_t& net_devices)
{
	ibchtc_logdbg("Checking RX HW time stamp status for all devices [%lu]", net_devices.size());
	ts_conversion_mode_t ts_conversion_mode = TS_CONVERSION_MODE_DISABLE;

	if (net_devices.empty()) {
		ibchtc_logdbg("No supported devices was found, return");
		return ts_conversion_mode;
	}


#ifdef DEFINED_IBV_CQ_TIMESTAMP

	if (safe_mce_sys().hw_ts_conversion_mode != TS_CONVERSION_MODE_DISABLE) {
		uint32_t devs_status = VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED;

		/* Get common time conversion mode for all devices */
		for (net_device_map_index_t::iterator dev_iter = net_devices.begin(); dev_iter != net_devices.end(); dev_iter++) {
			if (dev_iter->second->get_state() == net_device_val::RUNNING) {
				slave_data_vector_t slaves = dev_iter->second->get_slave_array();
				for (slave_data_vector_t::iterator slaves_iter = slaves.begin(); slaves_iter != slaves.end(); slaves_iter++) {
					devs_status &= get_single_converter_status((*slaves_iter)->p_ib_ctx->get_ibv_context());
				}
			}
		}

		switch (safe_mce_sys().hw_ts_conversion_mode) {
		case TS_CONVERSION_MODE_RAW:
			ts_conversion_mode = devs_status & VMA_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
			break;
		case TS_CONVERSION_MODE_BEST_POSSIBLE:
			if (devs_status == (VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED)) {
				ts_conversion_mode = TS_CONVERSION_MODE_SYNC;
			} else {
				ts_conversion_mode = devs_status & VMA_QUERY_DEVICE_SUPPORTED ? TS_CONVERSION_MODE_RAW : TS_CONVERSION_MODE_DISABLE;
			}
			break;
		case TS_CONVERSION_MODE_SYNC:
			ts_conversion_mode = devs_status == (VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED) ? TS_CONVERSION_MODE_SYNC : TS_CONVERSION_MODE_DISABLE;
			break;
		case TS_CONVERSION_MODE_PTP:
			ts_conversion_mode = devs_status == (VMA_QUERY_DEVICE_SUPPORTED | VMA_QUERY_VALUES_SUPPORTED) ? TS_CONVERSION_MODE_PTP : TS_CONVERSION_MODE_DISABLE;
			break;
		default:
			ts_conversion_mode = TS_CONVERSION_MODE_DISABLE;
			break;
		}
	}

#endif

	ibchtc_logdbg("Conversion status was set to %d", ts_conversion_mode);

	for (net_device_map_index_t::iterator dev_iter = net_devices.begin(); dev_iter != net_devices.end(); dev_iter++) {
		slave_data_vector_t slaves = dev_iter->second->get_slave_array();
		for (slave_data_vector_t::iterator slaves_iter = slaves.begin(); slaves_iter != slaves.end(); slaves_iter++) {
			ts_conversion_mode_t dev_ts_conversion_mode = dev_iter->second->get_state() == net_device_val::RUNNING ? ts_conversion_mode : TS_CONVERSION_MODE_DISABLE;
			(*slaves_iter)->p_ib_ctx->set_ctx_time_converter_status(dev_ts_conversion_mode);
		}
	}

	return ts_conversion_mode;
}

void time_converter::clean_obj()
{
	if (is_cleaned()) {
		return ;
	}

	set_cleaned();
	m_timer_handle = NULL;
	if (g_p_event_handler_manager->is_running()) {
		g_p_event_handler_manager->unregister_timers_event_and_delete(this);
	} else {
		cleanable_obj::clean_obj();
	}
}
