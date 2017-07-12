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


#include <infiniband/verbs.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include <vma/util/verbs_extra.h>
#include <vma/util/sys_vars.h>
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/time_converter_ib_ctx.h"
#include "vma/dev/time_converter_ptp.h"
#include "vma/util/verbs_extra.h"
#include "util/valgrind.h"
#include "vma/event/event_handler_manager.h"

#define MODULE_NAME             "ib_ctx_handler"

#define ibch_logpanic           __log_panic
#define ibch_logerr             __log_err
#define ibch_logwarn            __log_warn
#define ibch_loginfo            __log_info
#define ibch_logdbg             __log_info_dbg
#define ibch_logfunc            __log_info_func
#define ibch_logfuncall         __log_info_funcall


ib_ctx_handler::ib_ctx_handler(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode) :
	m_flow_tag_enabled(false)
	, m_on_device_memory(0)
	, m_removed(false)
	, m_p_ctx_time_converter(NULL)
{
	m_p_ibv_context = ctx;
	VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_context, sizeof(ibv_context));
	m_p_ibv_device = ctx->device;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_ibv_device == NULL) {
		ibch_logpanic("ibv_device is NULL! (ibv context %p)", m_p_ibv_context);
	}

	// Create pd for this device
	m_p_ibv_pd = ibv_alloc_pd(m_p_ibv_context);
	if (m_p_ibv_pd == NULL) {
		ibch_logpanic("ibv device %p pd allocation failure (ibv context %p) (errno=%d %m)",
			    m_p_ibv_device, m_p_ibv_context, errno);
	}
	m_p_ibv_device_attr = new vma_ibv_device_attr();
	vma_ibv_device_attr_comp_mask(m_p_ibv_device_attr);
	IF_VERBS_FAILURE(vma_ibv_query_device(m_p_ibv_context, m_p_ibv_device_attr)) {
		ibch_logerr("ibv_query_device failed on ibv device %p (ibv context %p) (errno=%d %m)",
			  m_p_ibv_device, m_p_ibv_context, errno);
		return;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END
#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP
	switch (ctx_time_converter_mode) {
	case TS_CONVERSION_MODE_DISABLE:
		m_p_ctx_time_converter = new time_converter_ib_ctx(ctx, TS_CONVERSION_MODE_DISABLE, 0);
	break;
	case TS_CONVERSION_MODE_PTP: {
# ifdef DEFINED_IBV_EXP_VALUES_CLOCK_INFO
		struct ibv_exp_values ibv_exp_values_tmp;
		memset(&ibv_exp_values_tmp, 0, sizeof(ibv_exp_values_tmp));
		int ret = ibv_exp_query_values(m_p_ibv_context,
					       IBV_EXP_VALUES_CLOCK_INFO,
					       &ibv_exp_values_tmp);
		if (!ret) {
			m_p_ctx_time_converter = new time_converter_ptp(ctx);
		} else { // revert to mode TS_CONVERSION_MODE_SYNC
			m_p_ctx_time_converter = new time_converter_ib_ctx(ctx,
							TS_CONVERSION_MODE_SYNC,
							m_p_ibv_device_attr->hca_core_clock);
			ibch_logwarn("ibv_exp_query_values failure for clock_info, "
					"reverting to mode TS_CONVERSION_MODE_SYNC "
					"(ibv context %p) (return value=%d)",
					m_p_ibv_context, ret);
		}
# else
		m_p_ctx_time_converter = new time_converter_ib_ctx(ctx,
				TS_CONVERSION_MODE_SYNC,
				m_p_ibv_device_attr->hca_core_clock);
		ibch_logwarn("PTP is not supported by the underlying Infiniband "
				"verbs. IBV_EXP_VALUES_CLOCK_INFO not defined. "
				"reverting to mode TS_CONVERSION_MODE_SYNC");
# endif // DEFINED_IBV_EXP_VALUES_CLOCK_INFO
	}
	break;
	default:
		m_p_ctx_time_converter = new time_converter_ib_ctx(ctx,
				ctx_time_converter_mode,
				m_p_ibv_device_attr->hca_core_clock);
		break;
	}
#else
	m_p_ctx_time_converter = new time_converter_ib_ctx(ctx, TS_CONVERSION_MODE_DISABLE, 0);
	if (ctx_time_converter_mode != TS_CONVERSION_MODE_DISABLE) {
		ibch_logwarn("time converter mode not applicable (configuration "
				"value=%d). set to TS_CONVERSION_MODE_DISABLE.",
				ctx_time_converter_mode);
	}
#endif // DEFINED_IBV_EXP_CQ_TIMESTAMP

	// Query device for on device memory capabilities
	update_on_device_memory_size();

	ibch_logdbg("ibv device '%s' [%p] has %d port%s. Vendor Part Id: %d, "
		    "FW Ver: %s, max_qp_wr=%d", m_p_ibv_device->name,
		    m_p_ibv_device, m_p_ibv_device_attr->phys_port_cnt,
		    ((m_p_ibv_device_attr->phys_port_cnt>1)?"s":""),
		    m_p_ibv_device_attr->vendor_part_id,
		    m_p_ibv_device_attr->fw_ver, m_p_ibv_device_attr->max_qp_wr);

	g_p_event_handler_manager->register_ibverbs_event(m_p_ibv_context->async_fd,
						this, m_p_ibv_context, 0);
}

ib_ctx_handler::~ib_ctx_handler() {
	g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
	// must delete ib_ctx_handler only after freeing all resources that
	// are still associated with the PD m_p_ibv_pd
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ibv_dealloc_pd(m_p_ibv_pd))
		ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
	delete m_p_ctx_time_converter;
	delete m_p_ibv_device_attr;
	BULLSEYE_EXCLUDE_BLOCK_END
}

void ib_ctx_handler::update_on_device_memory_size()
{
#if defined(HAVE_IBV_DM)
	struct ibv_exp_device_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.comp_mask = IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE;
	if (ibv_exp_query_device(m_p_ibv_context, &attr)) {
		ibch_logerr("Couldn't query device for its features");
		return;
	}

	m_on_device_memory = attr.max_dm_size;

#endif

	ibch_logdbg("ibv device '%s' [%p] supports %zu bytes of on device memory", m_p_ibv_device->name, m_p_ibv_device, m_on_device_memory);
}

ts_conversion_mode_t ib_ctx_handler::get_ctx_time_converter_status()
{
	return m_p_ctx_time_converter->get_converter_status();
}

ibv_mr* ib_ctx_handler::mem_reg(void *addr, size_t length, uint64_t access)
{
	// Register the memory block with the HCA on this ibv_device
	ibch_logfunc("(dev=%p) addr=%p, length=%d, m_p_ibv_pd=%p on dev=%p",
			m_p_ibv_device, addr, length, m_p_ibv_pd,
			m_p_ibv_pd->context->device);
#ifdef DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR
	struct ibv_exp_reg_mr_in in;
	memset(&in, 0 ,sizeof(in));
	in.exp_access = access;
	in.addr = addr;
	in.length = length;
	in.pd = m_p_ibv_pd;
	ibv_mr *mr = ibv_exp_reg_mr(&in);
#else
	ibv_mr *mr = ibv_reg_mr(m_p_ibv_pd, addr, length, access);
#endif
	VALGRIND_MAKE_MEM_DEFINED(mr, sizeof(ibv_mr));
	return mr;
}

void ib_ctx_handler::mem_dereg(ibv_mr *mr)
{
	if (is_removed()) {
		return;
	}
	IF_VERBS_FAILURE(ibv_dereg_mr(mr)) {
		ibch_logerr("failed de-registering a memory region "
				"(errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	VALGRIND_MAKE_MEM_UNDEFINED(mr, sizeof(ibv_mr));
}

void ib_ctx_handler::set_flow_tag_capability(bool flow_tag_capability)
{
	m_flow_tag_enabled = flow_tag_capability;
}

ibv_port_state ib_ctx_handler::get_port_state(int port_num)
{
	ibv_port_attr port_attr;

	memset(&port_attr, 0, sizeof(ibv_port_attr));
	IF_VERBS_FAILURE(ibv_query_port(m_p_ibv_context, port_num, &port_attr)) {
		ibch_logdbg("ibv_query_port failed on ibv device %p, port %d "
			    "(errno=%d)", m_p_ibv_context, port_num, errno);
	}ENDIF_VERBS_FAILURE;
	return port_attr.state;
}

void ib_ctx_handler::handle_event_ibverbs_cb(void *ev_data, void *ctx)
{
 	NOT_IN_USE(ctx);

	struct ibv_async_event *ibv_event = (struct ibv_async_event*)ev_data;
	ibch_logdbg("received ibv_event '%s' (%d)",
		    priv_ibv_event_desc_str(ibv_event->event_type),
		    ibv_event->event_type);
		
	if (ibv_event->event_type == IBV_EVENT_DEVICE_FATAL) {
		handle_event_device_fatal();
	}
}

void ib_ctx_handler::handle_event_device_fatal()
{
	m_removed = true;
	g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
}
