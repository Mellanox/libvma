/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <vma/util/sys_vars.h>
#include "vma/dev/ib_ctx_handler.h"
#include "vma/ib/base/verbs_extra.h"
#include "vma/dev/time_converter_ib_ctx.h"
#include "vma/dev/time_converter_ptp.h"
#include "util/valgrind.h"
#include "vma/event/event_handler_manager.h"

#define MODULE_NAME             "ibch"

#define ibch_logpanic           __log_panic
#define ibch_logerr             __log_err
#define ibch_logwarn            __log_warn
#define ibch_loginfo            __log_info
#define ibch_logdbg             __log_info_dbg
#define ibch_logfunc            __log_info_func
#define ibch_logfuncall         __log_info_funcall


ib_ctx_handler::ib_ctx_handler(struct ib_ctx_handler_desc *desc) :
	m_flow_tag_enabled(false)
	, m_on_device_memory(0)
	, m_removed(false)
	, m_lock_mr("spin_lock_mr")
	, m_p_ctx_time_converter(NULL)
{
	if (NULL == desc) {
		ibch_logpanic("Invalid ib_ctx_handler");
	}

	m_p_ibv_device = desc->device;

	if (m_p_ibv_device == NULL) {
		ibch_logpanic("m_p_ibv_device is invalid");
	}

	m_p_ibv_context = NULL;
	{
#if defined(DEFINED_ROCE_LAG)
		struct mlx5dv_context_attr dv_attr;

		memset(&dv_attr, 0, sizeof(dv_attr));
		dv_attr.flags |= MLX5DV_CONTEXT_FLAGS_DEVX;
		m_p_ibv_context = mlx5dv_open_device(m_p_ibv_device, &dv_attr);
#endif /* DEFINED_ROCE_LAG */
		if (m_p_ibv_context == NULL) {
			m_p_ibv_context = ibv_open_device(m_p_ibv_device);
		}
		if (m_p_ibv_context == NULL) {
			ibch_logpanic("m_p_ibv_context is invalid");
		}
		// Create pd for this device
		m_p_ibv_pd = ibv_alloc_pd(m_p_ibv_context);
		if (m_p_ibv_pd == NULL) {
			ibch_logpanic("ibv device %p pd allocation failure (ibv context %p) (errno=%d %m)",
				    m_p_ibv_device, m_p_ibv_context, errno);
		}
	}
	VALGRIND_MAKE_MEM_DEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));

	m_p_ibv_device_attr = new vma_ibv_device_attr_ex();
	if (m_p_ibv_device_attr == NULL) {
		ibch_logpanic("ibv device %p attr allocation failure (ibv context %p) (errno=%d %m)",
			    m_p_ibv_device, m_p_ibv_context, errno);
	}
	vma_ibv_device_attr_comp_mask(m_p_ibv_device_attr);
	IF_VERBS_FAILURE(vma_ibv_query_device(m_p_ibv_context, m_p_ibv_device_attr)) {
		ibch_logerr("ibv_query_device failed on ibv device %p (ibv context %p) (errno=%d %m)",
			  m_p_ibv_device, m_p_ibv_context, errno);
		goto err;
	} ENDIF_VERBS_FAILURE;

	// update device memory capabilities
	m_on_device_memory = vma_ibv_dm_size(m_p_ibv_device_attr);

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
	if (vma_is_pacing_caps_supported(m_p_ibv_device_attr)) {
		m_pacing_caps.rate_limit_min = m_p_ibv_device_attr->packet_pacing_caps.qp_rate_limit_min;
		m_pacing_caps.rate_limit_max = m_p_ibv_device_attr->packet_pacing_caps.qp_rate_limit_max;
	}
#endif // DEFINED_IBV_PACKET_PACING_CAPS

	g_p_event_handler_manager->register_ibverbs_event(m_p_ibv_context->async_fd,
						this, m_p_ibv_context, 0);

	return;

err:
	if (m_p_ibv_device_attr) {
		delete m_p_ibv_device_attr;
	}

	if (m_p_ibv_pd) {
		ibv_dealloc_pd(m_p_ibv_pd);
	}

	if (m_p_ibv_context) {
		ibv_close_device(m_p_ibv_context);
		m_p_ibv_context = NULL;
	}
}

ib_ctx_handler::~ib_ctx_handler()
{
	if (!m_removed) {
		g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
	}

	// must delete ib_ctx_handler only after freeing all resources that
	// are still associated with the PD m_p_ibv_pd
	BULLSEYE_EXCLUDE_BLOCK_START

	mr_map_lkey_t::iterator iter;
	while ((iter = m_mr_map_lkey.begin()) != m_mr_map_lkey.end()) {
		mem_dereg(iter->first);
	}
	if (m_p_ibv_pd) {
		IF_VERBS_FAILURE_EX(ibv_dealloc_pd(m_p_ibv_pd), EIO) {
			ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_ibv_pd, sizeof(struct ibv_pd));
		m_p_ibv_pd = NULL;
	}

	if (m_p_ctx_time_converter) {
		m_p_ctx_time_converter->clean_obj();
	}
	delete m_p_ibv_device_attr;

	if (m_p_ibv_context) {
		ibv_close_device(m_p_ibv_context);
		m_p_ibv_context = NULL;
	}

	BULLSEYE_EXCLUDE_BLOCK_END
}

void ib_ctx_handler::set_str()
{
	char str_x[512] = {0};

	m_str[0] = '\0';

	str_x[0] = '\0';
	sprintf(str_x, " %s:", get_ibname());
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " port(s): %d", get_ibv_device_attr()->phys_port_cnt);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " vendor: %d", get_ibv_device_attr()->vendor_part_id);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " fw: %s", get_ibv_device_attr()->fw_ver);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " max_qp_wr: %d", get_ibv_device_attr()->max_qp_wr);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " on_device_memory: %zu", m_on_device_memory);
	strcat(m_str, str_x);

	str_x[0] = '\0';
	sprintf(str_x, " packet_pacing_caps: min rate %u, max rate %u", m_pacing_caps.rate_limit_min, m_pacing_caps.rate_limit_max);
	strcat(m_str, str_x);
}

void ib_ctx_handler::print_val()
{
	set_str();
	ibch_logdbg("%s", m_str);
}

void ib_ctx_handler::set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode)
{
	if (m_p_ctx_time_converter != NULL) {
		/*
		 * Don't override time_converter object. Current method may be
		 * called more than once if multiple slaves point to the same
		 * ib_context.
		 * If we overrode the time_converter we would lose the object
		 * and wouldn't be able to stop its timer and destroy it.
		 */
		return;
	}

#ifdef DEFINED_IBV_CQ_TIMESTAMP
	switch (conversion_mode) {
	case TS_CONVERSION_MODE_DISABLE:
		m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_DISABLE, 0);
	break;
	case TS_CONVERSION_MODE_PTP: {
#ifdef DEFINED_IBV_CLOCK_INFO
		if (is_mlx4()) {
			m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_SYNC, m_p_ibv_device_attr->hca_core_clock);
			ibch_logwarn("ptp is not supported for mlx4 devices, reverting to mode TS_CONVERSION_MODE_SYNC (ibv context %p)",
					m_p_ibv_context);
		} else {
			vma_ibv_clock_info clock_info;
			memset(&clock_info, 0, sizeof(clock_info));
			int ret = vma_ibv_query_clock_info(m_p_ibv_context, &clock_info);
			if (ret == 0) {
				m_p_ctx_time_converter = new time_converter_ptp(m_p_ibv_context);
			} else {
				m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_SYNC, m_p_ibv_device_attr->hca_core_clock);
				ibch_logwarn("vma_ibv_query_clock_info failure for clock_info, reverting to mode TS_CONVERSION_MODE_SYNC (ibv context %p) (ret %d)",
						m_p_ibv_context, ret);
			}
		}
# else
		m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_SYNC, m_p_ibv_device_attr->hca_core_clock);
		ibch_logwarn("PTP is not supported by the underlying Infiniband verbs. DEFINED_IBV_CLOCK_INFO not defined. "
				"reverting to mode TS_CONVERSION_MODE_SYNC");
# endif // DEFINED_IBV_CLOCK_INFO
	}
	break;
	default:
		m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context,
				conversion_mode,
				m_p_ibv_device_attr->hca_core_clock);
		break;
	}
#else
	m_p_ctx_time_converter = new time_converter_ib_ctx(m_p_ibv_context, TS_CONVERSION_MODE_DISABLE, 0);
	if (conversion_mode != TS_CONVERSION_MODE_DISABLE) {
		ibch_logwarn("time converter mode not applicable (configuration "
				"value=%d). set to TS_CONVERSION_MODE_DISABLE.",
				conversion_mode);
	}
#endif // DEFINED_IBV_CQ_TIMESTAMP
}

ts_conversion_mode_t ib_ctx_handler::get_ctx_time_converter_status()
{
	return m_p_ctx_time_converter ? m_p_ctx_time_converter->get_converter_status(): TS_CONVERSION_MODE_DISABLE;
}

uint32_t ib_ctx_handler::mem_reg(void *addr, size_t length, uint64_t access)
{
	struct ibv_mr *mr = NULL;
	uint32_t lkey = (uint32_t)(-1);

#ifdef DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR
	struct ibv_exp_reg_mr_in in;
	memset(&in, 0 ,sizeof(in));
	in.exp_access = access;
	in.addr = addr;
	in.length = length;
	in.pd = m_p_ibv_pd;
	mr = ibv_exp_reg_mr(&in);
#else
	mr = ibv_reg_mr(m_p_ibv_pd, addr, length, access);
#endif
	VALGRIND_MAKE_MEM_DEFINED(mr, sizeof(ibv_mr));
	if (NULL == mr) {
		ibch_logerr("failed registering a memory region "
				"(errno=%d %m)", errno);
	} else {
		m_mr_map_lkey[mr->lkey] = mr;
		lkey = mr->lkey;

		ibch_logdbg("dev:%s (%p) addr=%p length=%lu pd=%p",
				get_ibname(), m_p_ibv_device, addr, length, m_p_ibv_pd);
	}

	return lkey;
}

void ib_ctx_handler::mem_dereg(uint32_t lkey)
{
	mr_map_lkey_t::iterator iter = m_mr_map_lkey.find(lkey);
	if (iter != m_mr_map_lkey.end()) {
		struct ibv_mr* mr = iter->second;
		ibch_logdbg("dev:%s (%p) addr=%p length=%lu pd=%p",
				get_ibname(), m_p_ibv_device, mr->addr, mr->length, m_p_ibv_pd);
		IF_VERBS_FAILURE_EX(ibv_dereg_mr(mr), EIO) {
			ibch_logdbg("failed de-registering a memory region "
					"(errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(mr, sizeof(ibv_mr));
		m_mr_map_lkey.erase(iter);
	}
}

struct ibv_mr* ib_ctx_handler::get_mem_reg(uint32_t lkey)
{
	mr_map_lkey_t::iterator iter = m_mr_map_lkey.find(lkey);
	if (iter != m_mr_map_lkey.end()) {
		return iter->second;
	}

	return NULL;
}

void ib_ctx_handler::set_flow_tag_capability(bool flow_tag_capability)
{
	m_flow_tag_enabled = flow_tag_capability;
}

void ib_ctx_handler::set_burst_capability(bool burst)
{
	m_pacing_caps.burst = burst;
}

bool ib_ctx_handler::is_packet_pacing_supported(uint32_t rate /* =1 */)
{
	if (rate) {
		return m_pacing_caps.rate_limit_min <= rate && rate <= m_pacing_caps.rate_limit_max;
	} else {
		return true;
	}
}

bool ib_ctx_handler::is_active(int port_num)
{
	ibv_port_attr port_attr;

	memset(&port_attr, 0, sizeof(ibv_port_attr));
	IF_VERBS_FAILURE(ibv_query_port(m_p_ibv_context, port_num, &port_attr)) {
		ibch_logdbg("ibv_query_port failed on ibv device %p, port %d "
			    "(errno=%d)", m_p_ibv_context, port_num, errno);
	}ENDIF_VERBS_FAILURE;
	VALGRIND_MAKE_MEM_DEFINED(&port_attr.state, sizeof(port_attr.state));
	return port_attr.state == IBV_PORT_ACTIVE;
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

	ibch_logdbg("IBV_EVENT_DEVICE_FATAL for ib_ctx_handler=%p", this);

	/* After getting IBV_EVENT_DEVICE_FATAL event rdma library returns
	 * an EIO from destroy commands when the kernel resources were already released.
	 * This comes to prevent memory leakage in the
	 * user space area upon device disassociation. Applications cannot
	 * call ibv_get_cq_event or ibv_get_async_event concurrently with any call to an
	 * object destruction function.
	 */
	g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
	if (m_p_ctx_time_converter) {
		m_p_ctx_time_converter->clean_obj();
		m_p_ctx_time_converter = NULL;
	}
}
