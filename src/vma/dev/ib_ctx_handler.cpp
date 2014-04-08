/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include <infiniband/verbs.h>

#include <vlogger/vlogger.h>
#include <vma/util/verbs_extra.h>
#include <vma/util/sys_vars.h>
#include <string.h>
#include "vma/dev/ib_ctx_handler.h"
#include "vma/util/bullseye.h"
#include "vma/util/verbs_extra.h"

#define MODULE_NAME             "ib_ctx_handler"


#define ibch_logpanic           __log_panic
#define ibch_logerr             __log_err
#define ibch_logwarn            __log_warn
#define ibch_loginfo            __log_info
#define ibch_logdbg             __log_info_dbg
#define ibch_logfunc            __log_info_func
#define ibch_logfuncall         __log_info_funcall



ib_ctx_handler::ib_ctx_handler(struct ibv_context* ctx) :
	m_channel(0), m_conf_attr_rx_num_wre(0), m_conf_attr_tx_num_post_send_notify(0),
	m_conf_attr_tx_max_inline(0), m_conf_attr_tx_num_wre(0)
{
	memset(&m_ibv_port_attr, 0, sizeof(struct ibv_port_attr));
	m_p_ibv_context = ctx;
        m_p_ibv_device = ctx->device;

        BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_ibv_device == NULL)
		ibch_logpanic("ibv_device is NULL! (ibv context %p)", m_p_ibv_context);

	// Create pd for this device
	m_p_ibv_pd = ibv_alloc_pd(m_p_ibv_context);
	if (m_p_ibv_pd == NULL)
		ibch_logpanic("ibv device %p pd allocation failure (ibv context %p) (errno=%d %m)", 
			    m_p_ibv_device, m_p_ibv_context, errno);

	IF_VERBS_FAILURE(ibv_query_device(m_p_ibv_context, &m_ibv_device_attr)) {
		ibch_logerr("ibv_query_device failed on ibv device %p (ibv context %p) (errno=%d %m)", 
			  m_p_ibv_device, m_p_ibv_context, errno);
		return;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	ibch_logdbg("ibv device '%s' [%p] has %d port%s. Vendor Part Id: %d, FW Ver: %s",
			m_p_ibv_device->name, m_p_ibv_device,
			m_ibv_device_attr.phys_port_cnt, ((m_ibv_device_attr.phys_port_cnt>1)?"s":""),
			m_ibv_device_attr.vendor_part_id, m_ibv_device_attr.fw_ver);

	set_dev_configuration();
}

ib_ctx_handler::~ib_ctx_handler() {
	// must delete ib_ctx_handler only after freeing all resources that
	// are still associated with the PD m_p_ibv_pd
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ibv_dealloc_pd(m_p_ibv_pd))
		ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
	BULLSEYE_EXCLUDE_BLOCK_END
}

ibv_mr* ib_ctx_handler::mem_reg(void *addr, size_t length, uint64_t access)
{
	// Register the memory block with the HCA on this ibv_device
	ibch_logfunc("(dev=%p) addr=%p, length=%d, m_p_ibv_pd=%p on dev=%p", m_p_ibv_device, addr, length, m_p_ibv_pd, m_p_ibv_pd->context->device);
#ifdef DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR
	struct ibv_exp_reg_mr_in in;
	memset(&in, 0 ,sizeof(in));
	in.exp_access = access;
	in.addr = addr;
	in.length = length;
	in.pd = m_p_ibv_pd;
	return ibv_exp_reg_mr(&in);
#else
	return ibv_reg_mr(m_p_ibv_pd, addr, length, access);
#endif
}

bool ib_ctx_handler::update_port_attr(int port_num)
{
        IF_VERBS_FAILURE(ibv_query_port(m_p_ibv_context, port_num, &m_ibv_port_attr)) {
                ibch_logdbg("ibv_query_port failed on ibv device %p, port %d (errno=%d)", m_p_ibv_context, port_num, errno);
                return false;
        } ENDIF_VERBS_FAILURE;
        return true;
}

ibv_port_state ib_ctx_handler::get_port_state(int port_num)
{       
        update_port_attr(port_num);
        return m_ibv_port_attr.state;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

ibv_port_attr ib_ctx_handler::get_ibv_port_attr(int port_num)
{
        update_port_attr(port_num);
        return m_ibv_port_attr;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void ib_ctx_handler::set_dev_configuration()
{
	ibch_logdbg("Setting configuration for the MLX card %s", m_p_ibv_device->name);
	m_conf_attr_rx_num_wre                  = mce_sys.rx_num_wr;
	m_conf_attr_tx_num_post_send_notify     = NUM_TX_POST_SEND_NOTIFY;
	m_conf_attr_tx_max_inline               = mce_sys.tx_max_inline;
	m_conf_attr_tx_num_wre                  = mce_sys.tx_num_wr;

	if (m_conf_attr_tx_num_wre < (m_conf_attr_tx_num_post_send_notify * 2)) {
		m_conf_attr_tx_num_wre = m_conf_attr_tx_num_post_send_notify * 2;
		ibch_loginfo("%s Setting the %s to %d according to the device specific configuration:",
			   m_p_ibv_device->name, SYS_VAR_TX_NUM_WRE, mce_sys.tx_num_wr);
	}
}
