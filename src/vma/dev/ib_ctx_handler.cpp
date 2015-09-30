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
#include "vma/dev/ib_ctx_handler.h"
#include "vma/util/bullseye.h"
#include <stdlib.h>
#include "vma/util/verbs_extra.h"
#include "vma/event/event_handler_manager.h"

#define MODULE_NAME             "ib_ctx_handler"

#define UPDATE_HW_TIMER_PERIOD_MS 10000
#define UPDATE_HW_TIMER_INIT_MS 1000

#define ibch_logpanic           __log_panic
#define ibch_logerr             __log_err
#define ibch_logwarn            __log_warn
#define ibch_loginfo            __log_info
#define ibch_logdbg             __log_info_dbg
#define ibch_logfunc            __log_info_func
#define ibch_logfuncall         __log_info_funcall



ib_ctx_handler::ib_ctx_handler(struct ibv_context* ctx) :
	m_channel(0), m_removed(false), m_conf_attr_rx_num_wre(0), m_conf_attr_tx_num_post_send_notify(0),
	m_conf_attr_tx_max_inline(0), m_conf_attr_tx_num_wre(0), m_ctx_parmeters_id(0), m_timer_handle(NULL)
{
	memset(&m_ibv_port_attr, 0, sizeof(m_ibv_port_attr));
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

	memset(&m_ibv_device_attr, 0, sizeof(m_ibv_device_attr));
	vma_ibv_device_attr_comp_mask(m_ibv_device_attr);
	IF_VERBS_FAILURE(vma_ibv_query_device(m_p_ibv_context, &m_ibv_device_attr)) {
		ibch_logerr("ibv_query_device failed on ibv device %p (ibv context %p) (errno=%d %m)", 
			  m_p_ibv_device, m_p_ibv_context, errno);
		return;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	load_timestamp_params(true);

	g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_INIT_MS, this, ONE_SHOT_TIMER, 0);
	m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PERIOD_MS, this, PERIODIC_TIMER, 0);

	ibch_logdbg("ibv device '%s' [%p] has %d port%s. Vendor Part Id: %d, FW Ver: %s, max_qp_wr=%d, hca_core_clock (per sec)=%ld",
			m_p_ibv_device->name, m_p_ibv_device, m_ibv_device_attr.phys_port_cnt, ((m_ibv_device_attr.phys_port_cnt>1)?"s":""),
			m_ibv_device_attr.vendor_part_id, m_ibv_device_attr.fw_ver, m_ibv_device_attr.max_qp_wr,
			m_ctx_convert_parmeters[m_ctx_parmeters_id].hca_core_clock);

	set_dev_configuration();

	g_p_event_handler_manager->register_ibverbs_event(m_p_ibv_context->async_fd, this, m_p_ibv_context, 0);
}

ib_ctx_handler::~ib_ctx_handler() {
	g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
	// must delete ib_ctx_handler only after freeing all resources that
	// are still associated with the PD m_p_ibv_pd
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ibv_dealloc_pd(m_p_ibv_pd))
		ibch_logdbg("pd deallocation failure (errno=%d %m)", errno);
	BULLSEYE_EXCLUDE_BLOCK_END

	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = NULL;
	}
}

void ib_ctx_handler::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);
	fix_hw_clock_deviation();
}

#ifdef DEFINED_IBV_EXP_CQ_TIMESTAMP

bool ib_ctx_handler::sync_clocks(struct timespec* st, uint64_t* hw_clock, bool init = false){
	struct timespec st1, st2, diff, st_min = TIMESPEC_INITIALIZER;
	struct ibv_exp_values queried_values;
	int64_t rval, interval, best_interval = 0;
	uint64_t hw_clock_min = 0;

	memset(&queried_values, 0, sizeof(queried_values));
	queried_values.comp_mask = IBV_EXP_VALUES_HW_CLOCK;
	for (int i = 0 ; i < 10 ; i++) {
		clock_gettime(CLOCK_REALTIME, &st1);
		if ((rval = ibv_exp_query_values(m_p_ibv_context,IBV_EXP_VALUES_HW_CLOCK, &queried_values)) || !queried_values.hwclock) {
			if (init) {
				ibch_logwarn("Error in querying hw clock, can't convert hw time to system time (ibv_exp_query_values() "
						"return value=%d ) (ibv context %p) (errno=%d %m)", rval, m_p_ibv_context, errno);
			}
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

void ib_ctx_handler::load_timestamp_params(bool init = false){
	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];
	int rval;
	if (!current_parameters_set->hca_core_clock){
		struct ibv_exp_device_attr device_attr;
		memset(&device_attr, 0, sizeof(device_attr));
		device_attr.comp_mask = IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

		if ((rval = ibv_exp_query_device(m_p_ibv_context ,&device_attr)) || !device_attr.hca_core_clock) {
			if (init) {
				ibch_logwarn("Error in querying hca core clock (ibv_exp_query_device() return value=%d ) (ibv context %p) "
						"(errno=%d %m)", rval, m_p_ibv_context, errno);
			}
			return;
		}
		current_parameters_set->hca_core_clock = device_attr.hca_core_clock * USEC_PER_SEC;
	}

	if (!current_parameters_set->is_convertion_valid) {
		if (sync_clocks(&current_parameters_set->sync_systime, &current_parameters_set->sync_hw_clock, init)) {
			current_parameters_set->is_convertion_valid = true;
		}
	}
}

void ib_ctx_handler::fix_hw_clock_deviation(){
	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];

	if (!current_parameters_set->hca_core_clock || !current_parameters_set->is_convertion_valid) {
		load_timestamp_params();
		return;
	}

	struct timespec current_time, diff_systime;
	uint64_t diff_hw_time, diff_systime_nano, estimated_hw_time, hw_clock;
	int next_id = (m_ctx_parmeters_id + 1) % 2;
	ctx_timestamping_params_t* next_parameters_set = &m_ctx_convert_parmeters[next_id];
	int64_t deviation_hw;

	if (!sync_clocks(&current_time, &hw_clock)) {
		next_parameters_set->is_convertion_valid = false;
		return;
	}

	ts_sub(&current_time, &current_parameters_set->sync_systime, &diff_systime);
	diff_hw_time = hw_clock - current_parameters_set->sync_hw_clock;
	diff_systime_nano = diff_systime.tv_sec * NSEC_PER_SEC + diff_systime.tv_nsec;

	estimated_hw_time = (diff_systime.tv_sec * current_parameters_set->hca_core_clock) + (diff_systime.tv_nsec * current_parameters_set->hca_core_clock / NSEC_PER_SEC);
	deviation_hw = estimated_hw_time -  diff_hw_time;

	ibch_logdbg("ibv device '%s' [%p] : fix_hw_clock_deviation parameters status : %ld.%09ld since last deviation fix, \nUPDATE_HW_TIMER_PERIOD_MS = %d, current_parameters_set = %p, "
			"estimated_hw_time = %ld, diff_hw_time = %ld, diff = %ld ,m_hca_core_clock = %ld", m_p_ibv_device->name, m_p_ibv_device, diff_systime.tv_sec, diff_systime.tv_nsec,
			UPDATE_HW_TIMER_PERIOD_MS, current_parameters_set, estimated_hw_time, diff_hw_time, deviation_hw, current_parameters_set->hca_core_clock);

	if (abs(deviation_hw) < 10) {
		return;
	}

	next_parameters_set->hca_core_clock = (diff_hw_time * NSEC_PER_SEC) / diff_systime_nano;
	next_parameters_set->sync_hw_clock = hw_clock;
	next_parameters_set->sync_systime = current_time;
	next_parameters_set->is_convertion_valid = true;

	m_ctx_parmeters_id = next_id;
}

#else

void ib_ctx_handler::load_timestamp_params(bool init){ NOT_IN_USE(init); }
void ib_ctx_handler::fix_hw_clock_deviation(){}
bool ib_ctx_handler::sync_clocks(struct timespec* ts, uint64_t* hw_clock, bool init = false){ NOT_IN_USE(ts); NOT_IN_USE(hw_clock); return init;}

#endif

void ib_ctx_handler::convert_hw_time_to_system_time(uint64_t packet_hw_time, struct timespec* packet_systime) {

	ctx_timestamping_params_t* current_parameters_set = &m_ctx_convert_parmeters[m_ctx_parmeters_id];
	if (current_parameters_set->hca_core_clock && packet_hw_time) {

		struct timespec hw_to_timespec, sync_systime;
		uint64_t hw_time_diff, hca_core_clock, sync_hw_clock;
		int is_ts_convertion_valid = current_parameters_set->is_convertion_valid;

		hca_core_clock = current_parameters_set->hca_core_clock;
		sync_hw_clock = current_parameters_set->sync_hw_clock;
		sync_systime = current_parameters_set->sync_systime;

		hw_time_diff = is_ts_convertion_valid ? packet_hw_time - sync_hw_clock : packet_hw_time;

		hw_to_timespec.tv_sec = hw_time_diff / hca_core_clock;
		hw_time_diff -= hw_to_timespec.tv_sec * hca_core_clock;
		hw_to_timespec.tv_nsec = (hw_time_diff * NSEC_PER_SEC) / hca_core_clock;

		if (is_ts_convertion_valid) {
			ts_add(&sync_systime, &hw_to_timespec, packet_systime);
		} else {
			*packet_systime = hw_to_timespec;
		}
	}
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

void ib_ctx_handler::handle_event_ibverbs_cb(void *ev_data, void *ctx)
{
 	NOT_IN_USE(ctx);

	struct ibv_async_event *ibv_event = (struct ibv_async_event*)ev_data;
	ibch_logdbg("received ibv_event '%s' (%d)", priv_ibv_event_desc_str(ibv_event->event_type), ibv_event->event_type);
		
	if (ibv_event->event_type == IBV_EVENT_DEVICE_FATAL) {
		handle_event_DEVICE_FATAL();
	}
}

void ib_ctx_handler::handle_event_DEVICE_FATAL()
{
	m_removed = true;
	g_p_event_handler_manager->unregister_ibverbs_event(m_p_ibv_context->async_fd, this);
}
