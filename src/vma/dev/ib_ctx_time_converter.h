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


#ifndef IB_CTX_TIME_CONVERTER_H
#define IB_CTX_TIME_CONVERTER_H

#include <infiniband/verbs.h>
#include "vma/event/timer_handler.h"
#include <vma/util/sys_vars.h>

class ctx_timestamping_params_t {
public:

	uint64_t                hca_core_clock;
	uint64_t                sync_hw_clock;
	struct timespec         sync_systime;

	ctx_timestamping_params_t() : hca_core_clock(0), sync_hw_clock(0) {
		sync_systime.tv_sec = 0;
		sync_systime.tv_nsec = 0;
	}
};

class ib_ctx_time_converter :  public timer_handler
{
public:

	ib_ctx_time_converter(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode);
	virtual ~ib_ctx_time_converter();

	void                      convert_hw_time_to_system_time(uint64_t packet_hw_time, struct timespec* packet_systime);
	void                      handle_timer_expired(void* user_data);

	uint64_t                  get_hca_core_clock();
	ts_conversion_mode_t      get_converter_status();
	static ts_conversion_mode_t     get_devices_convertor_status(struct ibv_context** ibv_context_list, int num_devices);

private:

	struct ibv_context*       m_p_ibv_context;
	ctx_timestamping_params_t m_ctx_convert_parmeters[2];
	int                       m_ctx_parmeters_id;
	void*                     m_timer_handle;
	ts_conversion_mode_t      m_converter_status;

	void                      fix_hw_clock_deviation();
	bool                      sync_clocks(struct timespec* st, uint64_t* hw_clock);
	static uint32_t           get_device_convertor_status(struct ibv_context* ctx);
};


#endif
