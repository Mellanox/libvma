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


#ifndef IB_CTX_HANDLER_H
#define IB_CTX_HANDLER_H

#include <infiniband/verbs.h>
#include "vma/event/event_handler_ibverbs.h"
#include "vma/dev/ib_ctx_time_converter.h"

// client to event manager 'command' invoker (??)
//
class ib_ctx_handler : public event_handler_ibverbs
{
public:
	ib_ctx_handler(struct ibv_context* ctx, ts_conversion_mode_t ctx_time_converter_mode);
	virtual ~ib_ctx_handler();
	/*
	 * on init or constructor:
	 *      register to event manager with m_channel and this.
	 * */
	//void execute(struct ibv_async_event ibv_event) { handle_ibv_event(ibv_event); }
	void                    set_dev_configuration();
	ibv_mr*                 mem_reg(void *addr, size_t length, uint64_t access);
	ibv_port_state          get_port_state(int port_num);
	ibv_device*             get_ibv_device() { return m_p_ibv_device;}
	ibv_pd*			get_ibv_pd() { return m_p_ibv_pd;}
	struct ibv_context*     get_ibv_context() { return m_p_ibv_context;}
	vma_ibv_device_attr&    get_ibv_device_attr() { return m_ibv_device_attr;}
	struct ibv_port_attr    get_ibv_port_attr(int port_num);
	bool                    is_removed() { return m_removed;}
	virtual void            handle_event_ibverbs_cb(void *ev_data, void *ctx);
	void                    handle_event_DEVICE_FATAL();
	ts_conversion_mode_t    get_ctx_time_converter_status();

	inline void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) { ctx_time_converter.convert_hw_time_to_system_time(hwtime, systime); }

private:
	struct ibv_context*     m_p_ibv_context;
	struct ibv_port_attr    m_ibv_port_attr;
	ibv_device*             m_p_ibv_device; // HCA handle
	vma_ibv_device_attr     m_ibv_device_attr;
	ibv_pd*                 m_p_ibv_pd;
	bool                    m_removed;

	bool                    update_port_attr(int port_num);

	//void handle_ibv_event(struct ibv_async_event ibv_event); // will be called by the command execute
	//
	//conf params
	uint32_t                m_conf_attr_rx_num_wre;
	uint32_t                m_conf_attr_tx_num_to_signal;
	uint32_t                m_conf_attr_tx_max_inline;
	uint32_t                m_conf_attr_tx_num_wre;

	ib_ctx_time_converter  ctx_time_converter;
};

#endif
