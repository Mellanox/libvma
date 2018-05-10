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


#ifndef IB_CTX_HANDLER_H
#define IB_CTX_HANDLER_H

#include <infiniband/verbs.h>
#include <tr1/unordered_map>

#include "vma/event/event_handler_ibverbs.h"
#include "vma/dev/time_converter.h"
#include "utils/lock_wrapper.h"

typedef std::tr1::unordered_map<uint32_t, struct ibv_mr*> mr_map_lkey_t;

// client to event manager 'command' invoker (??)
//
class ib_ctx_handler : public event_handler_ibverbs
{
public:
	struct ib_ctx_handler_desc {
		struct ibv_device *device;
		ts_conversion_mode_t ctx_time_converter_mode;
	};
public:
	ib_ctx_handler(struct ib_ctx_handler_desc *desc);
	virtual ~ib_ctx_handler();

	/*
	 * on init or constructor:
	 *      register to event manager with m_channel and this.
	 * */
	ibv_pd*                 get_ibv_pd() { return m_p_ibv_pd; }
	bool                    post_umr_wr(struct ibv_exp_send_wr &wr);
	ibv_device*             get_ibv_device() { return m_p_ibv_device; }
	inline char*            get_ibname() { return (m_p_ibv_device ? m_p_ibv_device->name : (char *)""); }
	struct ibv_context*     get_ibv_context() { return m_p_ibv_context; }
	vma_ibv_device_attr*    get_ibv_device_attr() { return m_p_ibv_device_attr; }
	uint32_t                mem_reg(void *addr, size_t length, uint64_t access);
	void                    mem_dereg(uint32_t lkey);
	struct ibv_mr*          get_mem_reg(uint32_t lkey);
	bool                    is_removed() { return m_removed;}
	ts_conversion_mode_t    get_ctx_time_converter_status();
	void                    set_flow_tag_capability(bool flow_tag_capability); 
	bool                    get_flow_tag_capability() { return m_flow_tag_enabled; } // m_flow_tag_capability
	size_t                  get_on_device_memory_size() { return m_on_device_memory; }
	bool                    is_active(int port_num);
	virtual void            handle_event_ibverbs_cb(void *ev_data, void *ctx);

	void set_str();
	void print_val();

	inline void convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime)
	{
		m_p_ctx_time_converter->convert_hw_time_to_system_time(hwtime, systime);
	}
private:
	bool                    create_umr_qp();
	void                    handle_event_device_fatal();
	ibv_device*             m_p_ibv_device; // HCA handle
	struct ibv_context*     m_p_ibv_context;
	vma_ibv_device_attr*    m_p_ibv_device_attr;
	ibv_pd*                 m_p_ibv_pd;
	bool                    m_flow_tag_enabled;
	size_t                  m_on_device_memory;
	bool                    m_removed;
	lock_spin               m_lock_umr;
	struct ibv_cq*          m_umr_cq;
	struct ibv_qp*          m_umr_qp;
	time_converter*         m_p_ctx_time_converter;
	mr_map_lkey_t           m_mr_map_lkey;

	char m_str[255];
};

#endif
