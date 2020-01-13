/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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
#include "vma/ib/base/verbs_extra.h"
#include "utils/lock_wrapper.h"

#ifdef DEFINED_DPCP
#include <mellanox/dpcp.h>
#endif /* DEFINED_DPCP */


typedef std::tr1::unordered_map<uint32_t, struct ibv_mr*> mr_map_lkey_t;

struct pacing_caps_t {
	uint32_t rate_limit_min;
	uint32_t rate_limit_max;
	bool burst;

	pacing_caps_t() : rate_limit_min(0), rate_limit_max(0), burst(false) {};
};

// client to event manager 'command' invoker (??)
//
class ib_ctx_handler : public event_handler_ibverbs
{
public:
	struct ib_ctx_handler_desc {
		struct ibv_device *device;
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
#ifdef DEFINED_DPCP
	dpcp::adapter*          set_dpcp_adapter();
	dpcp::adapter*          get_dpcp_adapter() { return m_p_adapter; }
#endif /* DEFINED_DPCP */
	vma_ibv_device_attr*    get_ibv_device_attr() { return vma_get_device_orig_attr(m_p_ibv_device_attr); }
#ifdef DEFINED_TSO
	vma_ibv_device_attr_ex* get_ibv_device_attr_ex() { return m_p_ibv_device_attr; }
#endif /* DEFINED_TSO */
	uint32_t                mem_reg(void *addr, size_t length, uint64_t access);
	void                    mem_dereg(uint32_t lkey);
	struct ibv_mr*          get_mem_reg(uint32_t lkey);
	bool                    is_removed() { return m_removed;}
	void                    set_ctx_time_converter_status(ts_conversion_mode_t conversion_mode);
	ts_conversion_mode_t    get_ctx_time_converter_status();
	void                    set_flow_tag_capability(bool flow_tag_capability); 
	bool                    get_flow_tag_capability() { return m_flow_tag_enabled; } // m_flow_tag_capability
	void                    set_burst_capability(bool burst);
	bool                    get_burst_capability() { return m_pacing_caps.burst; }
	bool                    is_packet_pacing_supported(uint32_t rate = 1);
	size_t                  get_on_device_memory_size() { return m_on_device_memory; }
	bool                    is_active(int port_num);
	bool                    is_mlx4(){ return is_mlx4(get_ibname()); }
	static bool             is_mlx4(const char *dev) { return strncmp(dev, "mlx4", 4) == 0; }
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
#ifdef DEFINED_DPCP
	dpcp::adapter          *m_p_adapter;
#endif /* DEFINED_DPCP */
	vma_ibv_device_attr_ex* m_p_ibv_device_attr;
	ibv_pd*                 m_p_ibv_pd;
	bool                    m_flow_tag_enabled;
	pacing_caps_t           m_pacing_caps;
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
