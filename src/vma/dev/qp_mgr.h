/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef QP_MGR_H
#define QP_MGR_H

#include <errno.h>
#include <ifaddrs.h>

#include "vma/ib/base/verbs_extra.h"
#include "vma/proto/vma_lwip.h"
#include "vlogger/vlogger.h"
#include "utils/atomic.h"
#include "vma/util/vtypes.h"
#include "vma/util/sys_vars.h"
#include "vma/util/libvma.h"
#include "vma/util/if.h"
#include "vma/util/hash_map.h"
#include "vma/lwip/opt.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/infra/sender.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/cq_mgr.h"

class buffer_pool;
class cq_mgr;
class ring;
class ring_simple;
class ring_eth_cb;

#ifndef MAX_SUPPORTED_IB_INLINE_SIZE
#define MAX_SUPPORTED_IB_INLINE_SIZE	884
#endif

/**
 * @class qp_mgr
 *
 * Object to manages the QP operation
 * This object is used for Rx & Tx at the same time
 * Once created it requests from the system a CQ to work with (for Rx & Tx separately)
 *
 * The qp_mgr object will manage the memory data buffers to be used for Rx & Tx.
 * A descriptor (mem_buf_desc_t) is used to point to each memory data buffers which is also menaged by the qm_mgr.
 *
 * NOTE:
 * The idea here is to use the rmda_cma_id object to manage the QP
 * all we need is to rdma_resolve_addr() so we have the correct pkey in the cma_id object
 * the rest is a simple transition of the QP states that is hidden inside the rdma_cm
 *
 */
class qp_mgr
{
friend class cq_mgr;
friend class cq_mgr_mlx5;
friend class cq_mgr_mp;
public:
	qp_mgr(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num, const uint32_t tx_num_wr);
	virtual ~qp_mgr();

	virtual void        up();
	virtual void        down();

	virtual void        post_recv_buffer(mem_buf_desc_t* p_mem_buf_desc); // Post for receive single mem_buf_desc
	void                post_recv_buffers(descq_t* p_buffers, size_t count); // Post for receive a list of mem_buf_desc
	int                 send(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr);

#ifdef DEFINED_TSO
	inline uint32_t     get_max_inline_data() const {
		return m_qp_cap.max_inline_data;
	}
	inline uint32_t     get_max_send_sge() const {
		return m_qp_cap.max_send_sge;
	}
#else
	uint32_t            get_max_inline_data() const {return m_max_inline_data; }
#endif /* DEFINED_TSO */
	int                 get_port_num() const { return m_port_num; }
	virtual uint16_t    get_partiton() const { return 0; };
	virtual uint32_t    get_underly_qpn() const { return 0; };
	struct ibv_qp*      get_ibv_qp() const { return m_qp; };
	class cq_mgr*       get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
	class cq_mgr*       get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
	virtual uint32_t    get_rx_max_wr_num();
	// This function can be replaced with a parameter during ring creation.
	// chain of calls may serve as cache warm for dummy send feature.
	inline bool         get_hw_dummy_send_support() {return m_hw_dummy_send_support; }

	virtual void        modify_qp_to_ready_state() = 0;
	void                modify_qp_to_error_state();

	void                release_rx_buffers();
	void                release_tx_buffers();
	virtual void        trigger_completion_for_all_sent_packets();
	uint32_t            is_ratelimit_change(struct vma_rate_limit_t &rate_limit);
	int                 modify_qp_ratelimit(struct vma_rate_limit_t &rate_limit, uint32_t rl_changes);
	static inline bool  is_lib_mlx5(const char* device_name) {return strstr(device_name, "mlx5");}
	virtual void        dm_release_data(mem_buf_desc_t* buff) { NOT_IN_USE(buff); }
	virtual bool        fill_hw_descriptors(vma_mlx_hw_device_data &data) {NOT_IN_USE(data);return false;};
protected:
	struct ibv_qp*      m_qp;
	uint64_t*           m_rq_wqe_idx_to_wrid;

	ring_simple*        m_p_ring;
	uint8_t             m_port_num;
	ib_ctx_handler*     m_p_ib_ctx_handler;

#ifdef DEFINED_TSO
	struct ibv_qp_cap   m_qp_cap;
#else
	uint32_t            m_max_inline_data;
#endif /* DEFINED_TSO */
	uint32_t            m_max_qp_wr;

	cq_mgr*             m_p_cq_mgr_rx;
	cq_mgr*             m_p_cq_mgr_tx;

	uint32_t            m_rx_num_wr;
	uint32_t            m_tx_num_wr;

	bool                m_hw_dummy_send_support;

	uint32_t            m_n_sysvar_rx_num_wr_to_post_recv;
	const uint32_t      m_n_sysvar_tx_num_wr_to_signal;
	const uint32_t      m_n_sysvar_rx_prefetch_bytes_before_poll;

	// recv_wr
	ibv_sge*            m_ibv_rx_sg_array;
	ibv_recv_wr*        m_ibv_rx_wr_array;
	uint32_t            m_curr_rx_wr;
	uintptr_t           m_last_posted_rx_wr_id; // Remember so in case we flush RQ we know to wait until this WR_ID is received

	// send wr
	uint32_t            m_n_unsignaled_count;
	mem_buf_desc_t*     m_p_last_tx_mem_buf_desc; // Remembered so we can list several mem_buf_desc_t on a single notification request

	mem_buf_desc_t*     m_p_prev_rx_desc_pushed;

	// generating packet IDs
	uint16_t            m_n_ip_id_base;
	uint16_t            m_n_ip_id_offset;
	struct vma_rate_limit_t m_rate_limit;

	int             configure(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual int     prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr) = 0;
	inline void     set_unsignaled_count(void) { m_n_unsignaled_count = m_n_sysvar_tx_num_wr_to_signal - 1;	}

	virtual cq_mgr* init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual cq_mgr* init_tx_cq_mgr(void);

	cq_mgr* handle_cq_initialization(uint32_t *num_wr, struct ibv_comp_channel* comp_event_channel, bool is_rx);

	virtual int     send_to_wire(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp);
	virtual bool    is_completion_need() { return !m_n_unsignaled_count; };
};

class qp_mgr_eth : public qp_mgr
{
public:
	qp_mgr_eth(const ring_simple* p_ring, const ib_ctx_handler* p_context,
		   const uint8_t port_num,
		   struct ibv_comp_channel* p_rx_comp_event_channel,
		   const uint32_t tx_num_wr, const uint16_t vlan,
		   bool call_configure = true):
			qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_vlan(vlan) {
		if(call_configure && configure(p_rx_comp_event_channel))
			throw_vma_exception("failed creating qp");
	};

	virtual ~qp_mgr_eth() {}

	virtual void 		modify_qp_to_ready_state();
	virtual uint16_t	get_partiton() const { return m_vlan; };

protected:
	virtual int		prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr);
private:
	const uint16_t 		m_vlan;
};

class qp_mgr_ib : public qp_mgr
{
public:
	qp_mgr_ib(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
			struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t pkey):
	qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_pkey(pkey), m_underly_qpn(0) {
		update_pkey_index();
		if(configure(p_rx_comp_event_channel)) throw_vma_exception("failed creating qp"); };

	virtual void 		modify_qp_to_ready_state();
	virtual uint16_t	get_partiton() const { return m_pkey; };
	virtual uint32_t	get_underly_qpn() const { return m_underly_qpn; };

protected:
	virtual int		prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr);

private:
	const uint16_t 		m_pkey;
	uint16_t 		m_pkey_index;
	uint32_t 		m_underly_qpn;

	void 			update_pkey_index();
};

#endif
