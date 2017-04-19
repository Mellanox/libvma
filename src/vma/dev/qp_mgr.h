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


#ifndef QP_MGR_H
#define QP_MGR_H

#include <errno.h>
#include <ifaddrs.h>

#include "vlogger/vlogger.h"
#include "utils/atomic.h"
#include "vma/util/vtypes.h"
#include "vma/util/sys_vars.h"
#include "vma/util/libvma.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/if.h"
#include "vma/lwip/opt.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/infra/sender.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/ah_cleaner.h"
#include "vma/dev/cq_mgr.h"

#if 0
REVIEW: verify can remove: #include "vma/dev/ring.h"
#endif

#ifdef DEFINED_VMAPOLL
#include <infiniband/mlx5_hw.h>
#include "vma/hw/mlx5/wqe.h"
#endif // DEFINED_VMAPOLL

class buffer_pool;
class cq_mgr;
class ring;
class ring_simple;

#ifndef MAX_SUPPORTED_IB_INLINE_SIZE
#define MAX_SUPPORTED_IB_INLINE_SIZE	884
#endif

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator==(ibv_gid const& key1, ibv_gid const& key2) {
	return !memcmp(key1.raw, key2.raw, sizeof key1);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef hash_map<ibv_gid, uint32_t> mgid_ref_count_map_t;

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
#ifdef DEFINED_VMAPOLL
friend class cq_mgr;
#endif // DEFINED_VMAPOLL

friend class cq_mgr_mlx5;
public:
	qp_mgr(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num, const uint32_t tx_num_wr);
	virtual ~qp_mgr();

	void                up();
	void                down();

	int                 post_recv(mem_buf_desc_t* p_mem_buf_desc); // Post for receive a list of mem_buf_desc
	int                 send(vma_ibv_send_wr* p_send_wqe);

	uint32_t            get_max_inline_tx_data() const {return m_max_inline_data; }
	int                 get_port_num() const { return m_port_num; }
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual uint16_t    get_pkey_index() const { return 0; };
	virtual uint16_t    get_partiton() const { return 0; };
	virtual uint32_t    get_underly_qpn() const { return 0; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	struct ibv_qp*      get_ibv_qp() const { return m_qp; };
	class cq_mgr*       get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
	class cq_mgr*       get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
	ib_ctx_handler*     get_ib_ctx_handler() const { return m_p_ib_ctx_handler; }
	uint32_t            get_rx_max_wr_num();

	// This function can be replaced with a parameter during ring creation.
	// chain of calls may serve as cache warm for dummy send feature.
	inline bool         get_hw_dummy_send_support() {return m_hw_dummy_send_support; }

	// create a AH cleaner object which will be linked to the following post send (if any)
	void                ah_cleanup(struct ibv_ah* ah);

	virtual void        modify_qp_to_ready_state() = 0;
	void                modify_qp_to_error_state();

	void                release_rx_buffers();
	void                release_tx_buffers();
	void                trigger_completion_for_all_sent_packets();
	static inline bool  is_lib_mlx5(const char* divace_name)
	{
		return strstr(divace_name, "mlx5");
	}
#ifdef DEFINED_VMAPOLL
	void            set_signal_in_next_send_wqe();
	void            mlx5_send(vma_ibv_send_wr* p_send_wqe);
	void            mlx5_init_sq();
#endif // DEFINED_VMAPOLL

protected:
	uint64_t        m_rq_wqe_counter;
	uint64_t        *m_rq_wqe_idx_to_wrid;

#ifdef DEFINED_VMAPOLL
	struct mlx5_qp      *m_mlx5_hw_qp;
	volatile struct     mlx5_wqe64* m_sq_hot_wqe;
	int                 m_sq_hot_wqe_index;
	volatile struct		mlx5_wqe64 (*m_mlx5_sq_wqes)[];
	volatile uint32_t   *m_sq_db;
	volatile void       *m_sq_bf_reg;
	uint16_t            m_sq_bf_offset;
	uint16_t            m_sq_bf_buf_size;
	uint16_t            m_sq_wqe_counter;
	uint64_t            *m_sq_wqe_idx_to_wrid;
	unsigned int        m_qp_num;
#endif // DEFINED_VMAPOLL
	struct ibv_qp*      m_qp;

	ring_simple*        m_p_ring;
	uint8_t             m_port_num;
	ib_ctx_handler*     m_p_ib_ctx_handler;

	ah_cleaner*         m_p_ahc_head;
	ah_cleaner*         m_p_ahc_tail;

	uint32_t            m_max_inline_data;
	uint32_t            m_max_qp_wr;

	cq_mgr*             m_p_cq_mgr_rx;
	cq_mgr*             m_p_cq_mgr_tx;

	uint32_t            m_rx_num_wr;
	uint32_t            m_tx_num_wr;

	bool                m_hw_dummy_send_support;

	const uint32_t      m_n_sysvar_rx_num_wr_to_post_recv;
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

	mgid_ref_count_map_t  m_attach_mc_grp_ref_cnt;

	int             configure(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual int     prepare_ibv_qp(vma_ibv_qp_init_attr& qp_init_attr) = 0;
	inline void     set_unsignaled_count();
	virtual cq_mgr* init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual cq_mgr* init_tx_cq_mgr(void);
};

class qp_mgr_eth : public qp_mgr
{
public:
	qp_mgr_eth(const ring_simple* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
			struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t vlan, bool call_configure = true) throw (vma_error) :
				qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_vlan(vlan)
					{ if(call_configure && configure(p_rx_comp_event_channel)) throw_vma_exception("failed creating qp");};

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
			struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t pkey) throw (vma_error) :
	qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_pkey(pkey), m_underly_qpn(0) {
		update_pkey_index();
		if(configure(p_rx_comp_event_channel)) throw_vma_exception("failed creating qp"); };

	virtual void 		modify_qp_to_ready_state();
	virtual uint16_t	get_partiton() const { return m_pkey; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual uint16_t	get_pkey_index() const { return m_pkey_index; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
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
