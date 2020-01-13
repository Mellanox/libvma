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


#ifndef CQ_MGR_MLX5_H
#define CQ_MGR_MLX5_H

#include "cq_mgr.h"
#include "qp_mgr_eth_mlx5.h"

#if defined(DEFINED_DIRECT_VERBS)
class qp_mgr_eth_mlx5;

/* Get CQE opcode. */
#define MLX5_CQE_OPCODE(op_own) ((op_own) >> 4)

/* Get CQE owner bit. */
#define MLX5_CQE_OWNER(op_own) ((op_own) & MLX5_CQE_OWNER_MASK)

class cq_mgr_mlx5: public cq_mgr
{
public:

	enum buff_status_e{BS_OK, BS_CQE_RESP_WR_IMM_NOT_SUPPORTED, BS_IBV_WC_WR_FLUSH_ERR, BS_CQE_INVALID, BS_GENERAL_ERR};

	cq_mgr_mlx5(ring_simple* p_ring, ib_ctx_handler* p_ib_ctx_handler, uint32_t cq_size,
		struct ibv_comp_channel* p_comp_event_channel, bool is_rx, bool call_configure = true);
	virtual ~cq_mgr_mlx5();

	virtual mem_buf_desc_t*     poll(enum buff_status_e& status);
	virtual int                 drain_and_proccess(uintptr_t* p_recycle_buffers_last_wr_id = NULL);
	virtual int                 poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int                 poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst);
	virtual int                 poll_and_process_element_tx(uint64_t* p_cq_poll_sn);
	int                         poll_and_process_error_element_tx(struct mlx5_cqe64 *cqe, uint64_t* p_cq_poll_sn);
	int                         poll_and_process_error_element_rx(struct mlx5_cqe64 *cqe, void* pv_fd_ready_array);

	virtual mem_buf_desc_t*     process_cq_element_rx(mem_buf_desc_t* p_mem_buf_desc, enum buff_status_e status);
	virtual void                add_qp_rx(qp_mgr* qp);
	void                        set_qp_rq(qp_mgr* qp);
	virtual void                add_qp_tx(qp_mgr* qp);
	virtual uint32_t            clean_cq();
	virtual bool                fill_cq_hw_descriptors(struct hw_cq_data &data);
	virtual void                get_cq_event(int count = 1) { vma_ib_mlx5_get_cq_event(&m_mlx5_cq, count); };

protected:
	qp_mgr_eth_mlx5*            m_qp;
	vma_ib_mlx5_cq_t            m_mlx5_cq;
	inline struct mlx5_cqe64*   check_cqe(void);

private:
	const bool                  m_b_sysvar_enable_socketxtreme;
	mem_buf_desc_t              *m_rx_hot_buffer;

	inline struct mlx5_cqe64*   get_cqe64(struct mlx5_cqe64 **cqe_err = NULL);
	inline void                 cqe64_to_mem_buff_desc(struct mlx5_cqe64 *cqe, mem_buf_desc_t* p_rx_wc_buf_desc, enum buff_status_e& status);
	void                        cqe64_to_vma_wc(struct mlx5_cqe64 *cqe, vma_ibv_wc *wc);
	inline struct mlx5_cqe64*   check_error_completion(struct mlx5_cqe64 *cqe, uint32_t *ci, uint8_t op_own);
	inline void                 update_global_sn(uint64_t& cq_poll_sn, uint32_t rettotal);

	virtual int	req_notify_cq() {
		return vma_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0);
	};
};

#endif /* DEFINED_DIRECT_VERBS */
#endif //CQ_MGR_MLX5_H
