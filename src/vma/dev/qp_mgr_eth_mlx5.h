/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef QP_MGR_ETH_MLX5_H
#define QP_MGR_ETH_MLX5_H

#include "qp_mgr.h"
#include "vma/util/sg_array.h"
#include "vma/dev/dm_mgr.h"

#if defined(DEFINED_DIRECT_VERBS)


struct mlx5_wqe64 {
	union {
		struct mlx5_wqe_ctrl_seg ctrl;
		uint32_t data[4];
	} ctrl;
	struct mlx5_wqe_eth_seg eseg;
	struct mlx5_wqe_data_seg dseg;
};

class qp_mgr_eth_mlx5 : public qp_mgr_eth
{
friend class cq_mgr_mlx5;
public:
	qp_mgr_eth_mlx5(struct qp_mgr_desc *desc,
			const uint32_t tx_num_wr,
			const uint16_t vlan, bool call_configure = true);
	virtual ~qp_mgr_eth_mlx5();
	virtual void	up();
	virtual void	down();
	virtual void    post_recv_buffer(mem_buf_desc_t* p_mem_buf_desc); // Post for receive single mem_buf_desc
	vma_ib_mlx5_qp_t    m_mlx5_qp;
protected:
	void		trigger_completion_for_all_sent_packets();
	void		init_sq();

	virtual bool is_rq_empty() const { return (m_mlx5_qp.rq.head == m_mlx5_qp.rq.tail); }

	uint64_t*   m_sq_wqe_idx_to_wrid;
	uint64_t    m_rq_wqe_counter;
private:
	cq_mgr*		init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual cq_mgr*	init_tx_cq_mgr(void);
	virtual bool	is_completion_need() { return !m_n_unsignaled_count || (m_dm_enabled && m_dm_mgr.is_completion_need()); };
	virtual void	dm_release_data(mem_buf_desc_t* buff) { m_dm_mgr.release_data(buff); }

	inline void	set_signal_in_next_send_wqe();
	int		send_to_wire(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp);
	inline int	fill_wqe(vma_ibv_send_wr* p_send_wqe);
#ifdef DEFINED_TSO
	int		fill_wqe_lso(vma_ibv_send_wr* pswr);
	inline void	ring_doorbell(uint64_t* wqe, int db_method, int num_wqebb, int num_wqebb_top = 0);
#else
	inline void	ring_doorbell(uint64_t* wqe, int num_wqebb, int num_wqebb_top = 0);
#endif /* DEFINED_TSO */
	inline int	fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t* data_addr, int max_inline_len, int inline_len);
	inline int	fill_ptr_segment(sg_array &sga, struct mlx5_wqe_data_seg* dp_seg, uint8_t* data_addr, int data_len, mem_buf_desc_t* buffer);

	struct mlx5_wqe64	(*m_sq_wqes)[];
	struct mlx5_wqe64*	m_sq_wqe_hot;
	uint8_t*		m_sq_wqes_end;
	enum {
		MLX5_DB_METHOD_BF,
		MLX5_DB_METHOD_DB
	} m_db_method;

	int                 m_sq_wqe_hot_index;
	uint16_t            m_sq_wqe_counter;
	dm_mgr              m_dm_mgr;
	bool                m_dm_enabled;
};
#endif //defined(DEFINED_DIRECT_VERBS)
#endif //QP_MGR_ETH_MLX5_H
