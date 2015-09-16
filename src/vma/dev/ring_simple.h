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

#ifndef RING_SIMPLE_H
#define RING_SIMPLE_H

#include "ring.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/utils.h"

class ring_simple : public ring
{
public:
	ring_simple(in_addr_t local_if, uint16_t partition_sn, int count, transport_type_t transport_type, ring* parent = NULL);
	virtual ~ring_simple();

	virtual int request_notification(cq_type_t cq_type, uint64_t poll_sn);
	virtual int poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void adapt_cq_moderation();
	virtual bool reclaim_recv_buffers_no_lock(descq_t *rx_reuse); // No locks
	virtual bool reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst); // No locks
	virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
	virtual int	drain_and_proccess(cq_type_t cq_type);
	virtual int	wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual void mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc); // Assume locked...
	// Tx completion handling at the qp_mgr level is just re listing the desc+data buffer in the free lists
	virtual void mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc); // Assume locked...
	virtual void mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);
	virtual void mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual int	get_max_tx_inline();
	int send_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual bool attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual bool detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink);
	virtual void restart(ring_resource_creation_info_t* p_ring_info);
	virtual bool is_up();
	void start_active_qp_mgr();
	void stop_active_qp_mgr();
	virtual mem_buf_desc_t* mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs = 1);
	virtual int	mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock = false);
	virtual void inc_ring_stats(ring_user_id_t id);
	virtual void send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, bool b_block);
	virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc);
	virtual bool is_member(mem_buf_desc_owner* rng);
	virtual ring_user_id_t generate_id();
	virtual ring_user_id_t generate_id(const address_t src_mac, const address_t dst_mac, uint16_t eth_proto, uint16_t encap_proto, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);

	friend class cq_mgr;
	friend class qp_mgr;
	friend class rfs;
	friend class rfs_uc;
	friend class rfs_uc_tcp_gro;
	friend class rfs_mc;
	friend class ring_bond;

protected:
	virtual qp_mgr* 		create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel) = 0;
	void 		create_resources(ring_resource_creation_info_t* p_ring_info, bool active);
	// Internal functions. No need for locks mechanism.
	bool			 rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, transport_type_t m_transport_type, void* pv_fd_ready_array);
	void 			 print_flow_to_rfs_udp_uc_map(flow_spec_udp_uc_map_t *p_flow_map);
	void 			 print_flow_to_rfs_tcp_map(flow_spec_tcp_map_t *p_flow_map);
	//	void	print_ring_flow_to_rfs_map(flow_spec_map_t *p_flow_map);

	void			 flow_udp_uc_del_all();
	void			 flow_udp_mc_del_all();
	void			 flow_tcp_del_all();
	bool		 request_more_tx_buffers(uint32_t count);

private:
	inline void 		 send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe);
	inline mem_buf_desc_t*	 get_tx_buffers(uint32_t n_num_mem_bufs);
	inline int		 put_tx_buffers(mem_buf_desc_t* buff_list);
	inline int		 put_tx_single_buffer(mem_buf_desc_t* buff);
	bool		 is_available_qp_wr(bool b_block);
	void		 modify_cq_moderation(uint32_t period, uint32_t count);
	void	save_l2_address(const L2_address* p_l2_addr) { delete_l2_address(); m_p_l2_addr = p_l2_addr->clone(); };
	void	delete_l2_address() { if (m_p_l2_addr) delete m_p_l2_addr; m_p_l2_addr = NULL; };
	qp_mgr*				m_p_qp_mgr;
	cq_mgr*				m_p_cq_mgr_rx;
	cq_mgr*				m_p_cq_mgr_tx;
	struct ibv_comp_channel*	m_p_rx_comp_event_channel;
	L2_address* 		m_p_l2_addr;

};

class ring_eth : public ring_simple
{
public:
	ring_eth(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, bool active, uint16_t vlan, ring* parent = NULL) :
		ring_simple(local_if, vlan, count, VMA_TRANSPORT_ETH, parent) { create_resources(p_ring_info, active); };

protected:
	virtual qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel);
};

class ring_ib : public ring_simple
{
public:
	ring_ib(in_addr_t local_if, ring_resource_creation_info_t* p_ring_info, int count, bool active, uint16_t pkey, ring* parent = NULL) :
		ring_simple(local_if, pkey, count, VMA_TRANSPORT_IB, parent) { create_resources(p_ring_info, active); };

protected:
	virtual qp_mgr* create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel);
};

#endif //RING_SIMPLE_H
