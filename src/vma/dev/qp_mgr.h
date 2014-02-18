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


#ifndef QP_MGR_H
#define QP_MGR_H

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netif/etharp.h>

#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/sys_vars.h"
#include "vma/util/atomic.h"
#include "vma/util/libvma.h"
#include "vma/util/verbs_extra.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/infra/sender.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/dev/ah_cleaner.h"
#include "vma/dev/cq_mgr.h"
#include "vma/dev/ring.h"

class buffer_pool;
class cq_mgr;
class ring;

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
public:
	qp_mgr(const ring* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num, const uint32_t tx_num_wr);
	virtual ~qp_mgr();

	void 			up();
	void 			down();

	int			post_recv(mem_buf_desc_t* p_mem_buf_desc); // Post for receive a list of mem_buf_desc
	int 			send(vma_ibv_send_wr* p_send_wqe);

	uint32_t		get_max_inline_tx_data() const {return m_max_inline_data; }
	int			get_port_num() const { return m_port_num; }
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual uint16_t	get_pkey_index() const { return 0; };
	virtual uint16_t	get_partiton() const { return 0; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	struct ibv_qp*		get_ibv_qp() const { return m_qp; };
	struct cq_mgr*  	get_tx_cq_mgr() const { return m_p_cq_mgr_tx; }
	struct cq_mgr*  	get_rx_cq_mgr() const { return m_p_cq_mgr_rx; }
	uint32_t		get_rx_max_wr_num();

	// create a AH cleaner object which will be linked to the following post send (if any)
	void                    ah_cleanup(struct ibv_ah* ah);

	virtual void 		modify_qp_to_ready_state() = 0;
	void 			modify_qp_to_error_state();

	void			release_rx_buffers();
	void 			release_tx_buffers();
	void			trigger_completion_for_all_sent_packets();

protected:
	struct ibv_qp*		m_qp;
	ring*			m_p_ring;
	uint8_t 		m_port_num;
	ib_ctx_handler*		m_p_ib_ctx_handler;

	ah_cleaner*             m_p_ahc_head;
	ah_cleaner*             m_p_ahc_tail;

	uint32_t		m_max_inline_data;
	uint32_t		m_max_qp_wr;

	cq_mgr*			m_p_cq_mgr_rx;
	cq_mgr*			m_p_cq_mgr_tx;

	uint32_t 		m_rx_num_wr;
	uint32_t 		m_tx_num_wr;

	uint32_t 		m_rx_num_wr_to_post_recv;

	// recv_wr
	ibv_sge*		m_ibv_rx_sg_array;
	ibv_recv_wr*		m_ibv_rx_wr_array;
	uint32_t		m_curr_rx_wr;

	// send wr
	uint32_t		m_n_unsignaled_count;
	uint32_t		m_n_tx_count;
	mem_buf_desc_t*		m_p_last_tx_mem_buf_desc; // Remembered so we can list several mem_buf_desc_t on a single notification request

	mem_buf_desc_t*		m_p_prev_rx_desc_pushed;

	// generating packet IDs
	uint16_t		m_n_ip_id_base;
	uint16_t		m_n_ip_id_offset;

	mgid_ref_count_map_t	m_attach_mc_grp_ref_cnt;

	void 			configure(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual void		prepare_ibv_qp(struct ibv_qp_init_attr& qp_init_attr) = 0;

	void 			validate_raw_qp_privliges();
};


class qp_mgr_eth : public qp_mgr
{
public:
	qp_mgr_eth(const ring* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
			struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t vlan) :
		qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_vlan(vlan) { configure(p_rx_comp_event_channel); };

	virtual void 		modify_qp_to_ready_state();
	virtual uint16_t	get_partiton() const { return m_vlan; };

protected:
	virtual void		prepare_ibv_qp(struct ibv_qp_init_attr& qp_init_attr);
private:
	const uint16_t 		m_vlan;
};


class qp_mgr_ib : public qp_mgr
{
public:
	qp_mgr_ib(const ring* p_ring, const ib_ctx_handler* p_context, const uint8_t port_num,
			struct ibv_comp_channel* p_rx_comp_event_channel, const uint32_t tx_num_wr, const uint16_t pkey) :
		qp_mgr(p_ring, p_context, port_num, tx_num_wr), m_pkey(pkey) { update_pkey_index(); configure(p_rx_comp_event_channel); };

	virtual void 		modify_qp_to_ready_state();
	virtual uint16_t	get_partiton() const { return m_pkey; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	virtual uint16_t	get_pkey_index() const { return m_pkey_index; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

protected:
	virtual void		prepare_ibv_qp(struct ibv_qp_init_attr& qp_init_attr);

private:
	const uint16_t 		m_pkey;
	uint16_t 		m_pkey_index;

	void 			update_pkey_index();
};

#endif
