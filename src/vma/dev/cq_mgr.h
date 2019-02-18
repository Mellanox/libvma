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


#ifndef CQ_MGR_H
#define CQ_MGR_H

#include "vma/ib/base/verbs_extra.h"
#include "utils/atomic.h"
#include "vma/dev/qp_mgr.h"
#include "vma/dev/ib_ctx_handler.h"
#include "vma/util/sys_vars.h"
#include "vma/util/hash_map.h"
#include "vma/util/vma_stats.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/vma_lwip.h"
#include "vma/vma_extra.h"


class net_device_mgr;
class ring;
class qp_mgr;
class ring_simple;

#define LOCAL_IF_INFO_INVALID (local_if_info_t){0,0}

struct cq_request_info_t {
	struct ibv_device*   p_ibv_device;
	struct ibv_context*  p_ibv_context;
	int                  n_port;
	qp_mgr*              p_qp_mgr;
};

struct buff_lst_info_t {
	mem_buf_desc_t*   buff_lst;
	uint32_t          n_buff_num;
};

typedef std::pair<uint32_t, uint32_t> local_if_info_key_t;

typedef struct local_if_info_t {
	in_addr_t   addr;
	uint32_t    attached_grp_ref_cnt;
} local_if_info_t;

struct qp_rec {
	qp_mgr  *qp;
	int     debt;
};

// Class cq_mgr
//
class cq_mgr
{
	friend class ring; // need to expose the m_n_global_sn only to ring 
	friend class ring_simple; // need to expose the m_n_global_sn only to ring
	friend class ring_bond; // need to expose the m_n_global_sn only to ring

public:
	cq_mgr(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler,
	       int cq_size, struct ibv_comp_channel *p_comp_event_channel,
	       bool is_rx, bool config=true);
	virtual ~cq_mgr();

	void configure(int cq_size);

	ibv_cq *get_ibv_cq_hndl();
	int	get_channel_fd();
	// ack events and rearm CQ
	int ack_and_request_notification();
	/**
	 * Arm the managed CQ's notification channel
	 * Calling this more then once without get_event() will return without
	 * doing anything (arm flag is changed to true on first call). 
	 * This call will also check if a wce was processes between the 
	 * last poll and this arm request - if true it will not arm the CQ 
	 * @return ==0 cq is armed 
	 *         ==1 cq not armed (cq poll_sn out of sync)
	 *         < 0 on error
	 */
	int	request_notification(uint64_t poll_sn);

	/**
	 * Block on the CQ's notification channel for the next event and process
	 * it before exiting.
	 *
	 * @return >=0 number of processed wce
	 *         < 0 error or if channel not armed or channel would block
	 *             (on non-blocked channel) (some other thread beat you to it)
	 */
	int	wait_for_notification_and_process_element(uint64_t* p_cq_poll_sn,
	   	                                          void* pv_fd_ready_array = NULL);

	/**
	 * This will poll n_num_poll time on the cq or stop early if it gets
	 * a wce (work completion element). If a wce was found 'processing' will
	 * occur.
	 * @return >=0 number of wce processed
	 *         < 0 error
	 */
	virtual int	poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	virtual int	poll_and_process_element_tx(uint64_t* p_cq_poll_sn);
	virtual int	poll_and_process_element_rx(mem_buf_desc_t **p_desc_lst);

	/**
	 * This will check if the cq was drained, and if it wasn't it will drain it.
	 * @param restart - In case of restart - don't process any buffer
	 * @return  >=0 number of wce processed
	 *          < 0 error
	 */
	virtual int	drain_and_proccess(uintptr_t* p_recycle_buffers_last_wr_id = NULL);

	// CQ implements the Rx mem_buf_desc_owner.
	// These callbacks will be called for each Rx buffer that passed processed completion
	// Rx completion handling at the cq_mgr level is forwarding the packet to the ib_comm_mgr layer
	void	mem_buf_desc_completion_with_error(mem_buf_desc_t* p_rx_wc_buf_desc);
	void	mem_buf_desc_return_to_owner(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);

	virtual void	add_qp_rx(qp_mgr* qp);
	virtual void	del_qp_rx(qp_mgr *qp);
	virtual uint32_t	clean_cq();
	
	virtual void 	add_qp_tx(qp_mgr* qp);

	bool	reclaim_recv_buffers(descq_t *rx_reuse);
	bool	reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst);
	bool	reclaim_recv_buffers_no_lock(mem_buf_desc_t *rx_reuse_lst);
	int	reclaim_recv_single_buffer(mem_buf_desc_t* rx_reuse);

	//maps between qpn and vlan id to the local interface
	void	map_vlan_and_qpn_to_local_if(int qp_num, uint16_t vlan_id, in_addr_t local_if);

	//unmaps the qpn and vlan id
	void 	unmap_vlan_and_qpn(int qp_num, uint16_t vlan_id);

	virtual bool fill_cq_hw_descriptors(struct hw_cq_data &data) {NOT_IN_USE(data);return false;};
	virtual void get_cq_event(int count = 1) {NOT_IN_USE(count);};

protected:

	/**
	 * Poll the CQ that is managed by this object
	 * @p_wce pointer to array where to save the wce in
	 * @num_entries Size of the p_wce (max number of wce to poll at once)
	 * @p_cq_poll_sn global unique wce id that maps last wce polled
	 * @return Number of successfully polled wce
	 */
	virtual int     poll(vma_ibv_wc* p_wce, int num_entries, uint64_t* p_cq_poll_sn);
	void		compensate_qp_poll_failed();
	inline void     process_recv_buffer(mem_buf_desc_t* buff, void* pv_fd_ready_array = NULL);

	/* Process a WCE... meaning...
	 * - extract the mem_buf_desc from the wce.wr_id and then loop on all linked mem_buf_desc
	 *   and deliver them to their owner for further processing (sockinfo on Tx path and ib_conn_mgr on Rx path)
	 * - for Tx wce the data buffers will be released to the associated ring before the mem_buf_desc are returned
	 */
	mem_buf_desc_t* process_cq_element_tx(vma_ibv_wc* p_wce);
	mem_buf_desc_t* process_cq_element_rx(vma_ibv_wc* p_wce);
	void            reclaim_recv_buffer_helper(mem_buf_desc_t* buff);

	// Returns true if the given buffer was used,
	//false if the given buffer was not used.
	bool		compensate_qp_poll_success(mem_buf_desc_t* buff);
	inline uint32_t process_recv_queue(void* pv_fd_ready_array = NULL);

	virtual void	prep_ibv_cq(vma_ibv_cq_init_attr &attr) const;
	//returns list of buffers to the owner.
	void		process_tx_buffer_list(mem_buf_desc_t* p_mem_buf_desc);

	struct ibv_cq*		m_p_ibv_cq;
	bool			m_b_is_rx;
	descq_t			m_rx_queue;
	static uint64_t		m_n_global_sn;
	uint32_t		m_cq_id;
	uint32_t		m_n_cq_poll_sn;
	ring_simple*		m_p_ring;
	uint32_t		m_n_wce_counter;
	bool			m_b_was_drained;
	bool			m_b_is_rx_hw_csum_on;
	qp_rec			m_qp_rec;
	const uint32_t		m_n_sysvar_cq_poll_batch_max;
	const uint32_t		m_n_sysvar_progress_engine_wce_max;
	cq_stats_t* 		m_p_cq_stat;
	transport_type_t	m_transport_type;
	mem_buf_desc_t*		m_p_next_rx_desc_poll;
	const uint32_t		m_n_sysvar_rx_prefetch_bytes_before_poll;
	const uint32_t		m_n_sysvar_rx_prefetch_bytes;
	size_t			m_sz_transport_header;
	ib_ctx_handler*		m_p_ib_ctx_handler;
	const uint32_t		m_n_sysvar_rx_num_wr_to_post_recv;
private:
	struct ibv_comp_channel *m_comp_event_channel;
	bool			m_b_notification_armed;
	const uint32_t		m_n_sysvar_qp_compensation_level;
	const uint32_t		m_rx_lkey;
	const bool		m_b_sysvar_cq_keep_qp_full;
	descq_t			m_rx_pool;
	int32_t			m_n_out_of_free_bufs_warning;
	cq_stats_t 		m_cq_stat_static;
	static atomic_t		m_n_cq_id_counter;

	/* This fields are needed to track internal memory buffers
	 * represented as struct vma_buff_t
	 * from user application by special VMA extended API
	 */
	mem_buf_desc_t*		m_rx_buffs_rdy_for_free_head;
	mem_buf_desc_t*		m_rx_buffs_rdy_for_free_tail;

	void		handle_tcp_ctl_packets(uint32_t rx_processed, void* pv_fd_ready_array);

	// requests safe_mce_sys().qp_compensation_level buffers from global pool
	bool 		request_more_buffers() __attribute__((noinline));

	// returns safe_mce_sys().qp_compensation_level buffers to global pool
	void 		return_extra_buffers() __attribute__((noinline));

	void		statistics_print();

	//Finds and sets the local if to which the buff is addressed (according to qpn and vlan id).
	inline void	find_buff_dest_local_if(mem_buf_desc_t * buff);

	//Finds and sets the vma if to which the buff is addressed (according to qpn).
	inline void	find_buff_dest_vma_if_ctx(mem_buf_desc_t * buff);

	void		process_cq_element_log_helper(mem_buf_desc_t* p_mem_buf_desc, vma_ibv_wc* p_wce);

	virtual int	req_notify_cq() {
		return ibv_req_notify_cq(m_p_ibv_cq, 0);
	};
};

// Helper gunction to extract the Tx cq_mgr from the CQ event,
// Since we have a single TX CQ comp channel for all cq_mgr's, it might not be the active_cq object
cq_mgr* get_cq_mgr_from_cq_event(struct ibv_comp_channel* p_cq_channel);

#endif //CQ_MGR_H
