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


#ifndef CQ_MGR_H
#define CQ_MGR_H

#include <map>
#include <deque>

#include "vma/util/sys_vars.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/atomic.h"
#include "vma/util/hash_map.h"
#include "vma/util/vma_stats.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/vma_lwip.h"
#include "vma/dev/ib_ctx_handler.h"


class net_device_mgr;
class ring;
class qp_mgr;

#define LOCAL_IF_INFO_INVALID (local_if_info_t){0,0}

struct cq_request_info_t {
	struct ibv_device* 	p_ibv_device;
	struct ibv_context* 	p_ibv_context;
	int 			n_port;
	qp_mgr* 		p_qp_mgr;
};

struct buff_lst_info_t {
	mem_buf_desc_t*		buff_lst;
	uint32_t		n_buff_num;
};

typedef std::pair<uint32_t, uint32_t> local_if_info_key_t;

typedef struct local_if_info_t {
	in_addr_t		addr;
	uint32_t		attached_grp_ref_cnt;
} local_if_info_t;

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

inline bool
operator==(local_if_info_key_t const& key1, local_if_info_key_t const& key2) {
	return key1.first == key2.first &&  key1.second == key2.second;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

struct qp_rec {
	qp_mgr		*qp;
	int		debth;
};


// Class cq_mgr
//
class cq_mgr
{
	friend class ring; // need to expose the m_n_global_sn only to ring 

public:

	cq_mgr(ring* p_ring, ib_ctx_handler* p_ib_ctx_handler, int cq_size, struct ibv_comp_channel* p_comp_event_channel, bool is_rx);
	~cq_mgr();

	ibv_cq *get_ibv_cq_hndl();
	int	get_channel_fd();

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
	int	poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	int	poll_and_process_element_tx(uint64_t* p_cq_poll_sn);

	/**
	 * This will check if the cq was drained, and if it wasn't it will drain it.
	 * @param restart - In case of restart - don't process any buffer
	 * @return  >=0 number of wce processed
	 *          < 0 error
	 */
	int	drain_and_proccess(bool b_recycle_buffers = false);

	// CQ implements the Rx mem_buf_desc_owner.
	// These callbacks will be called for each Rx buffer that passed processed completion
	// Rx completion handling at the cq_mgr level is forwarding the packet to the ib_comm_mgr layer
	void	mem_buf_desc_completion_with_error(mem_buf_desc_t* p_rx_wc_buf_desc);
	void	mem_buf_desc_return_to_owner(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array = NULL);

	void	add_qp_rx(qp_mgr* qp);
	void	del_qp_rx(qp_mgr *qp);
	
	void 	add_qp_tx(qp_mgr* qp);

	bool	reclaim_recv_buffers(descq_t *rx_reuse);
	bool	reclaim_recv_buffers_no_lock(descq_t *rx_reuse);
	bool 	reclaim_recv_buffers(mem_buf_desc_t *rx_reuse_lst);

	//maps between qpn and vlan id to the local interface
	void	map_vlan_and_qpn_to_local_if(int qp_num, uint16_t vlan_id, in_addr_t local_if);

	//unmaps the qpn and vlan id
	void 	unmap_vlan_and_qpn(int qp_num, uint16_t vlan_id);

	void 	modify_cq_moderation(uint32_t period, uint32_t count);

private:
	ring*				m_p_ring;
	ib_ctx_handler*			m_p_ib_ctx_handler;
	bool				m_b_is_rx;
	struct ibv_comp_channel*	m_comp_event_channel;
	struct ibv_cq*			m_p_ibv_cq;
	bool				m_b_notification_armed;
	bool				m_b_was_drained;
	uint32_t			m_n_wce_counter;
	qp_rec				m_qp_rec;

	mem_buf_desc_t*			m_p_next_rx_desc_poll;

	descq_t				m_rx_queue;
	descq_t				m_rx_pool;
	int32_t				m_n_out_of_free_bufs_warning;
	cq_stats_t* 			m_p_cq_stat;
	cq_stats_t 			m_cq_stat_static;
	uint32_t			m_cq_id;
	uint32_t 			m_n_cq_poll_sn;
	transport_type_t		m_transport_type;
	size_t				m_sz_transport_header;

	int 				m_buffer_miss_count; // for stats
	int 				m_buffer_total_count; // for stats
	int 				m_buffer_prev_id; // for stats
	
	static atomic_t			m_n_cq_id_counter;
	static uint64_t			m_n_global_sn;

	/**
	 * Poll the CQ that is managed by this object 
	 * @p_wce pointer to array where to save the wce in
	 * @num_entries Size of the p_wce (max number of wce to poll at once)
	 * @p_cq_poll_sn global unique wce id that maps last wce polled
	 * @return Number of successfully polled wce
	 */
	int		poll(ibv_wc* p_wce, int num_entries, uint64_t* p_cq_poll_sn);

	/* Process a WCE... meaning...
	 * - extract the mem_buf_desc from the wce.wr_id and then loop on all linked mem_buf_desc
	 *   and deliver them to their owner for further processing (sockinfo on Tx path and ib_conn_mgr on Rx path)
	 * - for Tx wce the data buffers will be released to the associated ring before the mem_buf_desc are returned
	 */
	mem_buf_desc_t*	process_cq_element_tx(struct ibv_wc* p_wce);
	mem_buf_desc_t*	process_cq_element_rx(struct ibv_wc* p_wce);

	/**
	 * Helper function wrapping the poll and the process functionality in single call
	 */
	int		poll_and_process_helper_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array = NULL);
	int		poll_and_process_helper_tx(uint64_t* p_cq_poll_sn);

	// Returns true if the given buffer was used,
	//false if the given buffer was not used.
	bool 		compensate_qp_post_recv(mem_buf_desc_t* buff);
	void		reclaim_recv_buffer_helper(mem_buf_desc_t* buff);
	uint32_t 	process_recv_queue(void* pv_fd_ready_array = NULL);
	inline void	process_recv_buffer(mem_buf_desc_t* buff, void* pv_fd_ready_array = NULL);

	//returns list of buffers to the owner.
	void		process_tx_buffer_list(mem_buf_desc_t* p_mem_buf_desc);

	// requests mce_sys.qp_compensation_level buffers from global pool
	bool 		request_more_buffers() __attribute__((noinline));

	// returns mce_sys.qp_compensation_level buffers to global pool
	void 		return_extra_buffers() __attribute__((noinline));

	// post-recv to a qp
	inline int 	post_recv_qp(qp_rec *qprec, mem_buf_desc_t *buff);

	void		statistics_print();

	//Finds and sets the local if to which the buff is addressed (according to qpn and vlan id).
	inline void	find_buff_dest_local_if(mem_buf_desc_t * buff);

	//Finds and sets the vma if to which the buff is addressed (according to qpn).
	inline void 	find_buff_dest_vma_if_ctx(mem_buf_desc_t * buff);

	void		process_cq_element_log_helper(mem_buf_desc_t* p_mem_buf_desc, struct ibv_wc* p_wce);
};

// Helper gunction to extract the Tx cq_mgr from the CQ event,
// Since we have a single TX CQ comp channel for all cq_mgr's, it might not be the active_cq object
cq_mgr* get_cq_mgr_from_cq_event(struct ibv_comp_channel* p_cq_channel);

#endif //CQ_MGR_H
