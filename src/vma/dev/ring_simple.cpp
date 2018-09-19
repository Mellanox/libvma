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


#include "ring_simple.h"

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include "utils/bullseye.h"
#include "vma/util/utils.h"
#include "vma/util/valgrind.h"
#include "vma/util/sg_array.h"
#include "vma/proto/ip_frag.h"
#include "vma/proto/L2_address.h"
#include "vma/proto/igmp_mgr.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/dev/cq_mgr.h"
#if defined(DEFINED_DIRECT_VERBS)
#include "qp_mgr_eth_mlx5.h"
#endif

#undef  MODULE_NAME
#define MODULE_NAME "ring_simple"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define ALIGN_WR_DOWN(_num_wr_) (max(32, ((_num_wr_      ) & ~(0xf))))
#define RING_TX_BUFS_COMPENSATE 256

#define RING_LOCK_AND_RUN(__lock__, __func_and_params__) 	\
		__lock__.lock(); __func_and_params__; __lock__.unlock();

#define RING_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) 	\
		__lock__.lock(); ret = __func_and_params__; __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) \
		if (!__lock__.trylock()) { ret = __func_and_params__; __lock__.unlock(); } \
		else { errno = EBUSY; }

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void ring_simple::send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(ret)) {
		// Error during post_send, reclaim the tx buffer
		if(p_send_wqe) {
			mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
			mem_buf_tx_release(p_mem_buf_desc, true);
		}
	}
	else {
		// Update TX statistics
		sg_array sga(p_send_wqe->sg_list, p_send_wqe->num_sge);
		m_p_ring_stat->n_tx_byte_count += sga.length();
		++m_p_ring_stat->n_tx_pkt_count;

		// Decrease counter in order to keep track of how many missing buffers we have when
		// doing ring->restart() and then drain_tx_buffers_to_buffer_pool()
		m_missing_buf_ref_count--;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

qp_mgr* ring_eth::create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel)
{
#if defined(DEFINED_DIRECT_VERBS)
	if (qp_mgr::is_lib_mlx5(((ib_ctx_handler*)ib_ctx)->get_ibname())) {
		return new qp_mgr_eth_mlx5(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), get_partition());
	}
#endif
	return new qp_mgr_eth(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), get_partition());
}

bool ring_eth::is_ratelimit_supported(struct vma_rate_limit_t &rate_limit)
{
#ifdef DEFINED_IBV_EXP_QP_RATE_LIMIT
	return m_p_qp_mgr->is_ratelimit_supported(m_p_ib_ctx->get_ibv_device_attr(), rate_limit);
#else
	NOT_IN_USE(rate_limit);
	return false;
#endif
}

qp_mgr* ring_ib::create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel)
{
	return new qp_mgr_ib(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), get_partition());
}

bool ring_ib::is_ratelimit_supported(struct vma_rate_limit_t &rate_limit)
{
	NOT_IN_USE(rate_limit);
	return false;
}

ring_simple::ring_simple(int if_index, ring* parent, ring_type_t type):
	ring_slave(if_index, parent, type),
	m_p_ib_ctx(NULL),
	m_p_qp_mgr(NULL),
	m_p_cq_mgr_rx(NULL),
	m_lock_ring_rx("ring_simple:lock_rx"),
	m_p_cq_mgr_tx(NULL),
	m_lock_ring_tx("ring_simple:lock_tx"),
	m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait"), m_tx_num_bufs(0), m_tx_num_wr(0), m_tx_num_wr_free(0),
	m_b_qp_tx_first_flushed_completion_handled(false), m_missing_buf_ref_count(0),
	m_tx_lkey(0),
	m_gro_mgr(safe_mce_sys().gro_streams_max, MAX_GRO_BUFS), m_up(false),
	m_p_rx_comp_event_channel(NULL), m_p_tx_comp_event_channel(NULL), m_p_l2_addr(NULL)
	, m_b_sysvar_eth_mc_l2_only_rules(safe_mce_sys().eth_mc_l2_only_rules)
	, m_b_sysvar_mc_force_flowtag(safe_mce_sys().mc_force_flowtag)
#ifdef DEFINED_SOCKETXTREME
	, m_rx_buffs_rdy_for_free_head(NULL) 
	, m_rx_buffs_rdy_for_free_tail(NULL) 
#endif // DEFINED_SOCKETXTREME		
	, m_flow_tag_enabled(false)
{
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	const slave_data_t * p_slave = p_ndev->get_slave(get_if_index());

	ring_logdbg("new ring_simple()");

	/* m_p_ib_ctx, m_tx_lkey should be initialized to be used
	 * in ring_eth_direct, ring_eth_cb constructors
	 */
	BULLSEYE_EXCLUDE_BLOCK_START
	m_p_ib_ctx = p_slave->p_ib_ctx;
	if(m_p_ib_ctx == NULL) {
		ring_logpanic("m_p_ib_ctx = NULL. It can be related to wrong bonding configuration");
	}

	m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(m_p_ib_ctx);
	if (m_tx_lkey == 0) {
		__log_info_panic("invalid lkey found %lu", m_tx_lkey);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	/* initialize m_partition in ring_eth() or ring_ib() */
	m_partition = 0;

	/* initialization basing on ndev information */
	m_local_if = p_ndev->get_local_addr();
	m_mtu = p_ndev->get_mtu();

	 // coverity[uninit_member]
	m_tx_pool.set_id("ring_simple (%p) : m_tx_pool", this);
}

ring_simple::~ring_simple()
{
	ring_logdbg("delete ring_simple()");

	// Go over all hash and for each flow: 1.Detach from qp 2.Delete related rfs object 3.Remove flow from hash
	m_lock_ring_rx.lock();
	flow_udp_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	// Allow last few post sends to be sent by HCA.
	// Was done in order to allow iperf's FIN packet to be sent.
	usleep(25000);

        /* coverity[double_lock] TODO: RM#1049980 */
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

#ifdef DEFINED_SOCKETXTREME	
	if (m_rx_buffs_rdy_for_free_head) {
		m_p_cq_mgr_rx->socketxtreme_reclaim_recv_buffer_helper(m_rx_buffs_rdy_for_free_head);
		m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = NULL;
	}
#endif // DEFINED_SOCKETXTREME		

	if (m_p_qp_mgr) {
		// 'down' the active QP/CQ
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->down();
	}
	// Release QP/CQ resources
	delete m_p_qp_mgr;

	delete_l2_address();

	// Delete the rx channel fd from the global fd collection
	if (g_p_fd_collection) {
		if (m_p_rx_comp_event_channel) {
			g_p_fd_collection->del_cq_channel_fd(m_p_rx_comp_event_channel->fd, true);
		}
		if (m_p_tx_comp_event_channel) {
			g_p_fd_collection->del_cq_channel_fd(m_p_tx_comp_event_channel->fd, true);
		}
	}

	if (m_p_rx_comp_event_channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_rx_comp_event_channel)) {
			ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
	}

	delete[] m_p_n_rx_channel_fds;

	ring_logdbg("Tx buffer poll: free count = %u, sender_has = %d, total = %d, %s (%d)",
			m_tx_pool.size(), m_missing_buf_ref_count, m_tx_num_bufs,
			((m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count) ?
					"bad accounting!!" : "good accounting"),
					(m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count));
	ring_logdbg("Tx WR num: free count = %d, total = %d, %s (%d)",
			m_tx_num_wr_free, m_tx_num_wr,
			((m_tx_num_wr - m_tx_num_wr_free) ? "bad accounting!!":"good accounting"), (m_tx_num_wr - m_tx_num_wr_free));
	ring_logdbg("Rx buffer pool: %d free global buffers available", m_tx_pool.size());

	// Release Tx buffers
	g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());

	// Release verbs resources
	if (m_p_tx_comp_event_channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_tx_comp_event_channel)) {
			ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
		m_p_tx_comp_event_channel = NULL;
	}

	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_ring_rx.unlock();
	m_lock_ring_tx.unlock();

	ring_logdbg("delete ring_simple() completed");
}

void ring_simple::create_resources()
{
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	const slave_data_t * p_slave = p_ndev->get_slave(get_if_index());

	save_l2_address(p_slave->p_L2_addr);
	m_p_tx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context());
	if (m_p_tx_comp_event_channel == NULL) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "ibv_create_comp_channel for tx failed. m_p_tx_comp_event_channel = %p (errno=%d %m)", m_p_tx_comp_event_channel, errno);
		if (errno == EMFILE) {
			VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "did we run out of file descriptors? traffic may not be offloaded, increase ulimit -n");
		}
		throw_vma_exception("create event channel failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
	// Check device capabilities for max QP work requests
	uint32_t max_qp_wr = ALIGN_WR_DOWN(m_p_ib_ctx->get_ibv_device_attr()->max_qp_wr - 1);
	m_tx_num_wr = safe_mce_sys().tx_num_wr;
	if (m_tx_num_wr > max_qp_wr) {
		ring_logwarn("Allocating only %d Tx QP work requests while user requested %s=%d for QP on interface %d.%d.%d.%d",
			max_qp_wr, SYS_VAR_TX_NUM_WRE, m_tx_num_wr);
		m_tx_num_wr = max_qp_wr;
	}

	m_tx_num_wr_free = m_tx_num_wr;

	memset(&m_cq_moderation_info, 0, sizeof(m_cq_moderation_info));

	m_flow_tag_enabled = m_p_ib_ctx->get_flow_tag_capability();

	m_p_rx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context()); // ODED TODO: Adjust the ibv_context to be the exact one in case of different devices
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_rx_comp_event_channel == NULL) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "ibv_create_comp_channel for rx failed. p_rx_comp_event_channel = %p (errno=%d %m)", m_p_rx_comp_event_channel, errno);
		if (errno == EMFILE) {
			VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "did we run out of file descriptors? traffic may not be offloaded, increase ulimit -n");
		}
		throw_vma_exception("create event channel failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
	m_p_n_rx_channel_fds = new int[1];
	m_p_n_rx_channel_fds[0] = m_p_rx_comp_event_channel->fd;
	// Add the rx channel fd to the global fd collection
	if (g_p_fd_collection) {
		// Create new cq_channel info in the global fd collection
		g_p_fd_collection->add_cq_channel_fd(m_p_n_rx_channel_fds[0], this);
		g_p_fd_collection->add_cq_channel_fd(m_p_tx_comp_event_channel->fd, this);
	}

#if 0
TODO:
The following 3 lines were copied form below. Can it be OK for experimental if these lines
remain below as in master?
	m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(p_ring_info->p_ib_ctx);

	request_more_tx_buffers(RING_TX_BUFS_COMPENSATE);
	m_tx_num_bufs = m_tx_pool.size();
#endif // 0
	m_p_qp_mgr = create_qp_mgr(m_p_ib_ctx, p_slave->port_num, m_p_rx_comp_event_channel);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_qp_mgr == NULL) {
		ring_logerr("Failed to allocate qp_mgr!");
		throw_vma_exception("create qp failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// save cq_mgr pointers
	m_p_cq_mgr_rx = m_p_qp_mgr->get_rx_cq_mgr();
	m_p_cq_mgr_tx = m_p_qp_mgr->get_tx_cq_mgr();

	init_tx_buffers(RING_TX_BUFS_COMPENSATE);

	if (safe_mce_sys().cq_moderation_enable) {
		modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
	}

	if (p_slave->active) {
		// 'up' the active QP/CQ resource
		m_up = true;
		m_p_qp_mgr->up();
	}

	ring_logdbg("new ring_simple() completed");
}

bool ring_simple::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink *sink)
{
	rfs* p_rfs;
	rfs* p_tmp_rfs = NULL;
	sockinfo* si = static_cast<sockinfo*> (sink);
	uint32_t flow_tag_id = 0; // spec will not be attached to rule

	ring_logdbg("flow: %s, with sink (%p), m_flow_tag_enabled: %d",
		    flow_spec_5t.to_str(), si, m_flow_tag_enabled);

	if( si == NULL )
		return false;

	// If m_flow_tag_enabled==true then flow tag is supported and flow_tag_id is guaranteed
	// to have a !0 value which will results in a flow id being added to the flow spec.
	// Otherwise, flow tag is not supported, flow_tag_id=0 and no flow id will be set in the flow spec.
	if (m_flow_tag_enabled) {
		// sockfd=0 is valid too but flow_tag_id=0 is invalid, increment it
		// effectively limiting our sockfd range to FLOW_TAG_MASK-1
		int flow_tag_id_candidate = si->get_fd() + 1;
		if (flow_tag_id_candidate > 0) {
			flow_tag_id = flow_tag_id_candidate & FLOW_TAG_MASK;
			if ((uint32_t)flow_tag_id_candidate != flow_tag_id) {
				// tag_id is out of the range by mask, will not use it
				ring_logdbg("flow_tag disabled as tag_id: %d is out of mask (%x) range!",
					    flow_tag_id, FLOW_TAG_MASK);
				flow_tag_id = FLOW_TAG_MASK;
			}
			ring_logdbg("sock_fd:%d enabled:%d with id:%d",
				    flow_tag_id_candidate-1, m_flow_tag_enabled, flow_tag_id);
		} else {
			flow_tag_id = FLOW_TAG_MASK; // FLOW_TAG_MASK - modal, FT to be attached but will not be used
			ring_logdbg("flow_tag:%d disabled as flow_tag_id_candidate:%d", flow_tag_id, flow_tag_id_candidate);
		}
	}

	/*
	 * //auto_unlocker lock(m_lock_ring_rx);
	 * todo instead of locking the whole function which have many "new" calls,
	 * we'll only lock the parts that touch the ring members.
	 * if some of the constructors need the ring locked, we need to modify
	 * and add separate functions for that, which will be called after ctor with ring locked.
	 * currently we assume the ctors does not require the ring to be locked.
	 */
	m_lock_ring_rx.lock();

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_key_t key_udp_uc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		if (flow_tag_id && si->flow_in_reuse()) {
			flow_tag_id = FLOW_TAG_MASK;
			ring_logdbg("UC flow tag for socketinfo=%p is disabled: SO_REUSEADDR or SO_REUSEPORT were enabled", si);
		}
		p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
		if (p_rfs == NULL) {
			// No rfs object exists so a new one must be created and inserted in the flow map
			m_lock_ring_rx.unlock();
			try {
				p_tmp_rfs = new rfs_uc(&flow_spec_5t, this, NULL, flow_tag_id);
			} catch(vma_exception& e) {
				ring_logerr("%s", e.message);
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_tmp_rfs == NULL) {
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_lock_ring_rx.lock();
			p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_udp_uc_map.set(key_udp_uc, p_rfs);
			}
		}
	} else if (flow_spec_5t.is_udp_mc()) {
		flow_spec_udp_key_t key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());

		if (flow_tag_id) {
			if (m_b_sysvar_mc_force_flowtag || !si->flow_in_reuse()) {
				ring_logdbg("MC flow tag ID=%d for socketinfo=%p is enabled: force_flowtag=%d, SO_REUSEADDR | SO_REUSEPORT=%d",
					flow_tag_id, si, m_b_sysvar_mc_force_flowtag, si->flow_in_reuse());
			} else {
				flow_tag_id = FLOW_TAG_MASK;
				ring_logdbg("MC flow tag for socketinfo=%p is disabled: force_flowtag=0, SO_REUSEADDR or SO_REUSEPORT were enabled", si);
			}
		}
		// Note for CX3:
		// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
		// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
		// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
		rfs_rule_filter* l2_mc_ip_filter = NULL;
		if ((m_transport_type == VMA_TRANSPORT_IB && 0 == m_p_qp_mgr->get_underly_qpn()) || m_b_sysvar_eth_mc_l2_only_rules) {
			rule_filter_map_t::iterator l2_mc_iter = m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip);
			if (l2_mc_iter == m_l2_mc_ip_attach_map.end()) { // It means that this is the first time attach called with this MC ip
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = 1;
			} else {
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = ((l2_mc_iter->second.counter) + 1);
			}
		}
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			m_lock_ring_rx.unlock();
			if ((m_transport_type == VMA_TRANSPORT_IB && 0 == m_p_qp_mgr->get_underly_qpn()) || m_b_sysvar_eth_mc_l2_only_rules) {
				l2_mc_ip_filter = new rfs_rule_filter(m_l2_mc_ip_attach_map, key_udp_mc.dst_ip, flow_spec_5t);
			}
			try {
				p_tmp_rfs = new rfs_mc(&flow_spec_5t, this, l2_mc_ip_filter, flow_tag_id);
			} catch(vma_exception& e) {
				ring_logerr("%s", e.message);
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_tmp_rfs == NULL) {
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_lock_ring_rx.lock();
			p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_udp_mc_map.set(key_udp_mc, p_rfs);
			}
		}
	} else if (flow_spec_5t.is_tcp()) {
		flow_spec_tcp_key_t key_tcp(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
				flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
		rule_key_t rule_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		rfs_rule_filter* tcp_dst_port_filter = NULL;
		if (safe_mce_sys().tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(rule_key.key);
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				m_tcp_dst_port_attach_map[rule_key.key].counter = 1;
			} else {
				m_tcp_dst_port_attach_map[rule_key.key].counter = ((tcp_dst_port_iter->second.counter) + 1);
			}
		}

		p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			m_lock_ring_rx.unlock();
			if (safe_mce_sys().tcp_3t_rules) {
				flow_tuple tcp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(), 0, 0, flow_spec_5t.get_protocol());
				tcp_dst_port_filter = new rfs_rule_filter(m_tcp_dst_port_attach_map, rule_key.key, tcp_3t_only);
			}
			if(safe_mce_sys().gro_streams_max && flow_spec_5t.is_5_tuple()) {
				// When the gro mechanism is being used, packets must be processed in the rfs
				// layer. This must not be bypassed by using flow tag.
				if (flow_tag_id) {
					flow_tag_id = FLOW_TAG_MASK;
					ring_logdbg("flow_tag_id = %d is disabled to enable TCP GRO socket to be processed on RFS!", flow_tag_id);
				}
				p_tmp_rfs = new rfs_uc_tcp_gro(&flow_spec_5t, this, tcp_dst_port_filter, flow_tag_id);
			} else {
				try {
					p_tmp_rfs = new rfs_uc(&flow_spec_5t, this, tcp_dst_port_filter, flow_tag_id);
				} catch(vma_exception& e) {
					ring_logerr("%s", e.message);
					return false;
				}
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_tmp_rfs == NULL) {
				ring_logerr("Failed to allocate rfs!");
				return false;
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_rx.lock();
			p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
			if (p_rfs) {
				delete p_tmp_rfs;
			} else {
				p_rfs = p_tmp_rfs;
				m_flow_tcp_map.set(key_tcp, p_rfs);
			}
		}
	BULLSEYE_EXCLUDE_BLOCK_START
	} else {
		m_lock_ring_rx.unlock();
		ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	bool ret = p_rfs->attach_flow(sink);
	if (ret) {
		if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
			// A flow with FlowTag was attached succesfully, check stored rfs for fast path be tag_id
			si->set_flow_tag(flow_tag_id);
			ring_logdbg("flow_tag: %d registration is done!", flow_tag_id);
		}
		if (flow_spec_5t.is_tcp() && !flow_spec_5t.is_3_tuple()) {
			// save the single 5tuple TCP connected socket for improved fast path
			si->set_tcp_flow_is_5t();
			ring_logdbg("single 5T TCP update m_tcp_flow_is_5t m_flow_tag_enabled: %d", m_flow_tag_enabled);
		}
	} else {
		ring_logerr("attach_flow=%d failed!", ret);
	}
	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_ring_rx.unlock();
	return ret;
}

bool ring_simple::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	rfs* p_rfs = NULL;

	ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str(), sink);

	auto_unlocker lock(m_lock_ring_rx);

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_key_t key_udp_uc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_rfs->detach_flow(sink);
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_udp_uc_map.del(key_udp_uc))) {
				ring_logdbg("Could not find rfs object to delete in ring udp uc hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	} else if (flow_spec_5t.is_udp_mc()) {
		int keep_in_map = 1;
		flow_spec_udp_key_t key_udp_mc(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		if (m_transport_type == VMA_TRANSPORT_IB || m_b_sysvar_eth_mc_l2_only_rules) {
			rule_filter_map_t::iterator l2_mc_iter = m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (l2_mc_iter == m_l2_mc_ip_attach_map.end()) {
				ring_logdbg("Could not find matching counter for the MC group!");
			BULLSEYE_EXCLUDE_BLOCK_END
			} else {
				keep_in_map = m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = MAX(0 , ((l2_mc_iter->second.counter) - 1));
			}
		}
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		p_rfs->detach_flow(sink);
		if(!keep_in_map){
			m_l2_mc_ip_attach_map.erase(m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip));
		}
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_udp_mc_map.del(key_udp_mc))) {
				ring_logdbg("Could not find rfs object to delete in ring udp mc hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	} else if (flow_spec_5t.is_tcp()) {
		int keep_in_map = 1;
		flow_spec_tcp_key_t key_tcp(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_src_ip(),
				flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port());
		rule_key_t rule_key(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port());
		if (safe_mce_sys().tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(rule_key.key);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				ring_logdbg("Could not find matching counter for TCP src port!");
				BULLSEYE_EXCLUDE_BLOCK_END
			} else {
				keep_in_map = m_tcp_dst_port_attach_map[rule_key.key].counter = MAX(0 , ((tcp_dst_port_iter->second.counter) - 1));
			}
		}
		p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (p_rfs == NULL) {
			ring_logdbg("Could not find rfs object to detach!");
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		p_rfs->detach_flow(sink);
		if(!keep_in_map){
			m_tcp_dst_port_attach_map.erase(m_tcp_dst_port_attach_map.find(rule_key.key));
		}
		if (p_rfs->get_num_of_sinks() == 0) {
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!(m_flow_tcp_map.del(key_tcp))) {
				ring_logdbg("Could not find rfs object to delete in ring tcp hash map!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			delete p_rfs;
		}
	BULLSEYE_EXCLUDE_BLOCK_START
	} else {
		ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return true;
}

#ifndef IGMP_V3_MEMBERSHIP_REPORT
#define IGMP_V3_MEMBERSHIP_REPORT	0x22	/* V3 version of 0x11 */ /* ALEXR: taken from <linux/igmp.h> */
#endif

// String formating helper function for IGMP
const char* priv_igmp_type_tostr(uint8_t igmptype)
{
	switch (igmptype) {
	case IGMP_HOST_MEMBERSHIP_QUERY:        return "IGMP_QUERY";
	case IGMP_HOST_MEMBERSHIP_REPORT:       return "IGMPV1_REPORT";
	case IGMP_V2_MEMBERSHIP_REPORT:     	return "IGMPV2_REPORT";
	case IGMP_V3_MEMBERSHIP_REPORT:     	return "IGMPV3_REPORT";
	case IGMP_HOST_LEAVE_MESSAGE:           return "IGMP_LEAVE_MESSAGE";
	default:                                return "IGMP type UNKNOWN";
	}
}

// calling sockinfo callback with RFS bypass
static inline bool check_rx_packet(sockinfo *si, mem_buf_desc_t* p_rx_wc_buf_desc, void *fd_ready_array)
{
	// Dispatching: Notify new packet to the FIRST registered receiver ONLY
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET

	p_rx_wc_buf_desc->reset_ref_count();
	p_rx_wc_buf_desc->inc_ref_count();

	si->rx_input_cb(p_rx_wc_buf_desc,fd_ready_array);

#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET

	// Check packet ref_count to see the last receiver is interested in this packet
	if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
		// The sink will be responsible to return the buffer to CQ for reuse
		return true;
	}
	// Reuse this data buffer & mem_buf_desc
	return false;
}

// All CQ wce come here for some basic sanity checks and then are distributed to the correct ring handler
// Return values: false = Reuse this data buffer & mem_buf_desc
bool ring_simple::rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
{
	size_t sz_data = 0;
	size_t transport_header_len;
	uint16_t ip_hdr_len = 0;
	uint16_t ip_tot_len = 0;
	uint16_t ip_frag_off = 0;
	uint16_t n_frag_offset = 0;
	struct ethhdr* p_eth_h = (struct ethhdr*)(p_rx_wc_buf_desc->p_buffer);
	struct iphdr* p_ip_h = NULL;
	struct udphdr* p_udp_h = NULL;

#ifdef DEFINED_SOCKETXTREME
	NOT_IN_USE(ip_tot_len);
	NOT_IN_USE(ip_frag_off);
	NOT_IN_USE(n_frag_offset);
	NOT_IN_USE(p_udp_h);
#endif // DEFINED_SOCKETXTREME

	// Validate buffer size
	sz_data = p_rx_wc_buf_desc->sz_data;
	if (unlikely(sz_data > p_rx_wc_buf_desc->sz_buffer)) {
		if (sz_data == IP_FRAG_FREED) {
			ring_logfuncall("Rx buffer dropped - old fragment part");
		} else {
			ring_logwarn("Rx buffer dropped - buffer too small (%d, %d)", sz_data, p_rx_wc_buf_desc->sz_buffer);
		}
		return false;
	}

	m_cq_moderation_info.bytes += sz_data;
	++m_cq_moderation_info.packets;

	m_p_ring_stat->n_rx_byte_count += sz_data;
	++m_p_ring_stat->n_rx_pkt_count;

	// This is an internal function (within ring and 'friends'). No need for lock mechanism.
	if (likely(m_flow_tag_enabled && p_rx_wc_buf_desc->rx.flow_tag_id &&
		   p_rx_wc_buf_desc->rx.flow_tag_id != FLOW_TAG_MASK &&
		   !p_rx_wc_buf_desc->rx.is_sw_csum_need)) {
		sockinfo* si = NULL;
		// trying to get sockinfo per flow_tag_id-1 as it was incremented at attach
		// to allow mapping sockfd=0
		si = static_cast <sockinfo* >(g_p_fd_collection->get_sockfd(p_rx_wc_buf_desc->rx.flow_tag_id-1));

		if (likely((si != NULL) && si->flow_tag_enabled())) { 
			// will process packets with set flow_tag_id and enabled for the socket
			if (p_eth_h->h_proto == htons(ETH_P_8021Q)) {
				// Handle VLAN header as next protocol
				transport_header_len = ETH_VLAN_HDR_LEN;
			} else {
				transport_header_len = ETH_HDR_LEN;
			}
			p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
			ip_hdr_len = 20; //(int)(p_ip_h->ihl)*4;
			ip_tot_len = ntohs(p_ip_h->tot_len);

			ring_logfunc("FAST PATH Rx packet info: transport_header_len: %d, IP_header_len: %d L3 proto: %d tcp_5t: %d",
				transport_header_len, p_ip_h->ihl, p_ip_h->protocol, si->tcp_flow_is_5t());

			if (likely(si->tcp_flow_is_5t())) {
				// we have a single 5tuple TCP connected socket, use simpler fast path
				struct tcphdr* p_tcp_h = (struct tcphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

				// Update the L3 and L4 info
				p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.src.sin_port        = p_tcp_h->source;
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;

				p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.dst.sin_port        = p_tcp_h->dest;
				p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;
				// Update packet descriptor with datagram base address and length
				p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_tcp_h + sizeof(struct tcphdr);
				p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct tcphdr);
				p_rx_wc_buf_desc->rx.sz_payload    = ip_tot_len - ip_hdr_len - p_tcp_h->doff*4;

				p_rx_wc_buf_desc->rx.tcp.p_ip_h                 = p_ip_h;
				p_rx_wc_buf_desc->rx.tcp.p_tcp_h                = p_tcp_h;
				p_rx_wc_buf_desc->rx.tcp.n_transport_header_len = transport_header_len;
				p_rx_wc_buf_desc->rx.n_frags = 1;

				ring_logfunc("FAST PATH Rx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
					ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
					p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
					p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
					ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
					p_rx_wc_buf_desc->rx.sz_payload);

				return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);

			} else if (likely(p_ip_h->protocol==IPPROTO_UDP)) {
				// Get the udp header pointer + udp payload size
				p_udp_h = (struct udphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

				// Update the L3 and L4 info
				p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.src.sin_port        = p_udp_h->source;
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;

				p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
				p_rx_wc_buf_desc->rx.dst.sin_port        = p_udp_h->dest;
				p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;
				// Update packet descriptor with datagram base address and length
				p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_udp_h + sizeof(struct udphdr);
				p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct udphdr);
				p_rx_wc_buf_desc->rx.sz_payload    = ntohs(p_udp_h->len) - sizeof(struct udphdr);

				p_rx_wc_buf_desc->rx.udp.local_if        = m_local_if;
				p_rx_wc_buf_desc->rx.n_frags = 1;

				ring_logfunc("FAST PATH Rx UDP datagram info: src_port=%d, dst_port=%d, payload_sz=%d, csum=%#x",
					     ntohs(p_udp_h->source), ntohs(p_udp_h->dest), p_rx_wc_buf_desc->rx.sz_payload, p_udp_h->check);

				return check_rx_packet(si, p_rx_wc_buf_desc, pv_fd_ready_array);
			}
		}
	}

	// Validate transport type headers
	switch (m_transport_type) {
	case VMA_TRANSPORT_IB:
	{
		// Get the data buffer start pointer to the ipoib header pointer
		struct ipoibhdr* p_ipoib_h = (struct ipoibhdr*)(p_rx_wc_buf_desc->p_buffer + GRH_HDR_LEN);

		transport_header_len = GRH_HDR_LEN + IPOIB_HDR_LEN;

		// Validate IPoIB header
		if (unlikely(p_ipoib_h->ipoib_header != htonl(IPOIB_HEADER))) {
			ring_logwarn("Rx buffer dropped - Invalid IPOIB Header Type (%#x : %#x)", p_ipoib_h->ipoib_header, htonl(IPOIB_HEADER));
			return false;
		}
	}
	break;
	case VMA_TRANSPORT_ETH:
	{
//		printf("\nring_simple::rx_process_buffer\n");
//		{
//			struct ethhdr* p_eth_h = (struct ethhdr*)(p_rx_wc_buf_desc->p_buffer);
//
//			int i = 0;
//			printf("p_eth_h->h_dest [0]=%d, [1]=%d, [2]=%d, [3]=%d, [4]=%d, [5]=%d\n",
//					(uint8_t)p_eth_h->h_dest[0], (uint8_t)p_eth_h->h_dest[1], (uint8_t)p_eth_h->h_dest[2], (uint8_t)p_eth_h->h_dest[3], (uint8_t)p_eth_h->h_dest[4], (uint8_t)p_eth_h->h_dest[5]);
//			printf("p_eth_h->h_source [0]=%d, [1]=%d, [2]=%d, [3]=%d, [4]=%d, [5]=%d\n",
//					(uint8_t)p_eth_h->h_source[0], (uint8_t)p_eth_h->h_source[1], (uint8_t)p_eth_h->h_source[2], (uint8_t)p_eth_h->h_source[3], (uint8_t)p_eth_h->h_source[4], (uint8_t)p_eth_h->h_source[5]);
//
//			while(i++<62){
//				printf("%d, ", (uint8_t)p_rx_wc_buf_desc->p_buffer[i]);
//			}
//			printf("\n");
//		}

		uint16_t* p_h_proto = &p_eth_h->h_proto;

		ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source),
				htons(*p_h_proto));

		// Handle VLAN header as next protocol
		struct vlanhdr* p_vlan_hdr = NULL;
		uint16_t packet_vlan = 0;
		if (*p_h_proto == htons(ETH_P_8021Q)) {
			p_vlan_hdr = (struct vlanhdr*)((uint8_t*)p_eth_h + ETH_HDR_LEN);
			transport_header_len = ETH_VLAN_HDR_LEN;
			p_h_proto = &p_vlan_hdr->h_vlan_encapsulated_proto;
			packet_vlan = (htons(p_vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
		} else {
			transport_header_len = ETH_HDR_LEN;
		}

		//TODO: Remove this code when handling vlan in flow steering will be available. Change this code if vlan stripping is performed.
		if((m_partition & VLAN_VID_MASK) != packet_vlan) {
			ring_logfunc("Rx buffer dropped- Mismatched vlan. Packet vlan = %d, Local vlan = %d", packet_vlan, m_partition & VLAN_VID_MASK);
			return false;
		}

		// Validate IP header as next protocol
		if (unlikely(*p_h_proto != htons(ETH_P_IP))) {
			ring_logwarn("Rx buffer dropped - Invalid Ethr Type (%#x : %#x)", p_eth_h->h_proto, htons(ETH_P_IP));
			return false;
		}
	}
	break;
	default:
		ring_logwarn("Rx buffer dropped - Unknown transport type %d", m_transport_type);
		return false;
	}

	// Jump to IP header - Skip IB (GRH and IPoIB) or Ethernet (MAC) header sizes
	sz_data -= transport_header_len;

	// Validate size for IPv4 header
	if (unlikely(sz_data < sizeof(struct iphdr))) {
		ring_logwarn("Rx buffer dropped - buffer too small for IPv4 header (%d, %d)", sz_data, sizeof(struct iphdr));
		return false;
	}

	// Get the ip header pointer
	p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);

	// Drop all non IPv4 packets
	if (unlikely(p_ip_h->version != IPV4_VERSION)) {
		ring_logwarn("Rx packet dropped - not IPV4 packet (got version: %#x)", p_ip_h->version);
		return false;
	}

	// Check that received buffer size is not smaller then the ip datagram total size
	ip_tot_len = ntohs(p_ip_h->tot_len);
	if (unlikely(sz_data < ip_tot_len)) {
		ring_logwarn("Rx packet dropped - buffer too small for received datagram (RxBuf:%d IP:%d)", sz_data, ip_tot_len);
		ring_loginfo("Rx packet info (buf->%p, bufsize=%d), id=%d", p_rx_wc_buf_desc->p_buffer, p_rx_wc_buf_desc->sz_data, ntohs(p_ip_h->id));
		vlog_print_buffer(VLOG_INFO, "rx packet data: ", "\n", (const char*)p_rx_wc_buf_desc->p_buffer, min(112, (int)p_rx_wc_buf_desc->sz_data));
		return false;
	} else if (sz_data > ip_tot_len) {
		p_rx_wc_buf_desc->sz_data -= (sz_data - ip_tot_len);
	}

	// Read fragmentation parameters
	ip_frag_off = ntohs(p_ip_h->frag_off);
	n_frag_offset = (ip_frag_off & FRAGMENT_OFFSET) * 8;

	ring_logfunc("Rx ip packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, offset=%d, id=%d, proto=%s[%d] (local if: %d.%d.%d.%d)",
			NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
			(sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset, ntohs(p_ip_h->id),
			iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol,
			NIPQUAD(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr));

	// Check that the ip datagram has at least the udp header size for the first ip fragment (besides the ip header)
	ip_hdr_len = (int)(p_ip_h->ihl)*4;
	if (unlikely((n_frag_offset == 0) && (ip_tot_len < (ip_hdr_len + sizeof(struct udphdr))))) {
		ring_logwarn("Rx packet dropped - ip packet too small (%d bytes)- udp header cut!", ip_tot_len);
		return false;
	}

	// Handle fragmentation
	p_rx_wc_buf_desc->rx.n_frags = 1;
	if (unlikely((ip_frag_off & MORE_FRAGMENTS_FLAG) || n_frag_offset)) { // Currently we don't expect to receive fragments
		//for disabled fragments handling:
		/*ring_logwarn("Rx packet dropped - VMA doesn't support fragmentation in receive flow!");
		ring_logwarn("packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, frag_offset=%d, id=%d, proto=%s[%d], transport type=%s, (local if: %d.%d.%d.%d)",
				NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
				(sz_data > ip_tot_len ? ip_tot_len : sz_data), n_frag_offset, ntohs(p_ip_h->id),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol, (m_transport_type ? "ETH" : "IB"),
				NIPQUAD(local_addr));
		return false;*/
#if 1 //handle fragments
		// Update fragments descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_ip_h + ip_hdr_len;
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len;

		// Add ip fragment packet to out fragment manager
		mem_buf_desc_t* new_buf = NULL;
		int ret = -1;
		if (g_p_ip_frag_manager)
			ret = g_p_ip_frag_manager->add_frag(p_ip_h, p_rx_wc_buf_desc, &new_buf);
		if (ret < 0)  // Finished with error
			return false;
		if (!new_buf)  // This is fragment
			return true;

		// Re-calc all ip related values for new ip packet of head fragmentation list
		p_rx_wc_buf_desc = new_buf;
		p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
		ip_hdr_len = (int)(p_ip_h->ihl)*4;
		ip_tot_len = ntohs(p_ip_h->tot_len);

		mem_buf_desc_t *tmp;
		for (tmp = p_rx_wc_buf_desc; tmp; tmp = tmp->p_next_desc) {
			++p_rx_wc_buf_desc->rx.n_frags;
		}
#endif
	}

	if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_ip_checksum((unsigned short*)p_ip_h, p_ip_h->ihl * 2)) {
		return false; // false ip checksum
	}

//We want to enable loopback between processes for IB
#if 0
	//AlexV: We don't support Tx MC Loopback today!
	if (p_ip_h->saddr == m_local_if) {
		ring_logfunc("Rx udp datagram discarded - mc loop disabled");
		return false;
	}
#endif
	rfs* p_rfs = NULL;

	// Update the L3 info
	p_rx_wc_buf_desc->rx.src.sin_family      = AF_INET;
	p_rx_wc_buf_desc->rx.src.sin_addr.s_addr = p_ip_h->saddr;
	p_rx_wc_buf_desc->rx.dst.sin_family      = AF_INET;
	p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr = p_ip_h->daddr;

	switch (p_ip_h->protocol) {
	case IPPROTO_UDP:
	{
		// Get the udp header pointer + udp payload size
		p_udp_h = (struct udphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_udp_h + sizeof(struct udphdr);
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct udphdr);

		if (p_rx_wc_buf_desc->rx.is_sw_csum_need && p_udp_h->check && compute_udp_checksum_rx(p_ip_h, p_udp_h, p_rx_wc_buf_desc)) {
			return false; // false udp checksum
		}

		size_t sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);
		ring_logfunc("Rx udp datagram info: src_port=%d, dst_port=%d, payload_sz=%d, csum=%#x",
				ntohs(p_udp_h->source), ntohs(p_udp_h->dest), sz_payload, p_udp_h->check);

		// Update the L3 info
		p_rx_wc_buf_desc->rx.udp.local_if        = m_local_if;

		// Update the L4 info
		p_rx_wc_buf_desc->rx.src.sin_port        = p_udp_h->source;
		p_rx_wc_buf_desc->rx.dst.sin_port        = p_udp_h->dest;
		p_rx_wc_buf_desc->rx.sz_payload          = sz_payload;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		if (!(IN_MULTICAST_N(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr))) {      // This is UDP UC packet
			p_rfs = m_flow_udp_uc_map.get(flow_spec_udp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.dst.sin_port), NULL);
		} else {        // This is UDP MC packet
			p_rfs = m_flow_udp_mc_map.get(flow_spec_udp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.dst.sin_port), NULL);
		}
	}
	break;

	case IPPROTO_TCP:
	{
		// Get the tcp header pointer + tcp payload size
		struct tcphdr* p_tcp_h = (struct tcphdr*)((uint8_t*)p_ip_h + ip_hdr_len);

		if (p_rx_wc_buf_desc->rx.is_sw_csum_need && compute_tcp_checksum(p_ip_h, (unsigned short*) p_tcp_h)) {
			return false; // false tcp checksum
		}

		size_t sz_payload = ip_tot_len - ip_hdr_len - p_tcp_h->doff*4;
		ring_logfunc("Rx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
				ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
				p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
				p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
				ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
				sz_payload);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->rx.frag.iov_base = (uint8_t*)p_tcp_h + sizeof(struct tcphdr);
		p_rx_wc_buf_desc->rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct tcphdr);

		// Update the L4 info
		p_rx_wc_buf_desc->rx.src.sin_port        = p_tcp_h->source;
		p_rx_wc_buf_desc->rx.dst.sin_port        = p_tcp_h->dest;
		p_rx_wc_buf_desc->rx.sz_payload          = sz_payload;

		p_rx_wc_buf_desc->rx.tcp.p_ip_h = p_ip_h;
		p_rx_wc_buf_desc->rx.tcp.p_tcp_h = p_tcp_h;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		p_rfs = m_flow_tcp_map.get(flow_spec_tcp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->rx.src.sin_addr.s_addr, p_rx_wc_buf_desc->rx.dst.sin_port,
				p_rx_wc_buf_desc->rx.src.sin_port), NULL);

		p_rx_wc_buf_desc->rx.tcp.n_transport_header_len = transport_header_len;

		if (unlikely(p_rfs == NULL)) {	// If we didn't find a match for TCP 5T, look for a match with TCP 3T
			p_rfs = m_flow_tcp_map.get(flow_spec_tcp_key_t(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr, 0,
					p_rx_wc_buf_desc->rx.dst.sin_port, 0), NULL);
		}
	}
	break;

	case IPPROTO_IGMP:
	{
		struct igmp* p_igmp_h= (struct igmp*)((uint8_t*)p_ip_h + ip_hdr_len);
		NOT_IN_USE(p_igmp_h); /* to supress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
		ring_logdbg("Rx IGMP packet info: type=%s (%d), group=%d.%d.%d.%d, code=%d",
				priv_igmp_type_tostr(p_igmp_h->igmp_type), p_igmp_h->igmp_type,
				NIPQUAD(p_igmp_h->igmp_group.s_addr), p_igmp_h->igmp_code);
		if (m_transport_type == VMA_TRANSPORT_IB  || m_b_sysvar_eth_mc_l2_only_rules) {
			ring_logdbg("Transport type is IB (or eth_mc_l2_only_rules), passing igmp packet to igmp_manager to process");
			if(g_p_igmp_mgr) {
				(g_p_igmp_mgr->process_igmp_packet(p_ip_h, m_local_if));
				return false; // we return false in order to free the buffer, although we handled the packet
			}
			ring_logdbg("IGMP packet drop. IGMP manager does not exist.");
			return false;
		}
		ring_logerr("Transport type is ETH, dropping the packet");
		return false;
	}
	break;

	default:
		ring_logwarn("Rx packet dropped - undefined protocol = %d", p_ip_h->protocol);
		return false;
	}

	if (unlikely(p_rfs == NULL)) {
		ring_logdbg("Rx packet dropped - rfs object not found: dst:%d.%d.%d.%d:%d, src%d.%d.%d.%d:%d, proto=%s[%d]",
				NIPQUAD(p_rx_wc_buf_desc->rx.dst.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->rx.dst.sin_port),
				NIPQUAD(p_rx_wc_buf_desc->rx.src.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->rx.src.sin_port),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol);

		return false;
	}
	return p_rfs->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
}

int ring_simple::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
	int ret = 1;
	if (likely(CQT_RX == cq_type)) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
				m_p_cq_mgr_rx->request_notification(poll_sn);
				++m_p_ring_stat->simple.n_rx_interrupt_requests);
	}
	else {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_p_cq_mgr_tx->request_notification(poll_sn));
	}
	return ret;
}

int ring_simple::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array));
	return ret;
}

#ifdef DEFINED_SOCKETXTREME
int ring_simple::socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags)
{
	int ret = 0;
	int i = 0;
	mem_buf_desc_t *desc;

	NOT_IN_USE(flags);

	if (likely(vma_completions) && ncompletions) {
		struct ring_ec *ec = NULL;

		m_socketxtreme_completion = vma_completions;

		while (!g_b_exit && (i < (int)ncompletions)) {
			m_socketxtreme_completion->events = 0;
			/* Check list size to avoid locking */
			if (!list_empty(&m_ec_list)) {
				ec = get_ec();
				if (ec) {
					memcpy(m_socketxtreme_completion, &ec->completion, sizeof(ec->completion));
					ec->clear();
					m_socketxtreme_completion++;
					i++;
				}
			} else {
				/* Internal thread can raise event on this stage before we
				 * start rx processing. In this case we can return event
				 * in right order. It is done to avoid locking and
				 * may be it is not so critical
				 */
				if (likely(m_p_cq_mgr_rx->socketxtreme_and_process_element_rx(&desc))) {
					desc->rx.socketxtreme_polled = true;
					rx_process_buffer(desc, NULL);
					if (m_socketxtreme_completion->events) {
						m_socketxtreme_completion++;
						i++;
					}
				} else {
					break;
				}
			}
		}

		m_socketxtreme_completion = NULL;

		ret = i;
	}
	else {
		ret = -1;
		errno = EINVAL;
	}

	return ret;
}
#endif // DEFINED_SOCKETXTREME

int ring_simple::wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = -1;
	if (m_p_cq_mgr_rx != NULL) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
				m_p_cq_mgr_rx->wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array);
		++m_p_ring_stat->simple.n_rx_interrupt_received);
	} else {
		ring_logerr("Can't find rx_cq for the rx_comp_event_channel_fd (= %d)", cq_channel_fd);
	}

	return ret;
}

bool ring_simple::reclaim_recv_buffers(descq_t *rx_reuse)
{
	bool ret = false;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse));
	return ret;
}

bool ring_simple::reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst)
{
	return m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse_lst);
}

#ifdef DEFINED_SOCKETXTREME
int ring_simple::socketxtreme_reclaim_single_recv_buffer(mem_buf_desc_t* rx_reuse_buff)
{
	int ret_val = 0;

	ret_val = rx_reuse_buff->lwip_pbuf_dec_ref_count();

	if ((ret_val == 0) && (rx_reuse_buff->get_ref_count() <= 0)) {
		/*if ((safe_mce_sys().thread_mode > THREAD_MODE_SINGLE)) {
			m_lock_ring_rx.lock();
		}*/

		if (!m_rx_buffs_rdy_for_free_head) {
			m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = rx_reuse_buff;
		}
		else {
			m_rx_buffs_rdy_for_free_tail->p_next_desc = rx_reuse_buff;
			m_rx_buffs_rdy_for_free_tail = rx_reuse_buff;
		}
		m_rx_buffs_rdy_for_free_tail->p_next_desc = NULL;

		/*if ((safe_mce_sys().thread_mode > THREAD_MODE_SINGLE)) {
			m_lock_ring_rx.lock();
		}*/
	}

	return ret_val;
}

void ring_simple::socketxtreme_reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst)
{
	m_lock_ring_rx.lock();
	if (m_rx_buffs_rdy_for_free_head) {
		m_p_cq_mgr_rx->socketxtreme_reclaim_recv_buffer_helper(m_rx_buffs_rdy_for_free_head);
		m_rx_buffs_rdy_for_free_head = m_rx_buffs_rdy_for_free_tail = NULL;
	}

	m_p_cq_mgr_rx->socketxtreme_reclaim_recv_buffer_helper(rx_reuse_lst);
	m_lock_ring_rx.unlock();
}
#endif // DEFINED_SOCKETXTREME

void ring_simple::mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	m_p_cq_mgr_rx->mem_buf_desc_completion_with_error(p_rx_wc_buf_desc);
}

void ring_simple::mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc)
{
	if (m_b_qp_tx_first_flushed_completion_handled) {
		p_tx_wc_buf_desc->p_next_desc = NULL; // All wr are flushed so we need to disconnect the Tx list
	}
	else {
		m_b_qp_tx_first_flushed_completion_handled = true; // This is true for all wr except for the first one which might point to already sent wr
	}
	m_tx_num_wr_free += mem_buf_tx_release(p_tx_wc_buf_desc, false, false);
}

void ring_simple::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array /*NULL*/)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_rx, m_p_cq_mgr_rx->mem_buf_desc_return_to_owner(p_mem_buf_desc, pv_fd_ready_array));
}

void ring_simple::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, m_tx_num_wr_free += put_tx_buffers(p_mem_buf_desc));
}

void ring_simple::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, put_tx_single_buffer(p_mem_buf_desc));
}

int ring_simple::drain_and_proccess()
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->drain_and_proccess());
	return ret;
}

mem_buf_desc_t* ring_simple::mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs /* default = 1 */)
{
	NOT_IN_USE(id);
	int ret = 0;
	mem_buf_desc_t* buff_list = NULL;
	uint64_t poll_sn;

	ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

	m_lock_ring_tx.lock();
	buff_list = get_tx_buffers(n_num_mem_bufs);
	while (!buff_list) {

		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, ret);
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			return NULL;
		}
		else if (ret > 0) {
			ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
			buff_list = get_tx_buffers(n_num_mem_bufs);
		}
		else if (b_block) { // (ret == 0)
			// Arm & Block on tx cq_mgr notification channel
			// until we get a few freed tx mem_buf_desc & data buffers

			// Only a single thread should block on next Tx cqe event, hence the dedicated lock!
			/* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();

			// poll once more (in the hope that we get a few freed tx mem_buf_desc)
			buff_list = get_tx_buffers(n_num_mem_bufs);
			if (!buff_list) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_p_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					/* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, 100);
					if (ret == 0) {
						m_lock_ring_tx_buf_wait.unlock();
						/* coverity[double_lock] TODO: RM#1049980 */
						m_lock_ring_tx.lock();
						buff_list = get_tx_buffers(n_num_mem_bufs);
						continue;
					} else if (ret < 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						return NULL;
					}
					/* coverity[double_lock] TODO: RM#1049980 */
					m_lock_ring_tx.lock();

					// Find the correct Tx cq_mgr from the CQ event,
					// It might not be the active_cq object since we have a single TX CQ comp channel for all cq_mgr's
					cq_mgr* p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
					if (p_cq_mgr_tx) {

						// Allow additional CQ arming now
						p_cq_mgr_tx->m_b_notification_armed = false;

						// Perform a non blocking event read, clear the fd channel
						ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
						if (ret < 0) {
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
							/* coverity[double_unlock] TODO: RM#1049980 */
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							return NULL;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
				buff_list = get_tx_buffers(n_num_mem_bufs);
			}
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();
		}
		else {
			// get out on non blocked socket
			m_lock_ring_tx.unlock();
			return NULL;
		}
	}

	// We got the buffers
	// Increase counter in order to keep track of how many buffers ring is missing when reclaiming them during ring->restart()
	m_missing_buf_ref_count += n_num_mem_bufs;

	m_lock_ring_tx.unlock();
	return buff_list;
}

int ring_simple::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock/*=false*/)
{
	ring_logfuncall("");

	if (!trylock)
		m_lock_ring_tx.lock();
	else if (m_lock_ring_tx.trylock())
		return 0;

	int accounting = put_tx_buffers(p_mem_buf_desc_list);
	if (b_accounting)
		m_missing_buf_ref_count -= accounting;
	m_lock_ring_tx.unlock();
	return accounting;
}

int ring_simple::get_max_tx_inline()
{
	return m_p_qp_mgr->get_max_inline_tx_data();
}

/* note that this function is inline, so keep it above the functions using it */
inline int ring_simple::send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	//Note: this is debatable logic as it count of WQEs waiting completion but
	//our SQ is cyclic buffer so in reality only last WQE is still being sent
	//and other SQ is mostly free to work on.
	int ret = 0;
	if (likely(m_tx_num_wr_free > 0)) {
		ret = m_p_qp_mgr->send(p_send_wqe, attr);
		--m_tx_num_wr_free;
	} else if (is_available_qp_wr(is_set(attr, VMA_TX_PACKET_BLOCK))) {
		ret = m_p_qp_mgr->send(p_send_wqe, attr);
	} else {
		ring_logdbg("silent packet drop, no available WR in QP!");
		ret = -1;
		if(p_send_wqe) {
			mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
			p_mem_buf_desc->p_next_desc = NULL;
		}
	}
	return ret;
}

bool ring_simple::get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe)
{
	NOT_IN_USE(id);
	NOT_IN_USE(p_send_wqe);

	return m_p_qp_mgr->get_hw_dummy_send_support();
}

void ring_simple::send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);

#ifdef DEFINED_SW_CSUM
	{
#else
	if (attr & VMA_TX_SW_CSUM) {
#endif
		compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);
		attr = (vma_wr_tx_packet_attr) (attr & ~(VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM));
	}

	auto_unlocker lock(m_lock_ring_tx);
	p_send_wqe->sg_list[0].lkey = m_tx_lkey;	// The ring keeps track of the current device lkey (In case of bonding event...)
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

void ring_simple::send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);

#ifdef DEFINED_SW_CSUM
	compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);
	attr = (vma_wr_tx_packet_attr) (attr & ~(VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM));
#endif

	auto_unlocker lock(m_lock_ring_tx);
	p_send_wqe->sg_list[0].lkey = m_tx_lkey; // The ring keeps track of the current device lkey (In case of bonding event...)
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	p_mem_buf_desc->lwip_pbuf.pbuf.ref++;
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

void ring_simple::flow_udp_del_all()
{
	flow_spec_udp_key_t map_key_udp;
	flow_spec_udp_map_t::iterator itr_udp;

	itr_udp = m_flow_udp_uc_map.begin();
	while (itr_udp != m_flow_udp_uc_map.end()) {
		rfs *p_rfs = itr_udp->second;
		map_key_udp = itr_udp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_uc_map.del(map_key_udp))) {
			ring_logdbg("Could not find rfs object to delete in ring udp uc hash map!");
		}
		itr_udp =  m_flow_udp_uc_map.begin();
	}

	itr_udp = m_flow_udp_mc_map.begin();
	while (itr_udp != m_flow_udp_mc_map.end()) {
		rfs *p_rfs = itr_udp->second;
		map_key_udp = itr_udp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_mc_map.del(map_key_udp))) {
			ring_logdbg("Could not find rfs object to delete in ring udp mc hash map!");
		}
		itr_udp =  m_flow_udp_mc_map.begin();
	}
}

void ring_simple::flow_tcp_del_all()
{
	flow_spec_tcp_key_t map_key_tcp;
	flow_spec_tcp_map_t::iterator itr_tcp;

	while ((itr_tcp = m_flow_tcp_map.begin()) != m_flow_tcp_map.end()) {
		rfs *p_rfs = itr_tcp->second;
		map_key_tcp = itr_tcp->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_tcp_map.del(map_key_tcp))) {
			ring_logdbg("Could not find rfs object to delete in ring tcp hash map!");
		}
	}
}

/*
 * called under m_lock_ring_tx lock
 */
bool ring_simple::is_available_qp_wr(bool b_block)
{
	int ret = 0;
	uint64_t poll_sn;

	while (m_tx_num_wr_free <= 0) {
		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, ret);
			/* coverity[missing_unlock] */
			return false;
		} else if (ret > 0) {
			ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
		} else if (b_block){
			// Arm & Block on tx cq_mgr notification channel
			// until we get a few freed tx mem_buf_desc & data buffers

			// Only a single thread should block on next Tx cqe event, hence the dedicated lock!
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();

			if (m_tx_num_wr_free <= 0) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_p_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					/* coverity[double_unlock] TODO: RM#1049980 */
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, -1);
					if (ret <= 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						/* coverity[double_lock] TODO: RM#1049980 */
						m_lock_ring_tx.lock();
						/* coverity[missing_unlock] */
						return false;
					}
					/* coverity[double_lock] TODO: RM#1049980 */
					m_lock_ring_tx.lock();

					// Find the correct Tx cq_mgr from the CQ event,
					// It might not be the active_cq object since we have a single TX CQ comp channel for all cq_mgr's
					cq_mgr* p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
					if (p_cq_mgr_tx) {

						// Allow additional CQ arming now
						p_cq_mgr_tx->m_b_notification_armed = false;

						// Perform a non blocking event read, clear the fd channel
						ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
						if (ret < 0) {
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
							/* coverity[double_unlock] TODO: RM#1049980 */
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							/* coverity[double_lock] TODO: RM#1049980 */
							m_lock_ring_tx.lock();
							return false;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
			}
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();
		} else {
			return false;
		}
	}

	--m_tx_num_wr_free;
	return true;
}

//call under m_lock_ring_tx lock
bool ring_simple::request_more_tx_buffers(uint32_t count)
{
	ring_logfuncall("Allocating additional %d buffers for internal use", count);

	bool res = g_buffer_pool_tx->get_buffers_thread_safe(m_tx_pool, this, count, m_tx_lkey);
	if (!res) {
		ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
		return false;
	}

	return true;
}

void ring_simple::init_tx_buffers(uint32_t count)
{
	request_more_tx_buffers(count);
	m_tx_num_bufs = m_tx_pool.size();
}

//call under m_lock_ring_tx lock
mem_buf_desc_t* ring_simple::get_tx_buffers(uint32_t n_num_mem_bufs)
{
	mem_buf_desc_t* head = NULL;
	if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
		int count = MAX(RING_TX_BUFS_COMPENSATE, n_num_mem_bufs);
		if (request_more_tx_buffers(count)) {
			m_tx_num_bufs += count;
		}

		if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
			return head;
		}
	}

	head = m_tx_pool.get_and_pop_back();
	head->lwip_pbuf.pbuf.ref = 1;
	n_num_mem_bufs--;

	mem_buf_desc_t* next = head;
	while (n_num_mem_bufs) {
		next->p_next_desc = m_tx_pool.get_and_pop_back();
		next = next->p_next_desc;
		next->lwip_pbuf.pbuf.ref = 1;
		n_num_mem_bufs--;
	}

	return head;
}

void ring_simple::return_to_global_pool()
{
	if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&  m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
		int return_bufs = m_tx_pool.size() / 2;
		m_tx_num_bufs -= return_bufs;
		g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_bufs);
	}
}

//call under m_lock_ring_tx lock
int ring_simple::put_tx_buffers(mem_buf_desc_t* buff_list)
{
	int count = 0, freed=0;
	mem_buf_desc_t *next;

	while (buff_list) {
		next = buff_list->p_next_desc;
		buff_list->p_next_desc = NULL;

		if (buff_list->tx.dev_mem_length)
			m_p_qp_mgr->dm_release_data(buff_list);

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff_list->lwip_pbuf.pbuf.ref))
			buff_list->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", buff_list);

		if (buff_list->lwip_pbuf.pbuf.ref == 0) {
			free_lwip_pbuf(&buff_list->lwip_pbuf);
			m_tx_pool.push_back(buff_list);
			freed++;
		}
		count++;
		buff_list = next;
	}
	ring_logfunc("buf_list: %p count: %d freed: %d\n", buff_list, count, freed);

	return_to_global_pool();

	return count;
}

//call under m_lock_ring_tx lock
int ring_simple::put_tx_single_buffer(mem_buf_desc_t* buff)
{
	int count = 0;

	if (likely(buff)) {

		if (buff->tx.dev_mem_length)
			m_p_qp_mgr->dm_release_data(buff);

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff->lwip_pbuf.pbuf.ref))
			buff->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", buff);

		if (buff->lwip_pbuf.pbuf.ref == 0) {
			buff->p_next_desc = NULL;
			free_lwip_pbuf(&buff->lwip_pbuf);
			m_tx_pool.push_back(buff);
			count++;
		}
	}

	return_to_global_pool();

	return count;
}

void ring_simple::modify_cq_moderation(uint32_t period, uint32_t count)
{
	uint32_t period_diff = period > m_cq_moderation_info.period ?
			period - m_cq_moderation_info.period : m_cq_moderation_info.period - period;
	uint32_t count_diff = count > m_cq_moderation_info.count ?
			count - m_cq_moderation_info.count : m_cq_moderation_info.count - count;

	if (period_diff < (m_cq_moderation_info.period / 20) && (count_diff < m_cq_moderation_info.count / 20))
		return;

	m_cq_moderation_info.period = period;
	m_cq_moderation_info.count = count;

	m_p_ring_stat->simple.n_rx_cq_moderation_period = period;
	m_p_ring_stat->simple.n_rx_cq_moderation_count = count;

	//todo all cqs or just active? what about HA?
	priv_ibv_modify_cq_moderation(m_p_cq_mgr_rx->get_ibv_cq_hndl(), period, count);
}

void ring_simple::adapt_cq_moderation()
{
	if (m_lock_ring_rx.trylock()) {
		++m_cq_moderation_info.missed_rounds;
		return; //todo try again sooner?
	}

	uint32_t missed_rounds = m_cq_moderation_info.missed_rounds;

	//todo collect bytes and packets from all rings ??
	int64_t interval_bytes = m_cq_moderation_info.bytes - m_cq_moderation_info.prev_bytes;
	int64_t interval_packets = m_cq_moderation_info.packets - m_cq_moderation_info.prev_packets;

	m_cq_moderation_info.prev_bytes = m_cq_moderation_info.bytes;
	m_cq_moderation_info.prev_packets = m_cq_moderation_info.packets;
	m_cq_moderation_info.missed_rounds = 0;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (interval_bytes < 0 || interval_packets < 0) {
		//rare wrap-around of 64 bit, just ignore
		m_lock_ring_rx.unlock();
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (interval_packets == 0) {
		// todo if no traffic, set moderation to default?
		modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
		m_lock_ring_rx.unlock();
		return;
	}

	uint32_t avg_packet_size = interval_bytes / interval_packets;
	uint32_t avg_packet_rate = (interval_packets * 1000) / (safe_mce_sys().cq_aim_interval_msec * (1 + missed_rounds));

	uint32_t ir_rate = safe_mce_sys().cq_aim_interrupts_rate_per_sec;

	int count = MIN(avg_packet_rate / ir_rate, safe_mce_sys().cq_aim_max_count);
	int period = MIN(safe_mce_sys().cq_aim_max_period_usec, ((1000000 / ir_rate) - (1000000 / MAX(avg_packet_rate, ir_rate))));

	if (avg_packet_size < 1024 && avg_packet_rate < 450000) {
		modify_cq_moderation(0, 0); //latency mode
		//todo latency for big messages is not good
		// the rate is affected by the moderation and the moderation by the rate..
		// so each cycle change from 0 to max, and max to 0, ..
	} else {
		modify_cq_moderation(period, count); //throughput mode
	}

	m_lock_ring_rx.unlock();
}

void ring_simple::start_active_qp_mgr() {
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();
	if (!m_up) {
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->up();
		m_b_qp_tx_first_flushed_completion_handled = false;
		m_up = true;
	}
	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();
}

void ring_simple::stop_active_qp_mgr() {
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();
	if (m_up) {
		m_up = false;
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->down();
	}
	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();
}

bool ring_simple::is_up() {
	return m_up;
}

int ring_simple::modify_ratelimit(struct vma_rate_limit_t &rate_limit)
{
	uint32_t rl_changes = m_p_qp_mgr->is_ratelimit_change(rate_limit);

	if (m_up && rl_changes)
		return m_p_qp_mgr->modify_qp_ratelimit(rate_limit, rl_changes);

	return 0;
}

int ring_simple::get_ring_descriptors(vma_mlx_hw_device_data &d)
{
	d.dev_data.vendor_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_id;
	d.dev_data.vendor_part_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_part_id;
	if (vma_is_packet_pacing_supported(m_p_ib_ctx->get_ibv_device_attr())) {
		d.dev_data.device_cap |= VMA_HW_PP_EN;
	}
	if (vma_is_umr_supported(m_p_ib_ctx->get_ibv_device_attr())) {
		d.dev_data.device_cap |= VMA_HW_UMR_EN;
	}
	if (vma_is_mp_rq_supported(m_p_ib_ctx->get_ibv_device_attr())) {
		d.dev_data.device_cap |= VMA_HW_MP_RQ_EN;
	}
	d.valid_mask = DATA_VALID_DEV;

	ring_logdbg("found device with Vendor-ID %u, ID %u, Device cap %u", d.dev_data.vendor_part_id,
		    d.dev_data.vendor_id, d.dev_data.device_cap);
	if (!m_p_qp_mgr->fill_hw_descriptors(d)) {
		return -1;
	}
	if (m_p_cq_mgr_rx->fill_cq_hw_descriptors(d.rq_data.wq_data.cq_data)) {
		d.valid_mask |= DATA_VALID_RQ;
	}

	if (m_p_cq_mgr_tx->fill_cq_hw_descriptors(d.sq_data.wq_data.cq_data)) {
		d.valid_mask |= DATA_VALID_SQ;
	}
	VALGRIND_MAKE_MEM_DEFINED(&d, sizeof(d));
	return 0;
}
