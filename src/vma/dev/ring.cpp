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


#include "ring.h"

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include "vma/util/utils.h"
#include "vma/util/bullseye.h"
#include "vma/proto/ip_frag.h"
#include "vma/proto/L2_address.h"
#include "vma/proto/igmp_mgr.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/sock/fd_collection.h"
#include "vma/dev/rfs_mc.h"
#include "vma/dev/rfs_uc.h"
#include "vma/dev/rfs_uc_tcp_gro.h"
#include "vma/dev/cq_mgr.h"
#include "lwip/src/include/lwip/tcp.h"


#undef  MODULE_NAME
#define MODULE_NAME 		"ring"
#undef  MODULE_HDR
#define MODULE_HDR	 	MODULE_NAME "%d:%s() "

#define ring_logpanic 		__log_info_panic
#define ring_logerr		__log_info_err
#define ring_logwarn		__log_info_warn
#define ring_loginfo		__log_info_info
#define ring_logdbg		__log_info_dbg
#define ring_logfunc		__log_info_func
#define ring_logfuncall		__log_info_funcall

#define ALIGN_WR_DOWN(_num_wr_) 		(max(32, ((_num_wr_      ) & ~(0xf))))


#define RING_LOCK_AND_RUN(__lock__, __func_and_params__) 	\
		__lock__.lock(); __func_and_params__; __lock__.unlock();

#define RING_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) 	\
		__lock__.lock(); ret = __func_and_params__; __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) \
		if (!__lock__.trylock()) { ret = __func_and_params__; __lock__.unlock(); } \
		else { errno = EBUSY; }


#define m_active_qp_mgr			m_ring_active_resource->second.m_p_qp_mgr
#define m_active_cq_mgr_rx		m_ring_active_resource->second.m_p_cq_mgr_rx
#define m_active_cq_mgr_tx		m_ring_active_resource->second.m_p_cq_mgr_tx


#define RING_TX_BUFS_COMPENSATE 256


qp_mgr* ring_eth::create_qp_mgr(ring_resource_definition& key, struct ibv_comp_channel* p_rx_comp_event_channel)
{
	return new qp_mgr_eth(this, key.get_ib_ctx_handle(), key.get_port_num(), p_rx_comp_event_channel, m_tx_num_wr, m_partition);
}

qp_mgr* ring_ib::create_qp_mgr(ring_resource_definition& key, struct ibv_comp_channel* p_rx_comp_event_channel)
{
	return new qp_mgr_ib(this, key.get_ib_ctx_handle(), key.get_port_num(), p_rx_comp_event_channel, m_tx_num_wr, m_partition);
}



ring::ring(in_addr_t local_if, uint16_t partition_sn, int count, transport_type_t transport_type) :
		m_local_if(local_if), m_transport_type(transport_type), m_n_num_resources(count), m_p_tx_comp_event_channel(NULL),
		m_lock_ring_rx("ring:lock_rx"), m_lock_ring_tx("ring:lock_tx"), m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait"),
		m_p_n_rx_channel_fds(NULL), m_tx_num_bufs(0), m_tx_num_wr(0), m_tx_num_wr_free(0), m_b_qp_tx_first_flushed_completion_handled(false),
		m_missing_buf_ref_count(0), m_tx_lkey(0), m_partition(partition_sn), m_gro_mgr(mce_sys.gro_streams_max, MAX_GRO_BUFS), m_p_ring_stat(NULL)
{
	 // coverity[uninit_member]
}

ring::~ring()
{
	ring_logdbg("delete ring()");
	ring_resources_map_t::iterator ring_resource_iter;

	// Go over all hash and for each flow: 1.Detach from qp 2.Delete related rfs object 3.Remove flow from hash

	m_lock_ring_rx.lock();
	flow_udp_uc_del_all();
	flow_udp_mc_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	// Allow last few post sends to be sent by HCA.
	// Was done in order to allow iperf's FIN packet to be sent.
	usleep(25000);

	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

	// 'down' the active QP/CQ
	m_active_qp_mgr->down();

	// Release QP/CQ resources
	while ((ring_resource_iter = m_ring_resources_map.begin()) != m_ring_resources_map.end()) {
		delete ring_resource_iter->second.m_p_qp_mgr;

		// Delete the rx channel fd from the global fd collection
		if (g_p_fd_collection) {
			g_p_fd_collection->del_cq_channel_fd(ring_resource_iter->second.m_p_rx_comp_event_channel->fd, true);
		}

		IF_VERBS_FAILURE(ibv_destroy_comp_channel(ring_resource_iter->second.m_p_rx_comp_event_channel)) {
			ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		m_ring_resources_map.erase(ring_resource_iter);
	}
	delete[] m_p_n_rx_channel_fds;

	int buffer_accounting = m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count;
	ring_logdbg("Tx buffer poll: free count = %u, sender_has = %d, total = %d, %s (%d)",
			m_tx_pool.size(), m_missing_buf_ref_count, m_tx_num_bufs,
			(buffer_accounting?"bad accounting!!":"good accounting"), buffer_accounting);
	ring_logdbg("Tx WR num: free count = %d, total = %d, %s (%d)",
			m_tx_num_wr_free, m_tx_num_wr,
			((m_tx_num_wr - m_tx_num_wr_free) ? "bad accounting!!":"good accounting"), (m_tx_num_wr - m_tx_num_wr_free));
	ring_logdbg("Rx buffer pool: %d free global buffers available", m_tx_pool.size());

	// Release Tx buffers
	g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, m_tx_pool.size());

	// Release verbs resources
	IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_tx_comp_event_channel)) {
		ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
	} ENDIF_VERBS_FAILURE;
	m_p_tx_comp_event_channel = NULL;

	vma_stats_instance_remove_ring_block(m_p_ring_stat);

	m_lock_ring_rx.unlock();
	m_lock_ring_tx.unlock();

	ring_logdbg("delete ring() completed");
}

void ring::create_resources(ring_resource_creation_info_t* p_ring_info, int active)
{
	ring_logdbg("new ring()");

	BULLSEYE_EXCLUDE_BLOCK_START
	if(p_ring_info == NULL) {
		ring_logpanic("p_ring_info = NULL");
	}

	if(p_ring_info[0].p_ib_ctx == NULL) {
		ring_logpanic("p_ring_info[0].p_ib_ctx = NULL. It can be related to wrong bonding configuration");
	}

	m_p_tx_comp_event_channel = ibv_create_comp_channel(p_ring_info[0].p_ib_ctx->get_ibv_context());
	if (m_p_tx_comp_event_channel == NULL) {
		ring_logpanic("ibv_create_comp_channel for tx failed. m_p_tx_comp_event_channel = %p (errno=%d %m)", m_p_tx_comp_event_channel, errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Check device capabilities for max QP work requests
	ibv_device_attr& r_ibv_dev_attr = p_ring_info[0].p_ib_ctx->get_ibv_device_attr();
	uint32_t max_qp_wr = ALIGN_WR_DOWN(r_ibv_dev_attr.max_qp_wr - 1);
	m_tx_num_wr = mce_sys.tx_num_wr;
	if (m_tx_num_wr > max_qp_wr) {
		ring_logwarn("Allocating only %d Tx QP work requests while user requested %s=%d for QP on interface %d.%d.%d.%d",
			max_qp_wr, SYS_VAR_TX_NUM_WRE, m_tx_num_wr);
		m_tx_num_wr = max_qp_wr;
	}

	m_tx_num_wr_free = m_tx_num_wr;
	
	memset(&m_cq_moderation_info, 0, sizeof(struct cq_moderation_info));

	m_p_n_rx_channel_fds = new int[m_n_num_resources];

	m_ring_active_resource = m_ring_resources_map.end();
	for (int i = 0; i < m_n_num_resources; i++) {
		struct ring_resources_info_t ring_resources_info;
		ring_resource_definition key(p_ring_info[i]);

		ring_resources_info.m_p_rx_comp_event_channel = ibv_create_comp_channel(p_ring_info[0].p_ib_ctx->get_ibv_context()); // ODED TODO: Adjust the ibv_context to be the exact one in case of different devices
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ring_resources_info.m_p_rx_comp_event_channel == NULL) {
			ring_logpanic("ibv_create_comp_channel for rx failed. p_rx_comp_event_channel = %p (errno=%d %m)",
					ring_resources_info.m_p_rx_comp_event_channel, errno);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		m_p_n_rx_channel_fds[i] = ring_resources_info.m_p_rx_comp_event_channel->fd;
		// Add the rx channel fd to the global fd collection
		if (g_p_fd_collection) {
			// Create new cq_channel info in the global fd collection
			g_p_fd_collection->add_cq_channel_fd(m_p_n_rx_channel_fds[i], this);
		}

		ring_resources_info.m_p_qp_mgr = create_qp_mgr(key, ring_resources_info.m_p_rx_comp_event_channel);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ring_resources_info.m_p_qp_mgr == NULL) {
			ring_logpanic("Failed to allocate qp_mgr!");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		// save cq_mgr pointers
		ring_resources_info.m_p_cq_mgr_rx = ring_resources_info.m_p_qp_mgr->get_rx_cq_mgr();
		ring_resources_info.m_p_cq_mgr_tx = ring_resources_info.m_p_qp_mgr->get_tx_cq_mgr();

		// Add to resources map
		m_ring_resources_map[key] = ring_resources_info;

		// Add to map that links between the rx_comp_event_channel and it's relevant rx_cq
		int key_fd = ring_resources_info.m_p_rx_comp_event_channel->fd;
		m_rx_channel_fd_to_ring_resources_map[key_fd] = m_ring_resources_map.find(key);

		if (i == active) {
			// In case this is the active port save it (will update on ring::restart)
			m_ring_active_resource = m_ring_resources_map.find(key);
		}
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_ring_active_resource == m_ring_resources_map.end()) {
		ring_logpanic("Failed to find the active resource");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(m_ring_active_resource->first.get_ib_ctx_handle());

	request_more_tx_buffers(RING_TX_BUFS_COMPENSATE);
	m_tx_num_bufs = m_tx_pool.size();

	// 'up' the active QP/CQ resource
	m_active_qp_mgr->up();

	// use local copy of stats by default
	m_p_ring_stat = &m_ring_stat_static;
	memset(m_p_ring_stat , 0, sizeof(*m_p_ring_stat));

	if (mce_sys.cq_moderation_enable) {
		modify_cq_moderation(mce_sys.cq_moderation_period_usec, mce_sys.cq_moderation_count);
	}

	vma_stats_instance_create_ring_block(m_p_ring_stat);

	ring_logdbg("new ring() completed");
}

void ring::restart(ring_resource_creation_info_t* p_ring_info)
{
	ring_logdbg("*** ring restart! ***");

	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

	// 'down' the active QP/CQ
	m_active_qp_mgr->down();
	int buffer_accounting = m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count;
	ring_logdbg("Tx buffer poll: free count = %u, sender_has = %d, total = %d, %s (%d)",
			m_tx_pool.size(), m_missing_buf_ref_count, m_tx_num_bufs,
			(buffer_accounting?"bad accounting!!":"good accounting"), buffer_accounting);
	ring_logdbg("Tx WR num: free count = %d, total = %d, %s (%d)",
			m_tx_num_wr_free, m_tx_num_wr,
			((m_tx_num_wr - m_tx_num_wr_free) ? "bad accounting!!":"good accounting"), (m_tx_num_wr - m_tx_num_wr_free));
	ring_logdbg("Rx buffer pool: %d free global buffers available", m_tx_pool.size());

	// Find the new current active resource iterator
	ring_resource_definition key(p_ring_info);
	m_ring_active_resource = m_ring_resources_map.find(key);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_ring_active_resource == m_ring_resources_map.end()) {
		ring_logwarn("failed to find new active resource");
		m_ring_active_resource = m_ring_resources_map.begin();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(m_ring_active_resource->first.get_ib_ctx_handle());


	//TODO ALEXR: need to check is old active Rx CQ was armed and then arm new active Rx CQ

	// 'up' the active QP/CQ
	m_active_qp_mgr->up();
	m_b_qp_tx_first_flushed_completion_handled = false;

	// re-arm the CQ's just in case someone was blocking on the old CQ channel waiting for an event
	int ret = 0;
	uint64_t poll_sn = cq_mgr::m_n_global_sn;
	ret = m_active_cq_mgr_rx->request_notification(poll_sn);
	if (ret < 0) {
		ring_logdbg("failed arming rx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_rx, errno);
	}
	ret = m_active_cq_mgr_tx->request_notification(poll_sn);
	if (ret < 0) {
		ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, errno);
	}

	if (mce_sys.cq_moderation_enable) {
		modify_cq_moderation(mce_sys.cq_moderation_period_usec, mce_sys.cq_moderation_count);
	}

	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();

	ring_logdbg("*** ring restart done! ***");
}

bool ring::attach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink *sink)
{
	rfs *p_rfs;

	ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str(), sink);

	auto_unlocker lock(m_lock_ring_rx);

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_uc_key_t key_udp_uc = {flow_spec_5t.get_dst_port()};
		p_rfs = m_flow_udp_uc_map.get(key_udp_uc, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			p_rfs = new rfs_uc(&flow_spec_5t, this);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_rfs == NULL) {
				ring_logpanic("Failed to allocate rfs!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_flow_udp_uc_map.set(key_udp_uc, p_rfs);
		}
	} else if (flow_spec_5t.is_udp_mc()) {
		flow_spec_udp_mc_key_t key_udp_mc = {flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port()};
		// For IB MC flow, the port is zeroed in the ibv_flow_spec when calling to ibv_flow_spec().
		// It means that for every MC group, even if we have sockets with different ports - only one rule in the HW.
		// So the hash map below keeps track of the number of sockets per rule so we know when to call ibv_attach and ibv_detach
		rfs_rule_filter* l2_mc_ip_filter = NULL;
		if (m_transport_type == VMA_TRANSPORT_IB || mce_sys.eth_mc_l2_only_rules) {
			rule_filter_map_t::iterator l2_mc_iter = m_l2_mc_ip_attach_map.find(key_udp_mc.dst_ip);
			if (l2_mc_iter == m_l2_mc_ip_attach_map.end()) { // It means that this is the first time attach called with this MC ip
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = 1;
			} else {
				m_l2_mc_ip_attach_map[key_udp_mc.dst_ip].counter = ((l2_mc_iter->second.counter) + 1);
			}
		}
		p_rfs = m_flow_udp_mc_map.get(key_udp_mc, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			if (m_transport_type == VMA_TRANSPORT_IB || mce_sys.eth_mc_l2_only_rules) {
				l2_mc_ip_filter = new rfs_rule_filter(m_l2_mc_ip_attach_map, key_udp_mc.dst_ip, flow_spec_5t);
			}
			p_rfs = new rfs_mc(&flow_spec_5t, this, l2_mc_ip_filter);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_rfs == NULL) {
				ring_logpanic("Failed to allocate rfs!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_flow_udp_mc_map.set(key_udp_mc, p_rfs);
		}
	} else if (flow_spec_5t.is_tcp()) {
		flow_spec_tcp_key_t key_tcp = {flow_spec_5t.get_src_ip(), flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port()};
		rfs_rule_filter* tcp_dst_port_filter = NULL;
		if (mce_sys.tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(key_tcp.dst_port);
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				m_tcp_dst_port_attach_map[key_tcp.dst_port].counter = 1;
			} else {
				m_tcp_dst_port_attach_map[key_tcp.dst_port].counter = ((tcp_dst_port_iter->second.counter) + 1);
			}
		}

		p_rfs = m_flow_tcp_map.get(key_tcp, NULL);
		if (p_rfs == NULL) {		// It means that no rfs object exists so I need to create a new one and insert it to the flow map
			if (mce_sys.tcp_3t_rules) {
				flow_tuple tcp_3t_only(flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port(), 0, 0, flow_spec_5t.get_protocol());
				tcp_dst_port_filter = new rfs_rule_filter(m_tcp_dst_port_attach_map, key_tcp.dst_port, tcp_3t_only);
			}
			if(mce_sys.gro_streams_max && flow_spec_5t.is_5_tuple()) {
				p_rfs = new rfs_uc_tcp_gro(&flow_spec_5t, this, tcp_dst_port_filter);
			} else {
				p_rfs = new rfs_uc(&flow_spec_5t, this, tcp_dst_port_filter);
			}
			BULLSEYE_EXCLUDE_BLOCK_START
			if (p_rfs == NULL) {
				ring_logpanic("Failed to allocate rfs!");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
			m_flow_tcp_map.set(key_tcp, p_rfs);
		}
	BULLSEYE_EXCLUDE_BLOCK_START
	} else {
		ring_logerr("Could not find map (TCP, UC or MC) for requested flow");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return p_rfs->attach_flow(sink);
}

bool ring::detach_flow(flow_tuple& flow_spec_5t, pkt_rcvr_sink* sink)
{
	rfs *p_rfs = NULL;

	ring_logdbg("flow: %s, with sink (%p)", flow_spec_5t.to_str(), sink);

	auto_unlocker lock(m_lock_ring_rx);

	/* Get the appropriate hash map (tcp, uc or mc) from the 5t details */
	if (flow_spec_5t.is_udp_uc()) {
		flow_spec_udp_uc_key_t key_udp_uc = {flow_spec_5t.get_dst_port()};
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
		flow_spec_udp_mc_key_t key_udp_mc = {flow_spec_5t.get_dst_ip(), flow_spec_5t.get_dst_port()};
		if (m_transport_type == VMA_TRANSPORT_IB || mce_sys.eth_mc_l2_only_rules) {
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
		flow_spec_tcp_key_t key_tcp = {flow_spec_5t.get_src_ip(), flow_spec_5t.get_dst_port(), flow_spec_5t.get_src_port()};
		if (mce_sys.tcp_3t_rules) {
			rule_filter_map_t::iterator tcp_dst_port_iter = m_tcp_dst_port_attach_map.find(key_tcp.dst_port);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (tcp_dst_port_iter == m_tcp_dst_port_attach_map.end()) {
				ring_logdbg("Could not find matching counter for TCP src port!");
				BULLSEYE_EXCLUDE_BLOCK_END
			} else {
				keep_in_map = m_tcp_dst_port_attach_map[key_tcp.dst_port].counter = MAX(0 , ((tcp_dst_port_iter->second.counter) - 1));
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
			m_tcp_dst_port_attach_map.erase(m_tcp_dst_port_attach_map.find(key_tcp.dst_port));
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


/*
void ring::print_ring_flow_to_rfs_map(flow_spec_map_t *p_flow_map)
{
	rfs *curr_rfs;
	flow_spec_5_tuple_key_t map_key;
	flow_spec_map_t::iterator itr;

	for (itr = p_flow_map->begin(); itr != p_flow_map->end(); ++itr) {
		curr_rfs = itr->second;
		map_key = itr->first;
		if (!curr_rfs) {
			ring_logdbg("key: [%d.%d.%d.%d:%d; %d.%d.%d.%d:%d;%s], rfs: NULL",
					 NIPQUAD(map_key.dst_ip), map_key.dst_port,
					 NIPQUAD(map_key.src_ip), map_key.src_port,
					 flow_type_to_str(map_key.l4_protocol));
		}
		else {
			ring_logdbg("key: [%d.%d.%d.%d:%d; %d.%d.%d.%d:%d;%s], rfs: num of sinks = %d",
					NIPQUAD(map_key.dst_ip), map_key.dst_port,
					NIPQUAD(map_key.src_ip), map_key.src_port,
					flow_type_to_str(map_key.l4_protocol), curr_rfs->get_num_of_sinks());
		}
	}
}
*/

//code coverage
#if 0
void ring::print_flow_to_rfs_udp_uc_map(flow_spec_udp_uc_map_t *p_flow_map)
{
	rfs *curr_rfs;
	flow_spec_udp_uc_key_t map_key;
	flow_spec_udp_uc_map_t::iterator itr;

	// This is an internal function (within ring and 'friends'). No need for lock mechanism.

	ring_logdbg("\n\n********** Printing UDP UC map *********");

	itr = p_flow_map->begin();
	if (!(itr != p_flow_map->end())) {
		ring_logdbg("flow_spec_udp_uc_map is EMPTY!\n");
	} else {
		for (itr = p_flow_map->begin(); itr != p_flow_map->end(); ++itr) {
			curr_rfs = itr->second;
			map_key = itr->first;
			if (!curr_rfs) {
				ring_logdbg("######### key: port = %d, rfs: NULL", ntohs(map_key.dst_port));
			}
			else {
				ring_logdbg("######### key: port = %d, rfs = %p, num of sinks = %d", ntohs(map_key.dst_port), curr_rfs, curr_rfs->get_num_of_sinks());
			}
		}
	}
}

void ring::print_flow_to_rfs_tcp_map(flow_spec_tcp_map_t *p_flow_map)
{
	rfs *curr_rfs;
	flow_spec_tcp_key_t map_key;
	flow_spec_tcp_map_t::iterator itr;

	// This is an internal function (within ring and 'friends'). No need for lock mechanism.

	ring_logdbg("\n\n********** Printing TCP map *********");

	itr = p_flow_map->begin();
	if (!(itr != p_flow_map->end())) {
		ring_logdbg("flow_spec_udp_uc_map is EMPTY!\n");
	} else {
		for (itr = p_flow_map->begin(); itr != p_flow_map->end(); ++itr) {
			curr_rfs = itr->second;
			map_key = itr->first;
			if (!curr_rfs) {
				ring_logdbg("######### key: port = %d, rfs: NULL", ntohs(map_key.dst_port));
			}
			else {
				ring_logdbg("######### key: src_ip:%d.%d.%d.%d, dst_port=%d, src_port=%d, rfs: num of sinks = %d", NIPQUAD(map_key.src_ip), ntohs(map_key.dst_port), ntohs(map_key.src_port), curr_rfs->get_num_of_sinks());
			}
		}
	}
}
#endif

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

// All CQ wce come here for some basic sanity checks and then are distributed to the correct ring handler
// Return values: false = Reuse this data buffer & mem_buf_desc
bool ring::rx_process_buffer(mem_buf_desc_t* p_rx_wc_buf_desc, transport_type_t transport_type, void* pv_fd_ready_array /*=NULL*/)
{
	size_t sz_data = 0;
	size_t transport_header_len = 0;
	uint16_t ip_hdr_len = 0;
	uint16_t ip_tot_len = 0;
	uint16_t ip_frag_off = 0;
	uint16_t n_frag_offset = 0;
	struct iphdr* p_ip_h = NULL;
	struct udphdr* p_udp_h = NULL;
	in_addr_t local_addr = p_rx_wc_buf_desc->path.rx.dst.sin_addr.s_addr;

	// This is an internal function (within ring and 'friends'). No need for lock mechanism.

	// Validate buffer size
	sz_data = p_rx_wc_buf_desc->sz_data;
	if (sz_data > p_rx_wc_buf_desc->sz_buffer) {
		if (sz_data == IP_FRAG_FREED)
			ring_logfuncall("Rx buffer dropped - old fragment part");
		else
			ring_logwarn("Rx buffer dropped - buffer too small (%d, %d)", sz_data, p_rx_wc_buf_desc->sz_buffer);
		return false;
	}

	m_cq_moderation_info.bytes += sz_data;
	++m_cq_moderation_info.packets;

	m_ring_stat_static.n_rx_byte_count += sz_data;
	++m_ring_stat_static.n_rx_pkt_count;

	// Validate transport type headers
	switch (transport_type) {
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
		// Get the data buffer start pointer to the Ethernet header pointer
		struct ethhdr* p_eth_h = (struct ethhdr*)(p_rx_wc_buf_desc->p_buffer);
		ring_logfunc("Rx buffer Ethernet dst=" ETH_HW_ADDR_PRINT_FMT " <- src=" ETH_HW_ADDR_PRINT_FMT " type=%#x",
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_dest),
				ETH_HW_ADDR_PRINT_ADDR(p_eth_h->h_source),
				htons(p_eth_h->h_proto));

		transport_header_len = ETH_HDR_LEN;
		uint16_t* p_h_proto = &p_eth_h->h_proto;

		// Handle VLAN header as next protocol
		struct vlanhdr* p_vlan_hdr = NULL;
		uint16_t packet_vlan = 0;
		if (*p_h_proto == htons(ETH_P_8021Q)) {
			p_vlan_hdr = (struct vlanhdr*)((uint8_t*)p_eth_h + transport_header_len);
			transport_header_len = ETH_VLAN_HDR_LEN;
			p_h_proto = &p_vlan_hdr->h_vlan_encapsulated_proto;
			packet_vlan = (htons(p_vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
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
		ring_logwarn("Rx buffer dropped - Unknown transport type %d", transport_type);
		return false;
	}

	// Jump to IP header - Skip IB (GRH and IPoIB) or Ethernet (MAC) header sizes
	sz_data -= transport_header_len;

	// Validate size for IPv4 header
	if (sz_data < sizeof(struct iphdr)) {
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
		sz_data = ip_tot_len;
	}

	// Read fragmentation parameters
	ip_frag_off = ntohs(p_ip_h->frag_off);
	n_frag_offset = (ip_frag_off & FRAGMENT_OFFSET) * 8;

	ring_logfunc("Rx ip packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, offset=%d, id=%d, proto=%s[%d] (local if: %d.%d.%d.%d)",
			NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
			sz_data, n_frag_offset, ntohs(p_ip_h->id),
			iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol,
			NIPQUAD(local_addr));

	// Check that the ip datagram has at least the udp header size for the first ip fragment (besides the ip header)
	ip_hdr_len = (int)(p_ip_h->ihl)*4;
	if ((n_frag_offset == 0) && (ip_tot_len < (ip_hdr_len + sizeof(struct udphdr)))) {
		ring_logwarn("Rx packet dropped - ip packet too small (%d bytes)- udp header cut!", ip_tot_len);
		return false;
	}

	// Handle fragmentation
	p_rx_wc_buf_desc->n_frags = 1;
	if (unlikely((ip_frag_off & MORE_FRAGMENTS_FLAG) || n_frag_offset)) { // Currently we don't expect to receive fragments
		//for disabled fragments handling:
		/*ring_logwarn("Rx packet dropped - VMA doesn't support fragmentation in receive flow!");
		ring_logwarn("packet info: dst=%d.%d.%d.%d, src=%d.%d.%d.%d, packet_sz=%d, frag_offset=%d, id=%d, proto=%s[%d], transport type=%s, (local if: %d.%d.%d.%d)",
				NIPQUAD(p_ip_h->daddr), NIPQUAD(p_ip_h->saddr),
				sz_data, n_frag_offset, ntohs(p_ip_h->id),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol, (transport_type ? "ETH" : "IB"),
				NIPQUAD(local_addr));
		return false;*/
#if 1 //handle fragments
		// Update fragments descriptor with datagram base address and length
		p_rx_wc_buf_desc->path.rx.frag.iov_base = (uint8_t*)p_ip_h + ip_hdr_len;
		p_rx_wc_buf_desc->path.rx.frag.iov_len  = ip_tot_len - ip_hdr_len;

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
		sz_data -= transport_header_len; // Jump to IP header (Skip IB (GRH and IPoIB) or Ethernet (MAC) header size
		p_ip_h = (struct iphdr*)(p_rx_wc_buf_desc->p_buffer + transport_header_len);
		ip_hdr_len = (int)(p_ip_h->ihl)*4;
		ip_tot_len = ntohs(p_ip_h->tot_len);

		mem_buf_desc_t *tmp;
		for (tmp = p_rx_wc_buf_desc; tmp; tmp = tmp->p_next_desc) {
			++p_rx_wc_buf_desc->n_frags;
		}
#endif
	}

//We want to enable loopback between processes for IB
#if 0
	//AlexV: We don't support Tx MC Loopback today!
	if (p_ip_h->saddr == m_local_if) {
		ring_logfunc("Rx udp datagram discarded - mc loop disabled");
		return false;
	}
#endif
	rfs *p_rfs = NULL;

	// Update the L3 info
	p_rx_wc_buf_desc->path.rx.src.sin_family      = AF_INET;
	p_rx_wc_buf_desc->path.rx.src.sin_addr.s_addr = p_ip_h->saddr;
	p_rx_wc_buf_desc->path.rx.dst.sin_family      = AF_INET;
	p_rx_wc_buf_desc->path.rx.dst.sin_addr.s_addr = p_ip_h->daddr;
	p_rx_wc_buf_desc->path.rx.local_if            = m_local_if;

	switch (p_ip_h->protocol) {
	case IPPROTO_UDP:
	{
		// Get the udp header pointer + udp payload size
		p_udp_h = (struct udphdr*)((uint8_t*)p_ip_h + ip_hdr_len);
		size_t sz_payload = ntohs(p_udp_h->len) - sizeof(struct udphdr);
		ring_logfunc("Rx udp datagram info: src_port=%d, dst_port=%d, payload_sz=%d, csum=%#x",
				ntohs(p_udp_h->source), ntohs(p_udp_h->dest), sz_payload, p_udp_h->check);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->path.rx.frag.iov_base = (uint8_t*)p_udp_h + sizeof(struct udphdr);
		p_rx_wc_buf_desc->path.rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct udphdr);

		// Update the L4 info
		p_rx_wc_buf_desc->path.rx.src.sin_port        = p_udp_h->source;
		p_rx_wc_buf_desc->path.rx.dst.sin_port        = p_udp_h->dest;
		p_rx_wc_buf_desc->path.rx.sz_payload          = sz_payload;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		if (!(IN_MULTICAST_N(p_rx_wc_buf_desc->path.rx.dst.sin_addr.s_addr))) {	// This is UDP UC packet
			p_rfs = m_flow_udp_uc_map.get((flow_spec_udp_uc_key_t){p_rx_wc_buf_desc->path.rx.dst.sin_port}, NULL);
		} else {	// This is UDP MC packet
			p_rfs = m_flow_udp_mc_map.get((flow_spec_udp_mc_key_t){p_rx_wc_buf_desc->path.rx.dst.sin_addr.s_addr,
				p_rx_wc_buf_desc->path.rx.dst.sin_port}, NULL);
		}
	}
	break;

	case IPPROTO_TCP:
	{
		// Get the tcp header pointer + tcp payload size
		struct tcphdr* p_tcp_h = (struct tcphdr*)((uint8_t*)p_ip_h + ip_hdr_len);
		size_t sz_payload = ip_tot_len - ip_hdr_len - p_tcp_h->doff*4;
		ring_logfunc("Rx TCP segment info: src_port=%d, dst_port=%d, flags='%s%s%s%s%s%s' seq=%u, ack=%u, win=%u, payload_sz=%u",
				ntohs(p_tcp_h->source), ntohs(p_tcp_h->dest),
				p_tcp_h->urg?"U":"", p_tcp_h->ack?"A":"", p_tcp_h->psh?"P":"",
				p_tcp_h->rst?"R":"", p_tcp_h->syn?"S":"", p_tcp_h->fin?"F":"",
				ntohl(p_tcp_h->seq), ntohl(p_tcp_h->ack_seq), ntohs(p_tcp_h->window),
				sz_payload);

		// Update packet descriptor with datagram base address and length
		p_rx_wc_buf_desc->path.rx.frag.iov_base = (uint8_t*)p_tcp_h + sizeof(struct tcphdr);
		p_rx_wc_buf_desc->path.rx.frag.iov_len  = ip_tot_len - ip_hdr_len - sizeof(struct tcphdr);

		// Update the L4 info
		p_rx_wc_buf_desc->path.rx.src.sin_port        = p_tcp_h->source;
		p_rx_wc_buf_desc->path.rx.dst.sin_port        = p_tcp_h->dest;
		p_rx_wc_buf_desc->path.rx.sz_payload          = sz_payload;

		p_rx_wc_buf_desc->path.rx.p_ip_h = p_ip_h;
		p_rx_wc_buf_desc->path.rx.p_tcp_h = p_tcp_h;

		// Find the relevant hash map and pass the packet to the rfs for dispatching
		p_rfs = m_flow_tcp_map.get((flow_spec_tcp_key_t){p_rx_wc_buf_desc->path.rx.src.sin_addr.s_addr,
			p_rx_wc_buf_desc->path.rx.dst.sin_port, p_rx_wc_buf_desc->path.rx.src.sin_port}, NULL);

		p_rx_wc_buf_desc->transport_header_len = transport_header_len;

		if (unlikely(p_rfs == NULL)) {	// If we didn't find a match for TCP 5T, look for a match with TCP 3T
			p_rfs = m_flow_tcp_map.get((flow_spec_tcp_key_t){0, p_rx_wc_buf_desc->path.rx.dst.sin_port, 0}, NULL);
		}
	}
	break;

	case IPPROTO_IGMP:
	{
		struct igmp* p_igmp_h= (struct igmp*)((uint8_t*)p_ip_h + ip_hdr_len);
		ring_logdbg("Rx IGMP packet info: type=%s (%d), group=%d.%d.%d.%d, code=%d",
				priv_igmp_type_tostr(p_igmp_h->igmp_type), p_igmp_h->igmp_type,
				NIPQUAD(p_igmp_h->igmp_group.s_addr), p_igmp_h->igmp_code);
		if (transport_type == VMA_TRANSPORT_IB  || mce_sys.eth_mc_l2_only_rules) {
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

	if (p_rfs == NULL) {
		ring_logdbg("Rx packet dropped - rfs object not found: dst:%d.%d.%d.%d:%d, src%d.%d.%d.%d:%d, proto=%s[%d]",
				NIPQUAD(p_rx_wc_buf_desc->path.rx.dst.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->path.rx.dst.sin_port),
				NIPQUAD(p_rx_wc_buf_desc->path.rx.src.sin_addr.s_addr), ntohs(p_rx_wc_buf_desc->path.rx.src.sin_port),
				iphdr_protocol_type_to_str(p_ip_h->protocol), p_ip_h->protocol);

		return false;
	}
	return p_rfs->rx_dispatch_packet(p_rx_wc_buf_desc, pv_fd_ready_array);
}

int ring::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
	int ret = 1;
	if (likely(CQT_RX == cq_type)) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
				m_active_cq_mgr_rx->request_notification(poll_sn);
				++m_ring_stat_static.n_rx_interrupt_requests);
	}
	else {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_active_cq_mgr_tx->request_notification(poll_sn));
	}
	return ret;
}

int ring::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_active_cq_mgr_rx->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array));
	return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int ring::poll_and_process_element_tx(uint64_t* p_cq_poll_sn)
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_active_cq_mgr_tx->poll_and_process_element_tx(p_cq_poll_sn));
	return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

int ring::wait_for_notification_and_process_element(cq_type_t cq_type, int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = -1;
	if (likely(CQT_RX == cq_type)) {
		cq_mgr* p_cq_mgr = NULL;
		p_rx_channel_fd_to_ring_resources_t::iterator channel_iter = m_rx_channel_fd_to_ring_resources_map.find(cq_channel_fd);
		if (channel_iter != m_rx_channel_fd_to_ring_resources_map.end()) {
			ring_resources_map_t::iterator iter = channel_iter->second;
			p_cq_mgr = iter->second.m_p_cq_mgr_rx;
		}
		if (p_cq_mgr != NULL) {
			RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
					p_cq_mgr->wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array);
					++m_ring_stat_static.n_rx_interrupt_received);
		} else {
			ring_logerr("Can't find rx_cq for the rx_comp_event_channel_fd (= %d)", cq_channel_fd);
		}
	}
	else {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_active_cq_mgr_tx->wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array));
	}
	return ret;
}

bool ring::reclaim_recv_buffers(descq_t *rx_reuse)
{
	bool ret = false;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_active_cq_mgr_rx->reclaim_recv_buffers(rx_reuse));
	return ret;
}

bool ring::reclaim_recv_buffers_no_lock(descq_t *rx_reuse)
{
	return m_active_cq_mgr_rx->reclaim_recv_buffers_no_lock(rx_reuse);
}

bool ring::reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst)
{
	return m_active_cq_mgr_rx->reclaim_recv_buffers(rx_reuse_lst);
}

void ring::mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	m_active_cq_mgr_rx->mem_buf_desc_completion_with_error(p_rx_wc_buf_desc);
}

void ring::mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc)
{
	if (m_b_qp_tx_first_flushed_completion_handled) {
		p_tx_wc_buf_desc->p_next_desc = NULL; // All wr are flushed so we need to disconnect the Tx list
	}
	else {
		m_b_qp_tx_first_flushed_completion_handled = true; // This is true for all wr except for the first one which might point to already sent wr
	}
	m_tx_num_wr_free += mem_buf_tx_release(p_tx_wc_buf_desc);
}

void ring::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array /*NULL*/)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_rx, m_active_cq_mgr_rx->mem_buf_desc_return_to_owner(p_mem_buf_desc, pv_fd_ready_array));
}

void ring::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, m_tx_num_wr_free += put_tx_buffers(p_mem_buf_desc));
}

void ring::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, m_tx_num_wr_free += put_tx_single_buffer(p_mem_buf_desc));
}

int ring::drain_and_proccess(cq_type_t cq_type)
{
	int ret = 0;
	if (likely(CQT_RX == cq_type)) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_active_cq_mgr_rx->drain_and_proccess());
	}
	else {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_active_cq_mgr_tx->drain_and_proccess());
	}
	return ret;
}

mem_buf_desc_t* ring::mem_buf_tx_get(bool b_block, int n_num_mem_bufs /* default = 1 */)
{
	int ret = 0;
	mem_buf_desc_t* buff_list = NULL;
	uint64_t poll_sn;

	ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

	m_lock_ring_tx.lock();
	buff_list = get_tx_buffers(n_num_mem_bufs);
	while (!buff_list) {

		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_active_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, ret);
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
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			m_lock_ring_tx.lock();

			// poll once more (in the hope that we get a few freed tx mem_buf_desc)
			buff_list = get_tx_buffers(n_num_mem_bufs);
			if (!buff_list) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_active_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, 100);
					if (ret == 0) {
						m_lock_ring_tx_buf_wait.unlock();
						m_lock_ring_tx.lock();
						buff_list = get_tx_buffers(n_num_mem_bufs);
						continue;
					} else if (ret < 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						return NULL;
					}

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
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, errno);
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							return NULL;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
				buff_list = get_tx_buffers(n_num_mem_bufs);
			}
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
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

int ring::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting/*=false*/)
{
	ring_logfuncall("");
	m_lock_ring_tx.lock();
	int accounting = put_tx_buffers(p_mem_buf_desc_list);
	if (b_accounting)
		m_missing_buf_ref_count -= accounting;
	m_lock_ring_tx.unlock();
	return accounting;
}

int ring::get_max_tx_inline()
{
	return m_active_qp_mgr->get_max_inline_tx_data();
}

inline void ring::send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe)
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
		// Decrease counter in order to keep track of how many missing buffers we have when
		// doing ring->restart() and then drain_tx_buffers_to_buffer_pool()
		m_missing_buf_ref_count--;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

void ring::send_ring_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block)
{
	m_lock_ring_tx.lock();
	p_send_wqe->sg_list[0].lkey = m_tx_lkey;	// The ring keeps track of the current device lkey (In case of bonding event...)
	int ret = send_buffer(p_send_wqe, b_block);
	send_status_handler(ret, p_send_wqe);
	m_lock_ring_tx.unlock();
	return;
}

void ring::send_lwip_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block)
{
	m_lock_ring_tx.lock();
	p_send_wqe->sg_list[0].lkey = m_tx_lkey; // The ring keeps track of the current device lkey (In case of bonding event...)
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	p_mem_buf_desc->lwip_pbuf.pbuf.ref++;
	int ret = send_buffer(p_send_wqe, b_block);
	send_status_handler(ret, p_send_wqe);
	m_lock_ring_tx.unlock();
	return;
}

int ring::send_buffer(vma_ibv_send_wr* p_send_wqe, bool b_block)
{
	int ret = 0;
	if (is_available_qp_wr(b_block)) {
		ret = m_active_qp_mgr->send(p_send_wqe);
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

void ring::flow_udp_uc_del_all()
{
	flow_spec_udp_uc_key_t map_key_udp_uc;
	flow_spec_udp_uc_map_t::iterator itr_udp_uc;

	itr_udp_uc = m_flow_udp_uc_map.begin();
	while (itr_udp_uc != m_flow_udp_uc_map.end()) {
		rfs *p_rfs = itr_udp_uc->second;
		map_key_udp_uc = itr_udp_uc->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_uc_map.del(map_key_udp_uc))) {
			ring_logdbg("Could not find rfs object to delete in ring udp uc hash map!");
		}
		itr_udp_uc =  m_flow_udp_uc_map.begin();
	}
}

void ring::flow_udp_mc_del_all()
{
	flow_spec_udp_mc_key_t map_key_udp_mc;
	flow_spec_udp_mc_map_t::iterator itr_udp_mc;

	itr_udp_mc = m_flow_udp_mc_map.begin();
	while (itr_udp_mc != m_flow_udp_mc_map.end()) {
		rfs *p_rfs = itr_udp_mc->second;
		map_key_udp_mc = itr_udp_mc->first;
		if (p_rfs) {
			delete p_rfs;
		}
		if (!(m_flow_udp_mc_map.del(map_key_udp_mc))) {
			ring_logdbg("Could not find rfs object to delete in ring udp mc hash map!");
		}
		itr_udp_mc = m_flow_udp_mc_map.begin();
	}
}

void ring::flow_tcp_del_all()
{
	flow_spec_tcp_key_t map_key_tcp;
	flow_spec_tcp_map_t::iterator itr_tcp;

	itr_tcp = m_flow_tcp_map.begin();
	for (; itr_tcp != m_flow_tcp_map.end(); ++itr_tcp) {
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
bool ring::is_available_qp_wr(bool b_block)
{
	int ret = 0;
	uint64_t poll_sn;

	while (m_tx_num_wr_free <= 0) {
		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_active_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, ret);
			return false;
		} else if (ret > 0) {
			ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
		} else if (b_block){
			// Arm & Block on tx cq_mgr notification channel
			// until we get a few freed tx mem_buf_desc & data buffers

			// Only a single thread should block on next Tx cqe event, hence the dedicated lock!
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			m_lock_ring_tx.lock();

			if (m_tx_num_wr_free <= 0) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_active_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, -1);
					if (ret <= 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						m_lock_ring_tx.lock();
						return false;
					}

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
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_active_qp_mgr, m_active_cq_mgr_tx, errno);
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							m_lock_ring_tx.lock();
							return false;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
			}
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
			m_lock_ring_tx.lock();
		} else {
			return false;
		}
	}

	--m_tx_num_wr_free;
	return true;
}

//call under m_lock_ring_tx lock
bool ring::request_more_tx_buffers(uint32_t count)
{
	mem_buf_desc_t *p_temp_desc_list, *p_temp_buff;

	ring_logfuncall("Allocating additional %d buffers for internal use", count);

	//todo have get_buffers_thread_safe with given m_tx_pool as parameter, to save assembling and disassembling of buffer chain
	p_temp_desc_list = g_buffer_pool_tx->get_buffers_thread_safe(count, m_tx_lkey);
	if (p_temp_desc_list == NULL) {
		ring_logfunc("Out of mem_buf_desc from TX free pool for internal object pool");
		return false;
	}

	while (p_temp_desc_list) {
		p_temp_buff = p_temp_desc_list;
		p_temp_desc_list = p_temp_buff->p_next_desc;
		p_temp_buff->p_desc_owner = this;
		p_temp_buff->p_next_desc = NULL;
		m_tx_pool.push_back(p_temp_buff);
	}

	return true;
}

//call under m_lock_ring_tx lock
mem_buf_desc_t* ring::get_tx_buffers(uint32_t n_num_mem_bufs)
{
	mem_buf_desc_t* head = NULL;
	if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
		int count = MAX(RING_TX_BUFS_COMPENSATE, n_num_mem_bufs);
		if (request_more_tx_buffers(count)) {
			m_tx_num_bufs += count;
		}
	}

	if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
		return head;
	}

	head = m_tx_pool.back();
	m_tx_pool.pop_back();
	head->lwip_pbuf.pbuf.ref = 1;
	n_num_mem_bufs--;

	mem_buf_desc_t* next = head;
	while (n_num_mem_bufs) {
		next->p_next_desc = m_tx_pool.back();
		m_tx_pool.pop_back();
		next = next->p_next_desc;
		next->lwip_pbuf.pbuf.ref = 1;
		n_num_mem_bufs--;
	}

	return head;
}

//call under m_lock_ring_tx lock
int ring::put_tx_buffers(mem_buf_desc_t* buff_list)
{
	int count = 0;
	mem_buf_desc_t *next;

	while (buff_list) {
		next = buff_list->p_next_desc;
		buff_list->p_next_desc = NULL;

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff_list->lwip_pbuf.pbuf.ref))
			buff_list->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", buff_list);

		if (buff_list->lwip_pbuf.pbuf.ref == 0) {
			free_lwip_pbuf(&buff_list->lwip_pbuf);
			m_tx_pool.push_back(buff_list);
			count++;
		}
		buff_list = next;
	}

	if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&  m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
		int return_to_global_pool = m_tx_pool.size() / 2;
		m_tx_num_bufs -= return_to_global_pool;
		g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_to_global_pool);
	}

	return count;
}

//call under m_lock_ring_tx lock
int ring::put_tx_single_buffer(mem_buf_desc_t* buff)
{
	int count = 0;

	if (likely(buff)) {

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

	if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&  m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
		int return_to_global_pool = m_tx_pool.size() / 2;
		m_tx_num_bufs -= return_to_global_pool;
		g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_to_global_pool);
	}

	return count;
}

void ring::modify_cq_moderation(uint32_t period, uint32_t count)
{
	uint32_t period_diff = period > m_cq_moderation_info.period ?
			period - m_cq_moderation_info.period : m_cq_moderation_info.period - period;
	uint32_t count_diff = count > m_cq_moderation_info.count ?
			count - m_cq_moderation_info.count : m_cq_moderation_info.count - count;

	if (period_diff < (m_cq_moderation_info.period / 20) && (count_diff < m_cq_moderation_info.count / 20))
		return;

	m_cq_moderation_info.period = period;
	m_cq_moderation_info.count = count;

	m_ring_stat_static.n_rx_cq_moderation_period = period;
	m_ring_stat_static.n_rx_cq_moderation_count = count;

	//todo all cqs or just active? what about HA?
	m_active_cq_mgr_rx->modify_cq_moderation(period, count);
}

void ring::adapt_cq_moderation()
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
		modify_cq_moderation(mce_sys.cq_moderation_period_usec, mce_sys.cq_moderation_count);
		m_lock_ring_rx.unlock();
		return;
	}

	uint32_t avg_packet_size = interval_bytes / interval_packets;
	uint32_t avg_packet_rate = (interval_packets * 1000) / (mce_sys.cq_aim_interval_msec * (1 + missed_rounds));

	uint32_t ir_rate = mce_sys.cq_aim_interrupts_rate_per_sec;

	int count = MIN(avg_packet_rate / ir_rate, mce_sys.cq_aim_max_count);
	int period = MIN(mce_sys.cq_aim_max_period_usec, ((1000000 / ir_rate) - (1000000 / MAX(avg_packet_rate, ir_rate))));

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
