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


#include "vma/dev/rfs_mc.h"
#include "vma/util/utils.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME 		"rfs_mc"


rfs_mc::rfs_mc(flow_tuple *flow_spec_5t, ring *p_ring, rfs_rule_filter* rule_filter /*= NULL*/) : rfs (flow_spec_5t, p_ring, rule_filter)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!m_flow_tuple.is_udp_mc()) {
		rfs_logpanic("rfs: rfs_mc called with non MC destination ip");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	prepare_flow_spec();
}

void rfs_mc::prepare_flow_spec()
{
	transport_type_t type = m_p_ring->get_transport_type();

	ring_resources_map_t::iterator ring_resource_iter = m_p_ring->m_ring_resources_map.begin();
	for (; ring_resource_iter != m_p_ring->m_ring_resources_map.end(); ring_resource_iter++) {
		attach_flow_data_t* 		      p_attach_flow_data = NULL;
#ifdef DEFINED_IBV_FLOW_SPEC_IB
		attach_flow_data_ib_t*  	      attach_flow_data_ib = NULL;
#endif
		attach_flow_data_eth_ipv4_tcp_udp_t*  attach_flow_data_eth = NULL;

		switch (type) {
			case VMA_TRANSPORT_IB:
				// IB MC flow steering is done only on L2 --> need to zero other fields to get correct behaviour
				// CX3 HW does not support L3+L4 MC flow steering rule
#ifdef DEFINED_IBV_FLOW_SPEC_IB
				attach_flow_data_ib = new attach_flow_data_ib_t(ring_resource_iter->second.m_p_qp_mgr);

				uint8_t dst_gid[16];
				create_mgid_from_ipv4_mc_ip(dst_gid, ring_resource_iter->second.m_p_qp_mgr->get_partiton(), m_flow_tuple.get_dst_ip());
				ibv_flow_spec_ib_set_by_dst_gid(&(attach_flow_data_ib->ibv_flow_attr.ib),
							dst_gid);

				p_attach_flow_data = (attach_flow_data_t*)attach_flow_data_ib;
#else
				rfs_logerr("IB multicast offload is not supported");
#endif
				break;
			case VMA_TRANSPORT_ETH:
				attach_flow_data_eth = new attach_flow_data_eth_ipv4_tcp_udp_t(ring_resource_iter->second.m_p_qp_mgr);

				uint8_t dst_mac[6];
				create_multicast_mac_from_ip(dst_mac, m_flow_tuple.get_dst_ip());
				ibv_flow_spec_eth_set(&(attach_flow_data_eth->ibv_flow_attr.eth),
							dst_mac,
						        htons(ring_resource_iter->second.m_p_qp_mgr->get_partiton()));

				if (mce_sys.eth_mc_l2_only_rules) {
					ibv_flow_spec_ipv4_set(&(attach_flow_data_eth->ibv_flow_attr.ipv4), 0, 0);
					ibv_flow_spec_tcp_udp_set(&(attach_flow_data_eth->ibv_flow_attr.tcp_udp), 0, 0, 0);
					p_attach_flow_data = (attach_flow_data_t*)attach_flow_data_eth;
					break;
				}

				ibv_flow_spec_ipv4_set(&(attach_flow_data_eth->ibv_flow_attr.ipv4),
							m_flow_tuple.get_dst_ip(),
							0);

				ibv_flow_spec_tcp_udp_set(&(attach_flow_data_eth->ibv_flow_attr.tcp_udp),
							(m_flow_tuple.get_protocol() == PROTO_TCP),
							m_flow_tuple.get_dst_port(),
							m_flow_tuple.get_src_port());

				p_attach_flow_data = (attach_flow_data_t*)attach_flow_data_eth;
				break;
			BULLSEYE_EXCLUDE_BLOCK_START
			default:
				rfs_logpanic("Incompatible transport type = %d", type);
				break;
			BULLSEYE_EXCLUDE_BLOCK_END
		}

		m_attach_flow_data_vector.push_back(p_attach_flow_data);
	}
}

bool rfs_mc::rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
{
	// Dispatching: Notify new packet to all registered receivers
	p_rx_wc_buf_desc->reset_ref_count();

	for (uint32_t i=0; i < m_n_sinks_list_entries; ++i) {
		if (m_sinks_list[i]) {
			m_sinks_list[i]->rx_input_cb(p_rx_wc_buf_desc, pv_fd_ready_array);
		}
	}

	// Check packet ref_count to see if any receivers are interested in this packet
	if (p_rx_wc_buf_desc->get_ref_count() > 0) {
		// The sink will be responsible to return the buffer to CQ for reuse
		return true;
	}

	// Reuse this data buffer & mem_buf_desc
	return false;
}
