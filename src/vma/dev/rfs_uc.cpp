/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#include "vma/dev/rfs_uc.h"
#include "vma/proto/L2_address.h"
#include "vma/util/bullseye.h"
#include "vma/dev/ring_simple.h"
#include "util/instrumentation.h"

#define MODULE_NAME 		"rfs_uc"


rfs_uc::rfs_uc(flow_tuple *flow_spec_5t, ring_simple *p_ring, rfs_rule_filter* rule_filter, uint32_t flow_tag_id) :
	rfs(flow_spec_5t, p_ring, rule_filter, flow_tag_id)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_flow_tuple.is_udp_mc()) {
		rfs_logpanic("rfs: rfs_uc called with MC destination ip");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	prepare_flow_spec();

}

void rfs_uc::prepare_flow_spec()
{
	transport_type_t type = m_p_ring->get_transport_type();

	/*
	 * todo note that ring is not locked here.
	 * we touch members that should not change during the ring life.
	 * the ring will not be deleted as we increased refcnt.
	 * if one of these assumptions change, we must lock.
	 */
	attach_flow_data_t* 		       p_attach_flow_data = NULL;
	attach_flow_data_ib_ipv4_tcp_udp_t*    attach_flow_data_ib = NULL;
	attach_flow_data_eth_ipv4_tcp_udp_t*   attach_flow_data_eth = NULL;
	vma_ibv_flow_spec_ipv4*             p_ipv4 = NULL;
	vma_ibv_flow_spec_tcp_udp*          p_tcp_udp = NULL;
	vma_ibv_flow_spec_action_tag*       p_flow_tag = NULL;

	switch (type) {
		case VMA_TRANSPORT_IB:
			attach_flow_data_ib = new attach_flow_data_ib_ipv4_tcp_udp_t(m_p_ring->m_p_qp_mgr);

#ifdef DEFINED_IBV_FLOW_SPEC_IB
			ibv_flow_spec_ib_set_by_dst_qpn(&(attach_flow_data_ib->ibv_flow_attr.ib),
						htonl(((IPoIB_addr*)m_p_ring->m_p_l2_addr)->get_qpn()));
#endif
			p_ipv4 = &(attach_flow_data_ib->ibv_flow_attr.ipv4);
			p_tcp_udp = &(attach_flow_data_ib->ibv_flow_attr.tcp_udp);
			p_attach_flow_data = (attach_flow_data_t*)attach_flow_data_ib;
			break;
		case VMA_TRANSPORT_ETH:
			attach_flow_data_eth = new attach_flow_data_eth_ipv4_tcp_udp_t(m_p_ring->m_p_qp_mgr);

			ibv_flow_spec_eth_set(&(attach_flow_data_eth->ibv_flow_attr.eth),
						m_p_ring->m_p_l2_addr->get_address(),
						htons(m_p_ring->m_p_qp_mgr->get_partiton()));
			p_ipv4 = &(attach_flow_data_eth->ibv_flow_attr.ipv4);
			p_tcp_udp = &(attach_flow_data_eth->ibv_flow_attr.tcp_udp);
			p_flow_tag = &(attach_flow_data_eth->ibv_flow_attr.flow_tag);
			p_attach_flow_data = (attach_flow_data_t*)attach_flow_data_eth;
			break;
		BULLSEYE_EXCLUDE_BLOCK_START
		default:
			rfs_logpanic("Incompatible transport type = %d", type);
			break;
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	ibv_flow_spec_ipv4_set(p_ipv4,
				m_flow_tuple.get_dst_ip(),
				m_flow_tuple.get_src_ip());

	ibv_flow_spec_tcp_udp_set(p_tcp_udp,
				(m_flow_tuple.get_protocol() == PROTO_TCP),
				m_flow_tuple.get_dst_port(),
				m_flow_tuple.get_src_port());

	if (m_flow_tuple.get_src_port() || m_flow_tuple.get_src_ip()) {
		// set priority of 5-tuple to be higher than 3-tuple
		// to make sure 5-tuple have higher priority on ConnectX-4
		p_attach_flow_data->ibv_flow_attr.priority = 0;
	}

	if (m_flow_tag_id && attach_flow_data_eth) {
		ibv_flow_spec_flow_tag_set(p_flow_tag, m_flow_tag_id);
		attach_flow_data_eth->ibv_flow_attr.add_flow_tag_spec();
	}

	m_attach_flow_data_vector.push_back(p_attach_flow_data);
}

bool rfs_uc::rx_dispatch_packet(mem_buf_desc_t* p_rx_wc_buf_desc, void* pv_fd_ready_array)
{
	// Dispatching: Notify new packet to the FIRST registered receiver ONLY
	p_rx_wc_buf_desc->reset_ref_count();
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET
	//for (uint32_t i=0; i < m_n_sinks_list_entries; ++i) {
		if (likely(m_sinks_list[0])) {
			p_rx_wc_buf_desc->inc_ref_count();
			m_sinks_list[0]->rx_input_cb(p_rx_wc_buf_desc, pv_fd_ready_array);
#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_DISPATCH_PACKET]);
#endif //RDTSC_MEASURE_RX_DISPATCH_PACKET
			// Check packet ref_count to see the last receiver is interested in this packet
			if (p_rx_wc_buf_desc->dec_ref_count() > 1) {
				// The sink will be responsible to return the buffer to CQ for reuse
				return true;
			}
		}
	//}

	// Reuse this data buffer & mem_buf_desc
	return false;
}
