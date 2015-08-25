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

ring::ring(in_addr_t local_if, uint16_t partition_sn, int count, transport_type_t transport_type) :
		m_p_ring_stat(NULL), m_local_if(local_if), m_transport_type(transport_type), m_n_num_resources(count), m_p_tx_comp_event_channel(NULL),
		m_lock_ring_rx("ring:lock_rx"), m_lock_ring_tx("ring:lock_tx"), m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait"),
		m_p_n_rx_channel_fds(NULL), m_tx_num_bufs(0), m_tx_num_wr(0), m_tx_num_wr_free(0), m_b_qp_tx_first_flushed_completion_handled(false),
		m_missing_buf_ref_count(0), m_tx_lkey(0), m_partition(partition_sn), m_gro_mgr(mce_sys.gro_streams_max, MAX_GRO_BUFS), m_up(false),
		m_parent(NULL)
{
	 // coverity[uninit_member]
	m_tx_pool.set_id("ring (%p) : m_tx_pool", this);
}

int	ring::get_num_resources() const {
	return m_n_num_resources;
}

int* ring::get_rx_channel_fds() const {
	return m_p_n_rx_channel_fds;
}

transport_type_t ring::get_transport_type() const {
	return m_transport_type;
}

ring* ring::get_parent() {
	return m_parent;
}
