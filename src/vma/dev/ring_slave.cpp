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

#include "ring_slave.h"


#undef  MODULE_NAME
#define MODULE_NAME "ring_slave"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "


ring_slave::ring_slave(int if_index, ring* parent, ring_type_t type): ring()
{
	net_device_val* p_ndev = NULL;
	const slave_data_t * p_slave = NULL;

	/* Configure ring() fields */
	set_parent(parent);
	set_if_index(if_index);

	/* Sanity check */
	p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	if (NULL == p_ndev) {
		ring_logpanic("Invalid if_index = %d", if_index);
	}

	p_slave = p_ndev->get_slave(get_if_index());
	if (NULL == p_slave) {
		ring_logpanic("Invalid if_index = %d", if_index);
	}

	/* Configure ring_slave() fields */
	m_type = type;
	m_transport_type = p_ndev->get_transport_type();
	m_active = p_slave->active;

	// use local copy of stats by default
	m_p_ring_stat = &m_ring_stat;
	memset(m_p_ring_stat, 0, sizeof(*m_p_ring_stat));
	m_p_ring_stat->n_type = m_type;
	if (m_parent != this) {
		m_ring_stat.p_ring_master = m_parent;
	}

	vma_stats_instance_create_ring_block(m_p_ring_stat);

	print_val();
}

ring_slave::~ring_slave()
{
	print_val();

	if (m_p_ring_stat) {
		vma_stats_instance_remove_ring_block(m_p_ring_stat);
	}
}

void ring_slave::print_val()
{
	ring_logdbg("%d: 0x%X: parent 0x%X type %s",
			m_if_index, this,
			((uintptr_t)this == (uintptr_t)m_parent ? 0 : m_parent),
			(m_type == RING_SIMPLE ? "simple" : "tap"));
}

void ring_slave::restart()
{
	ring_logpanic("Can't restart a slave ring");
}

bool ring_slave::is_active_member(mem_buf_desc_owner* rng, ring_user_id_t id)
{
	NOT_IN_USE(id);

	return (this == rng);
}

bool ring_slave::is_member(mem_buf_desc_owner* rng)
{
	return (this == rng);
}

ring_user_id_t ring_slave::generate_id()
{
	return 0;
}

ring_user_id_t ring_slave::generate_id(const address_t src_mac, const address_t dst_mac,
				uint16_t eth_proto, uint16_t encap_proto,
				uint32_t src_ip, uint32_t dst_ip,
				uint16_t src_port, uint16_t dst_port)
{
	NOT_IN_USE(src_mac);
	NOT_IN_USE(dst_mac);
	NOT_IN_USE(eth_proto);
	NOT_IN_USE(encap_proto);
	NOT_IN_USE(src_ip);
	NOT_IN_USE(dst_ip);
	NOT_IN_USE(src_port);
	NOT_IN_USE(dst_port);

	return 0;
}

void ring_slave::inc_tx_retransmissions(ring_user_id_t id) {
	NOT_IN_USE(id);
	m_p_ring_stat->simple.n_tx_retransmits++;
}
