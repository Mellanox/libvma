/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include "data_updater.h"

data_updater::~data_updater()
{

}

header_ttl_updater::header_ttl_updater(uint8_t ttl, bool is_multicast)
	: data_updater()
	, m_ttl(ttl)
	, m_is_multicast(is_multicast)
{

}

bool header_ttl_updater::update_field(dst_entry &dst)
{
	if ((IN_MULTICAST_N(dst.get_dst_addr()) && m_is_multicast) ||
	    (!IN_MULTICAST_N(dst.get_dst_addr()) && !m_is_multicast)) {
		dst.set_ip_ttl(m_ttl);
	}
	return true;
}

header_pcp_updater::header_pcp_updater(uint8_t pcp)
	: data_updater()
	, m_pcp(pcp)
{

}

bool header_pcp_updater::update_field(dst_entry &dst)
{
	return dst.set_pcp(m_pcp);
}

header_tos_updater::header_tos_updater(uint8_t tos)
	: data_updater()
	, m_tos(tos)
{

}

bool header_tos_updater::update_field(dst_entry &dst)
{
	dst.set_ip_tos(m_tos);
	return true;
}

ring_alloc_logic_updater::ring_alloc_logic_updater(int fd, lock_base & socket_lock,
						   resource_allocation_key & ring_alloc_logic,
						   socket_stats_t* socket_stats)
	: data_updater()
	, m_fd(fd)
	, m_socket_lock(socket_lock)
	, m_key(ring_alloc_logic)
	, m_sock_stats(socket_stats)
{

}

bool ring_alloc_logic_updater::update_field(dst_entry &dst)
{
	if (dst.update_ring_alloc_logic(m_fd, m_socket_lock, m_key))
		m_sock_stats->counters.n_tx_migrations++;

	return true;
}
