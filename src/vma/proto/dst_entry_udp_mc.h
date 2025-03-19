/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef DST_ENTRY_UDP_MC_H
#define DST_ENTRY_UDP_MC_H

#include "vma/proto/dst_entry_udp.h"

class dst_entry_udp_mc : public dst_entry_udp
{
public:
	dst_entry_udp_mc(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port,
			in_addr_t mc_tx_if_ip, bool mc_b_loopback, socket_data &sock_data,
			resource_allocation_key &ring_alloc_logic);
	virtual ~dst_entry_udp_mc();

	virtual bool 	conf_l2_hdr_and_snd_wqe_ib();

protected:
	ip_address 	m_mc_tx_if_ip;
	bool 		m_b_mc_loopback_enabled;

	virtual void	set_src_addr();
	virtual bool 	resolve_net_dev(bool is_connect=false);
};

#endif /* DST_ENTRY_UDP_MC_H */
