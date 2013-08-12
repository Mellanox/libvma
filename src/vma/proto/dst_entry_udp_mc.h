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


#ifndef DST_ENTRY_UDP_MC_H
#define DST_ENTRY_UDP_MC_H

#include "vma/proto/dst_entry_udp.h"

class dst_entry_udp_mc : public dst_entry_udp
{
public:
	dst_entry_udp_mc(in_addr_t dst_ip, uint16_t dst_port, uint16_t src_port, in_addr_t mc_tx_if_ip, bool mc_b_loopback, uint8_t mc_ttl, int owner_fd);
	virtual ~dst_entry_udp_mc();

	void 		set_mc_tx_if_ip(in_addr_t tx_if_ip);
	void 		set_mc_loopback(bool b_mc_loopback);
	void 		set_mc_ttl(uint8_t mc_ttl);
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	inline in_addr_t get_mc_tx_if_ip() const { return m_mc_tx_if_ip.get_in_addr(); };
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
	virtual bool 	conf_l2_hdr_and_snd_wqe_ib();

protected:
	ip_address 	m_mc_tx_if_ip;
	bool 		m_b_mc_loopback_enabled;

	virtual bool 	get_net_dev_val();

	virtual bool 	resolve_net_dev();
};

#endif /* DST_ENTRY_UDP_MC_H */
