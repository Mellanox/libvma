/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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
	virtual void	set_src_addr();
	virtual bool 	resolve_net_dev(bool is_connect=false);
};

#endif /* DST_ENTRY_UDP_MC_H */
