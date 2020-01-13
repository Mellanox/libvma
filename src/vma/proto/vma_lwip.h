/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef _VMA_LWIP_H
#define _VMA_LWIP_H

#include "vma/event/timer_handler.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "vma/lwip/tcp.h"

typedef enum vma_wr_tx_packet_attr {
	/* 8 bits are reserved for TCP flags (see lwip/tcp.h)
	 * this option should be synchronized with lwip/tcp value
	 */
	/* retransmit operation. */
	VMA_TX_PACKET_REXMIT  = TCP_WRITE_REXMIT, /* 0x08 */
	/* nop send operation. */
	VMA_TX_PACKET_DUMMY   = TCP_WRITE_DUMMY, /* 0x10 */
	/* large segment offload operation. */
	VMA_TX_PACKET_TSO  = TCP_WRITE_TSO, /* 0x20 */
	/* sendfile operation. */
	VMA_TX_FILE  = TCP_WRITE_FILE, /* 0x40 */

	/* MLX5_ETH_WQE_L3_CSUM offload to HW L3 (IP) header checksum */
	VMA_TX_PACKET_L3_CSUM = (1 << 6), /* hardcoded values. It is the same as VMA_TX_FILE but there is no conflict */
	/* MLX5_ETH_WQE_L4_CSUM offload to HW L4 (TCP/UDP) header checksum */
	VMA_TX_PACKET_L4_CSUM = (1 << 7), /* hardcoded values */
	/* blocking send operation */
	VMA_TX_PACKET_BLOCK   = (1 << 8),
	/* Force SW checksum */
	VMA_TX_SW_CSUM        = (1 << 9),
} vma_wr_tx_packet_attr;

static inline bool is_set(vma_wr_tx_packet_attr state_, vma_wr_tx_packet_attr tx_mode_)
{
	return (uint32_t)state_ & (uint32_t)tx_mode_;
}

static inline const char* lwip_cc_algo_str(uint32_t algo)
{
	switch (algo) {
	case CC_MOD_CUBIC:	return "(CUBIC)";
	case CC_MOD_NONE:	return "(NONE)";
	case CC_MOD_LWIP:
	default:		return "(LWIP)";
	}
}

class vma_lwip : public timer_handler
{
public:
	vma_lwip();
	virtual ~vma_lwip();

	virtual void handle_timer_expired(void* user_data);

	static u32_t sys_now(void);

private:
	bool		m_run_timers;
	
	void		free_lwip_resources(void);

	static u8_t read_tcp_timestamp_option(void);
};

extern vma_lwip *g_p_lwip;

uint32_t get_lwip_tcp_mss(uint32_t mtu, uint32_t lwip_mss);

#endif
