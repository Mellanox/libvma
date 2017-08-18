/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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

#include <list>
#include <net/ethernet.h>
#include <sys/param.h>
#include "vma/event/timer_handler.h"
#include "vma/util/hash_map.h"
#include "vma/util/libvma.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "vma/lwip/tcp.h"

typedef enum vma_wr_tx_packet_attr {
	/* blocking send operation */
	VMA_TX_PACKET_BLOCK   = (1 << 0),
	/* nop send operation. this option should be synchronized with lwip/tcp value */
	VMA_TX_PACKET_DUMMY   = TCP_WRITE_DUMMY,
	/* retransmit operation. */
	VMA_TX_PACKET_REXMIT  = TCP_WRITE_REXMIT,
	/* large segment offload operation. */
	VMA_TX_PACKET_TSO  = TCP_WRITE_TSO,
	/* MLX5_ETH_WQE_L3_CSUM offload to HW L3 (IP) header checksum */
	VMA_TX_PACKET_L3_CSUM = (1 << 6),
	/* MLX5_ETH_WQE_L4_CSUM offload to HW L4 (TCP/UDP) header checksum */
	VMA_TX_PACKET_L4_CSUM = (1 << 7),
} vma_wr_tx_packet_attr;

class buffer_pool;

#define TCP_RX_POLL_TO_MS 1000

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

static inline bool is_set(vma_wr_tx_packet_attr state_, vma_wr_tx_packet_attr tx_mode_)
{
	return (uint32_t)state_ & (uint32_t)tx_mode_;
}

static inline int is_mcast_mac(const uint8_t *addr)
{
        return (0x01 & addr[0]);
}

static inline int is_bcast_mac(const uint8_t *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

static inline const char* lwip_cc_algo_str(uint32_t algo)
{
	switch (algo) {
	case CC_MOD_CUBIC:	return "(CUBIC)";
	case CC_MOD_LWIP:
	default:		return "(LWIP)";
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif


class vma_lwip : 
	public lock_spin_recursive, public timer_handler
{
public:
	vma_lwip();
	virtual ~vma_lwip();

	static int sockaddr2ipaddr(const sockaddr *__to, socklen_t __tolen, ip_addr_t & ip, uint16_t & port);
	void do_timers();

	//RX: feed packet to the LWIP stack
	static int  vma_tcp_input(mem_buf_desc_t* p_rx_wc_buf_desc, tcp_pcb* p_conn, void* pv_fd_ready_array);

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
