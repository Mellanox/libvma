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


#ifndef _VMA_LWIP_H
#define _VMA_LWIP_H

#include <list>
#include <deque>
#include <net/ethernet.h>
#include "vma/event/timer_handler.h"
#include "vma/util/hash_map.h"
#include "vma/util/libvma.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/sock/pkt_rcvr_sink.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

class buffer_pool;

#define TCP_RX_POLL_TO_MS 1000

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

static inline int is_mcast_mac(const uint8_t *addr)
{
        return (0x01 & addr[0]);
}

static inline int is_bcast_mac(const uint8_t *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef deque<pbuf*> pbuf_queueu_t;

class vma_lwip : 
	public lock_spin_recursive, public timer_handler
{
public:
	vma_lwip();
	virtual ~vma_lwip();

	static int sockaddr2ipaddr(const sockaddr *__to, socklen_t __tolen, ip_addr_t & ip, uint16_t & port);
	void do_timers();

	const std::deque<ibv_mr*> *get_memory_regions() const
	{
	    return &m_mrs;
	}

	static err_t vma_lwip_netif_init(struct netif *lwip_if);
	static u16_t vma_ip_route_mtu(ip_addr_t *dest);

	//RX: feed packet to the LWIP stack
	static int  vma_tcp_input(mem_buf_desc_t* p_rx_wc_buf_desc, tcp_pcb* p_conn, void* pv_fd_ready_array);

	virtual void handle_timer_expired(void* user_data);

private:

	/// List of memory regions
	std::deque<ibv_mr*> m_mrs;

	buffer_pool     *m_tx_bufs;

	bool		m_run_timers;
};

extern vma_lwip *g_p_lwip;

#endif
