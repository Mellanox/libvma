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


#include <list>
#include <tr1/unordered_map>
#include <ifaddrs.h>

#include "vlogger/vlogger.h"
#include "vma/vma_extra.h"
#include "vma/util/sock_addr.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/vma_stats.h"
#include "vma/util/sys_vars.h"
#include "vma/util/wakeup.h"
#include "vma/proto/flow_tuple.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/dst_entry.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/ring.h"
#include "vma/dev/ring_allocation_logic.h"

#include "socket_fd_api.h"
#include "pkt_rcvr_sink.h"
#include "pkt_sndr_source.h"
#include "sock-redirect.h"

#ifndef BASE_SOCKINFO_H
#define BASE_SOCKINFO_H

#define MAX_RX_MEM_BUF_DESC		32
#define SI_RX_EPFD_EVENT_MAX		16

struct buff_info_t {
       int     n_buff_num;
       std::deque<mem_buf_desc_t*>     rx_reuse;
};

typedef struct {
	net_device_entry* 	p_nde;
	net_device_val* 	p_ndv;
	ring* 			p_ring;
	int 			refcnt;
} net_device_resources_t;

typedef std::tr1::unordered_map<in_addr_t, net_device_resources_t> rx_net_device_map_t;


namespace std { namespace tr1 {
template<>
class hash<flow_tuple_with_local_if>
{
public:
	size_t operator()(const flow_tuple_with_local_if &key) const
	{
		flow_tuple_with_local_if* tmp_key = (flow_tuple_with_local_if*)&key;
		return tmp_key->hash();
	}
};
}}
typedef std::tr1::unordered_map<flow_tuple_with_local_if, ring*> rx_flow_map_t;

typedef struct {
	int 			refcnt;
	buff_info_t 		rx_reuse_info;
} ring_info_t;

typedef std::tr1::unordered_map<ring*, ring_info_t> rx_ring_map_t;

class sockinfo : public socket_fd_api, public pkt_rcvr_sink, public pkt_sndr_source, public wakeup
{
public:
	sockinfo(int fd);
	virtual ~sockinfo();

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	// don't put mt lock around sockinfo just yet
	void lock(){};
	void unlock() {};
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

	virtual void consider_rings_migration();

	virtual void add_epoll_context(epfd_info *epfd);
	virtual void remove_epoll_context(epfd_info *epfd);

protected:
	bool			m_b_closed;
	bool 			m_b_blocking;
	in_protocol_t		m_protocol;

	lock_spin_recursive	m_lock_rcv;
	lock_mutex		m_lock_snd;

	sock_addr 		m_bound;
	sock_addr 		m_connected;
	dst_entry*		m_p_connected_dst_entry;

	in_addr_t 		m_so_bindtodevice_ip;

	socket_stats_t		m_socket_stats;
	socket_stats_t*		m_p_socket_stats;

	int			m_rx_epfd;
	cache_observer 		m_rx_nd_observer;
	rx_net_device_map_t	m_rx_nd_map;
	rx_flow_map_t		m_rx_flow_map;
	// we either listen on ALL system cqs or bound to the specific cq
	ring*			m_p_rx_ring; //used in TCP instead of m_rx_ring_map
	buff_info_t		m_rx_reuse_buff; //used in TCP instead of m_rx_ring_map

	rx_ring_map_t		m_rx_ring_map; // CQ map
	lock_mutex_recursive	m_rx_ring_map_lock;
	ring_allocation_logic_rx m_ring_alloc_logic;

	loops_timer             m_loops_timer;

	/**
	 * list of pending ready packet on the Rx,
	 * each element is a pointer to the ib_conn_mgr that holds this ready rx datagram
	 */
	int			m_n_rx_pkt_ready_list_count;
	vma_desc_list_t		m_rx_pkt_ready_list;
	size_t 			m_rx_pkt_ready_offset;
	size_t			m_rx_ready_byte_count;

	int			m_rx_num_buffs_reuse;

	virtual void 		set_blocking(bool is_blocked);
	virtual int 		fcntl(int __cmd, unsigned long int __arg);
	virtual int 		ioctl(unsigned long int __request, unsigned long int __arg);


	int 			rx_wait(int &poll_count, bool is_blocking = true);
	int 			rx_wait_helper(int &poll_count, bool is_blocking = true);

	void 			save_stats_rx_os(int bytes);
	void 			save_stats_tx_os(int bytes);
	void 			save_stats_rx_offload(int nbytes);

	virtual mem_buf_desc_t *get_next_desc (mem_buf_desc_t *p_desc) = 0;
	virtual	mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx) = 0;
	virtual void 		post_deqeue (bool release_buff) = 0;
	virtual int 		zero_copy_rx (iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) = 0;
	virtual size_t		handle_msg_trunc(size_t total_rx, size_t payload_size, int* p_flags);

	bool 			attach_receiver(flow_tuple_with_local_if &flow_key);
	bool 			detach_receiver(flow_tuple_with_local_if &flow_key);
	void			do_rings_migration();

	// Attach to all relevant rings for offloading receive flows - always used from slow path
	// According to bounded information we need to attach to all UC relevant flows
	// If local_ip is ANY then we need to attach to all offloaded interfaces OR to the one our connected_ip is routed to
	void			attach_as_uc_receiver(role_t role, bool skip_rules = false);

	transport_t 		find_target_family(role_t role, struct sockaddr *sock_addr_first, struct sockaddr *sock_addr_second = NULL);

	// This callback will notify that socket is ready to receive and map the cq.
	virtual void		rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false);
	virtual void 		rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false);

	virtual void		lock_rx_q() {m_lock_rcv.lock();}
	virtual void		unlock_rx_q() {m_lock_rcv.unlock();}

	void 			destructor_helper();

	void 			move_owned_rx_ready_descs(const mem_buf_desc_owner* p_desc_owner, descq_t* toq); // Move all owner's rx ready packets ro 'toq'

	// This function validates the ipoib's properties
	// Input params:
	// 	1. IF name (can be alias)
	//	2. IF flags
	//	3. general path to ipoib property file (for example: /sys/class/net/%s/mtu)
	//	4. the expected value of the property
	//	5. size of the property
	// Output params:
	//	1. property sysfs filename
	//	2. physical IF name (stripped alias)
	// Return Value
	// Type: INT
	// Val:  -1 Reading from the sys file failed
	// 	 1 Reading succeeded but the actual prop value != expected
	//	 0 Reading succeeded and acutal ptop value == expected one
	//TODO need to copy this function from util
	//int validate_ipoib_prop(char* ifname, unsigned int ifflags, const char param_file[], const char *val, int size, char *filename, char * base_ifname);

	inline void fetch_peer_info(sockaddr_in *p_peer_addr, sockaddr_in *__from, socklen_t *__fromlen)
	{
		*__from = *p_peer_addr;
		*__fromlen = sizeof(sockaddr_in);
	}

	inline int dequeue_packet(iovec *p_iov, ssize_t sz_iov,
		                  sockaddr_in *__from, socklen_t *__fromlen,
		                  int *p_flags)
	{
		mem_buf_desc_t *pdesc;
		int total_rx = 0;
		uint32_t nbytes, pos;
		bool relase_buff = true;

		bool is_peek = *p_flags & MSG_PEEK;
		int rx_pkt_ready_list_idx = 1;
		int rx_pkt_ready_offset = m_rx_pkt_ready_offset;

		pdesc = m_rx_pkt_ready_list.front();
		void *iov_base = (uint8_t*)pdesc->path.rx.frag.iov_base + m_rx_pkt_ready_offset;
		size_t bytes_left = pdesc->path.rx.frag.iov_len - m_rx_pkt_ready_offset;
		size_t payload_size = pdesc->path.rx.sz_payload;

		if (__from && __fromlen)
			fetch_peer_info(&pdesc->path.rx.src, __from, __fromlen);

		if (*p_flags & MSG_VMA_ZCOPY) {
			relase_buff = false;
			total_rx = zero_copy_rx(p_iov, pdesc, p_flags);
			if (unlikely(total_rx < 0))
				return -1;
		}
		else {
			for (int i = 0; i < sz_iov && pdesc; i++) {
				pos = 0;
				while (pos < p_iov[i].iov_len && pdesc) {
					nbytes = p_iov[i].iov_len - pos;
					if (nbytes > bytes_left) nbytes = bytes_left;
					memcpy((char *)(p_iov[i].iov_base) + pos, iov_base, nbytes);
					pos += nbytes;
					total_rx += nbytes;
					m_rx_pkt_ready_offset += nbytes;
					bytes_left -= nbytes;
					iov_base = (uint8_t*)iov_base + nbytes;
					if(bytes_left <= 0) {
						if (unlikely(is_peek)) {
							pdesc = get_next_desc_peek(pdesc, rx_pkt_ready_list_idx);
						}else {
							pdesc = get_next_desc(pdesc);
						}
						m_rx_pkt_ready_offset = 0;
						if (pdesc) {
							iov_base = pdesc->path.rx.frag.iov_base;
							bytes_left = pdesc->path.rx.frag.iov_len;
						}
					}

				}
			}

		}

		if (unlikely(is_peek)) {
			m_rx_pkt_ready_offset = rx_pkt_ready_offset; //if MSG_PEEK is on, m_rx_pkt_ready_offset must be zero-ed
			//save_stats_rx_offload(total_rx); //TODO??
		}
		else {
			m_rx_ready_byte_count -= total_rx;
			m_p_socket_stats->n_rx_ready_byte_count -= total_rx;
			post_deqeue(relase_buff);
			save_stats_rx_offload(total_rx);
		}

		total_rx = handle_msg_trunc(total_rx, payload_size, p_flags);

        return total_rx;
    }

    inline void reuse_buffer(mem_buf_desc_t *buff)
    {
        ring* p_ring = (ring*)(buff->p_desc_owner);
        rx_ring_map_t::iterator iter = m_rx_ring_map.find(p_ring);
        if(likely(iter != m_rx_ring_map.end())){
            std::deque<mem_buf_desc_t*> *rx_reuse = &iter->second.rx_reuse_info.rx_reuse;
            rx_reuse->push_back(buff);
            iter->second.rx_reuse_info.n_buff_num += buff->n_frags;
            if(iter->second.rx_reuse_info.n_buff_num > m_rx_num_buffs_reuse){
                if (p_ring->reclaim_recv_buffers(rx_reuse)) {
                    iter->second.rx_reuse_info.n_buff_num = 0;
                } else if (iter->second.rx_reuse_info.n_buff_num > 2 * m_rx_num_buffs_reuse) {
                	g_buffer_pool_rx->put_buffers_thread_safe(rx_reuse, rx_reuse->size());
                	iter->second.rx_reuse_info.n_buff_num = 0;
                }
            }

        }
        else{
            // Retuned buffer to global pool when owner can't be found
            // In case ring was deleted while buffers where still queued
            vlog_printf(VLOG_DEBUG, "Buffer owner not found\n");
            // Awareness: these are best efforts: decRef without lock in case no CQ
            if(buff->dec_ref_count() <= 0 && (buff->lwip_pbuf.pbuf.ref-- <= 1))
                g_buffer_pool_rx->put_buffers_thread_safe(buff);

        }
    }

    int			get_sock_by_L3_L4(in_protocol_t protocol, in_addr_t ip, in_port_t  port);
};

#endif /* BASE_SOCKINFO_H */
