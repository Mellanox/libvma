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

#include <tr1/unordered_map>
#include <ifaddrs.h>

#include "config.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/vma_extra.h"
#include "vma/util/sock_addr.h"
#include "vma/util/vma_stats.h"
#include "vma/util/sys_vars.h"
#include "vma/util/wakeup_pipe.h"
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

#define SI_RX_EPFD_EVENT_MAX		16
#define BYTE_TO_KB(byte_value)		((byte_value) / 125)
#define KB_TO_BYTE(kbit_value)		((kbit_value) * 125)

struct buff_info_t {
		buff_info_t(){
			rx_reuse.set_id("buff_info_t (%p) : rx_reuse", this);
			n_buff_num = 0;
		}

       int     n_buff_num;
       descq_t     rx_reuse;
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

typedef std::tr1::unordered_map<ring*, ring_info_t*> rx_ring_map_t;

class sockinfo : public socket_fd_api, public pkt_rcvr_sink, public pkt_sndr_source, public wakeup_pipe
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

	virtual int add_epoll_context(epfd_info *epfd);
	virtual void remove_epoll_context(epfd_info *epfd);

	inline bool tcp_flow_is_5t(void) { return m_tcp_flow_is_5t; }
	inline void set_tcp_flow_is_5t(void) { m_tcp_flow_is_5t = true; }
	inline void set_flow_tag(int flow_tag_id) {
		if ( flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
			m_flow_tag_id = flow_tag_id;
			m_flow_tag_enabled = true;
		}
	}
	inline bool flow_tag_enabled(void) { return m_flow_tag_enabled; }
	inline int get_rx_epfd(void) { return m_rx_epfd; }
	
	virtual bool flow_in_reuse(void) { return false;};
	virtual int* get_rings_fds(int &res_length);
	virtual int get_rings_num();
	virtual int get_socket_network_ptr(void *ptr, uint16_t &len);

#ifdef DEFINED_SOCKETXTREME
	virtual bool check_rings() {return m_p_rx_ring ? true: false;}
#else
	virtual bool check_rings() {return true;}
	virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);
#endif

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
	ring*			m_p_rx_ring; //used in TCP/UDP
	buff_info_t		m_rx_reuse_buff; //used in TCP instead of m_rx_ring_map
	bool			m_rx_reuse_buf_pending; //used to periodically return buffers, even if threshold was not reached
	bool			m_rx_reuse_buf_postponed; //used to mark threshold was reached, but free was not done yet
	inline void		set_rx_reuse_pending(bool is_pending = true) {m_rx_reuse_buf_pending = is_pending;}

	rx_ring_map_t		m_rx_ring_map; // CQ map
	lock_mutex_recursive	m_rx_ring_map_lock;
	ring_allocation_logic_rx m_ring_alloc_logic;

	loops_timer             m_loops_timer;

	/**
	 * list of pending ready packet on the Rx,
	 * each element is a pointer to the ib_conn_mgr that holds this ready rx datagram
	 */
	int						m_n_rx_pkt_ready_list_count;
	size_t 					m_rx_pkt_ready_offset;
	size_t					m_rx_ready_byte_count;

	const int				m_n_sysvar_rx_num_buffs_reuse;
	const int32_t				m_n_sysvar_rx_poll_num;
	ring_alloc_logic_attr			m_ring_alloc_log_rx;
	ring_alloc_logic_attr			m_ring_alloc_log_tx;
	uint8_t					m_pcp;
#ifdef DEFINED_SOCKETXTREME
	/* Track internal events to return in socketxtreme_poll()
	 * Current design support single event for socket at a particular time
	 */
	struct ring_ec m_ec;
	struct vma_completion_t* m_socketxtreme_completion;
	struct vma_buff_t*       m_socketxtreme_last_buff_lst;
#endif // DEFINED_SOCKETXTREME

	// Callback function pointer to support VMA extra API (vma_extra.h)
	vma_recv_callback_t	m_rx_callback;
	void*			m_rx_callback_context; // user context
	struct vma_rate_limit_t m_so_ratelimit;
	void*			m_fd_context; // Context data stored with socket
	uint32_t		m_flow_tag_id;	// Flow Tag for this socket
	bool			m_flow_tag_enabled; // for this socket
	bool			m_tcp_flow_is_5t; // to bypass packet analysis

	int*			m_p_rings_fds;
	virtual void 		set_blocking(bool is_blocked);
	virtual int 		fcntl(int __cmd, unsigned long int __arg);
	virtual int 		ioctl(unsigned long int __request, unsigned long int __arg);
	virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	int setsockopt_kernel(int __level, int __optname, const void *__optval, socklen_t __optlen, int supported, bool allow_priv);
	virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);

	virtual	mem_buf_desc_t* get_front_m_rx_pkt_ready_list() = 0;
	virtual	size_t get_size_m_rx_pkt_ready_list() = 0;
	virtual	void pop_front_m_rx_pkt_ready_list() = 0;
	virtual	void push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff) = 0;

	int 			rx_wait(int &poll_count, bool is_blocking = true);
	int 			rx_wait_helper(int &poll_count, bool is_blocking = true);

	void 			save_stats_rx_os(int bytes);
	void 			save_stats_tx_os(int bytes);
	void 			save_stats_rx_offload(int nbytes);

	virtual int             rx_verify_available_data() = 0;
	virtual mem_buf_desc_t *get_next_desc (mem_buf_desc_t *p_desc) = 0;
	virtual	mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx) = 0;
	
	virtual void 	post_deqeue (bool release_buff) = 0;
	
	virtual int 	zero_copy_rx (iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) = 0;
	int 			register_callback(vma_recv_callback_t callback, void *context);

	virtual size_t		handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags, int* p_out_flags);

	bool 			attach_receiver(flow_tuple_with_local_if &flow_key);
	bool 			detach_receiver(flow_tuple_with_local_if &flow_key);
	net_device_resources_t* create_nd_resources(const ip_address ip_local);
	bool                    destroy_nd_resources(const ip_address ip_local);
	void			do_rings_migration();

	// Attach to all relevant rings for offloading receive flows - always used from slow path
	// According to bounded information we need to attach to all UC relevant flows
	// If local_ip is ANY then we need to attach to all offloaded interfaces OR to the one our connected_ip is routed to
	bool			attach_as_uc_receiver(role_t role, bool skip_rules = false);
	virtual void		set_rx_packet_processor(void) = 0;
	transport_t 		find_target_family(role_t role, struct sockaddr *sock_addr_first, struct sockaddr *sock_addr_second = NULL);

	// This callback will notify that socket is ready to receive and map the cq.
	virtual void		rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false);
	virtual void 		rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false);

	virtual void		lock_rx_q() {m_lock_rcv.lock();}
	virtual void		unlock_rx_q() {m_lock_rcv.unlock();}

	void 			destructor_helper();
	int 			modify_ratelimit(dst_entry* p_dst_entry, struct vma_rate_limit_t &rate_limit);

	void 			move_owned_rx_ready_descs(const mem_buf_desc_owner* p_desc_owner, descq_t* toq); // Move all owner's rx ready packets ro 'toq'
	void			set_sockopt_prio(__const void *__optval, socklen_t __optlen);

	virtual bool try_un_offloading(); // un-offload the socket if possible
#ifdef DEFINED_SOCKETXTREME	
	virtual inline void do_wakeup()
	{
		/* TODO: Let consider if we really need this check */
		if (!check_vma_active()) {
			wakeup_pipe::do_wakeup();
		}
	}

	inline bool check_vma_active(void)
	{
		return (m_p_rx_ring && m_p_rx_ring->get_vma_active());
	}

	inline void set_events(uint64_t events)
	{
		/* Collect all events if rx ring is enabled */
		if (m_p_rx_ring) {
			if (m_socketxtreme_completion) {
				if (!m_socketxtreme_completion->events) {
					m_socketxtreme_completion->user_data = (uint64_t)m_fd_context;
				}
				m_socketxtreme_completion->events |= events;
			}
			else {
				if (!m_ec.completion.events) {
					m_ec.completion.user_data = (uint64_t)m_fd_context;
					m_p_rx_ring->put_ec(&m_ec);
				}
				m_ec.completion.events |= events;
			}
		}

		if ((uint32_t)events) {
			socket_fd_api::notify_epoll_context((uint32_t)events);
		}
	}

	inline uint64_t get_events(void)
	{
		return m_ec.completion.events;
	}

	inline void clear_events(void)
	{
		m_ec.completion.events = 0;
	}
#endif // DEFINED_SOCKETXTREME	

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
		                  int in_flags, int *p_out_flags)
	{
		mem_buf_desc_t *pdesc;
		int total_rx = 0;
		uint32_t nbytes, pos;
		bool relase_buff = true;

		bool is_peek = in_flags & MSG_PEEK;
		int rx_pkt_ready_list_idx = 1;
		int rx_pkt_ready_offset = m_rx_pkt_ready_offset;

		pdesc = get_front_m_rx_pkt_ready_list();
		void *iov_base = (uint8_t*)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
		size_t bytes_left = pdesc->rx.frag.iov_len - m_rx_pkt_ready_offset;
		size_t payload_size = pdesc->rx.sz_payload;

		if (__from && __fromlen)
			fetch_peer_info(&pdesc->rx.src, __from, __fromlen);

		if (in_flags & MSG_VMA_ZCOPY) {
			relase_buff = false;
			total_rx = zero_copy_rx(p_iov, pdesc, p_out_flags);
			if (unlikely(total_rx < 0))
				return -1;
			m_rx_pkt_ready_offset = 0;	
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
							iov_base = pdesc->rx.frag.iov_base;
							bytes_left = pdesc->rx.frag.iov_len;
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

		total_rx = handle_msg_trunc(total_rx, payload_size, in_flags, p_out_flags);

        return total_rx;
    }

    inline void reuse_buffer(mem_buf_desc_t *buff)
    {
    	set_rx_reuse_pending(false);
    	ring* p_ring = ((ring*)(buff->p_desc_owner))->get_parent();
    	rx_ring_map_t::iterator iter = m_rx_ring_map.find(p_ring);
    	if(likely(iter != m_rx_ring_map.end())){
            descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
            int& n_buff_num = iter->second->rx_reuse_info.n_buff_num;
            rx_reuse->push_back(buff);
            n_buff_num += buff->rx.n_frags;
            if(n_buff_num < m_n_sysvar_rx_num_buffs_reuse){
        	    return;
            }
            if(n_buff_num >= 2 * m_n_sysvar_rx_num_buffs_reuse){
                if (p_ring->reclaim_recv_buffers(rx_reuse)) {
                    n_buff_num = 0;
                } else {
                	g_buffer_pool_rx->put_buffers_after_deref_thread_safe(rx_reuse);
                	n_buff_num = 0;
                }
                m_rx_reuse_buf_postponed = false;
            } else {
                m_rx_reuse_buf_postponed = true;
            }
        }
        else{
            // Retuned buffer to global pool when owner can't be found
            // In case ring was deleted while buffers where still queued
            vlog_printf(VLOG_DEBUG, "Buffer owner not found\n");
            // Awareness: these are best efforts: decRef without lock in case no CQ
            if(buff->dec_ref_count() <= 1 && (buff->lwip_pbuf.pbuf.ref-- <= 1))
                g_buffer_pool_rx->put_buffers_thread_safe(buff);

        }
    }

    inline void return_reuse_buffers_postponed()
    {
	    if (!m_rx_reuse_buf_postponed)
		    return;

            //for the parallel reclaim mechanism from internal thread, used for "silent" sockets
	    set_rx_reuse_pending(false);

            m_rx_reuse_buf_postponed = false;

	    if (m_p_rx_ring) {
		    if (m_rx_reuse_buff.n_buff_num >= m_n_sysvar_rx_num_buffs_reuse) {
			    if (m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
			    	   m_rx_reuse_buff.n_buff_num = 0;
			    } else {
				   m_rx_reuse_buf_postponed = true;
			    }	
		    }
	    } else {
		    rx_ring_map_t::iterator iter = m_rx_ring_map.begin();
		    while (iter != m_rx_ring_map.end()) {
		            descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
		            int& n_buff_num = iter->second->rx_reuse_info.n_buff_num;
			    if (n_buff_num >= m_n_sysvar_rx_num_buffs_reuse) {
				    if (iter->first->reclaim_recv_buffers(rx_reuse)) {
					    n_buff_num = 0;
				    } else {
					    m_rx_reuse_buf_postponed = true;
				    }
			    }
			    ++iter;
		    }
	    }
    }

    inline void move_owned_descs(ring* p_desc_owner, descq_t *toq, descq_t *fromq)
    {
    	// Assume locked by owner!!!

    	mem_buf_desc_t *temp;
    	const size_t size = fromq->size();
    	for (size_t i = 0 ; i < size; i++) {
    		temp = fromq->front();
    		fromq->pop_front();
    		if (p_desc_owner->is_member(temp->p_desc_owner))
    			toq->push_back(temp);
    		else
    			fromq->push_back(temp);
    	}
    }

    inline void move_not_owned_descs(ring* p_desc_owner, descq_t *toq, descq_t *fromq)
    {
    	// Assume locked by owner!!!

    	mem_buf_desc_t *temp;
    	const size_t size = fromq->size();
    	for (size_t i = 0 ; i < size; i++) {
    		temp = fromq->front();
    		fromq->pop_front();
    		if (p_desc_owner->is_member(temp->p_desc_owner))
    			fromq->push_back(temp);
    		else
    			toq->push_back(temp);
    	}
    }


    int			get_sock_by_L3_L4(in_protocol_t protocol, in_addr_t ip, in_port_t  port);

    //////////////////////////////////////////////////////////////////
    int handle_exception_flow(){
		if (safe_mce_sys().exception_handling.is_suit_un_offloading()) {
			try_un_offloading();
		}
		if (safe_mce_sys().exception_handling == vma_exception_handling::MODE_RETURN_ERROR) {
			errno = EINVAL;
			return -1;
		}
		if (safe_mce_sys().exception_handling == vma_exception_handling::MODE_ABORT) {
			return -2;
		}
		return 0;
    }
    //////////////////////////////////////////////////////////////////
};

#ifdef DEFINED_SOCKETXTREME
#define NOTIFY_ON_EVENTS(context, events) context->set_events(events)
#else
#define NOTIFY_ON_EVENTS(context, events) context->notify_epoll_context(events)
#endif // DEFINED_SOCKETXTREME

#endif /* BASE_SOCKINFO_H */
