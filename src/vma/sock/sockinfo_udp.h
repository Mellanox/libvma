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


#ifndef SOCKINFO_H
#define SOCKINFO_H

#include <list>
#include <vector>
#include <tr1/unordered_map>
#include <netinet/in.h>

#include "vlogger/vlogger.h"
#include "vma/vma_extra.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/vma_stats.h"
#include "vma/util/sys_vars.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/proto/dst_entry_udp.h"

#include "pkt_rcvr_sink.h"
#include "pkt_sndr_source.h"
#include "sock-redirect.h"
#include "sockinfo.h"


#define MAX_RX_MEM_BUF_DESC	32

extern int g_n_os_igmp_max_membership;

// Send flow dst_entry map
namespace std {
 namespace tr1 {
  template<>
   class hash<sock_addr>
   {
   public:
	size_t operator()(const sock_addr &key) const
	{
		sock_addr* tmp_key = (sock_addr*)&key;
		return tmp_key->hash();
	}
   };
 }
}
typedef std::tr1::unordered_map<sock_addr, dst_entry*> dst_entry_map_t;

// Multicast Request list
typedef std::list<struct ip_mreq> ip_mreq_list_t;
typedef std::tr1::unordered_map<in_addr_t, int> mc_memberships_map_t;

struct cmsg_state
{
	struct msghdr	*mhdr;
	struct cmsghdr	*cmhdr;
	size_t		cmsg_bytes_consumed;
};

/**
 * @class udp sockinfo
 * Represents an udp socket.
 */
class sockinfo_udp : public sockinfo
{
public:
	sockinfo_udp(int fd);
	virtual ~sockinfo_udp();

	void 	setPassthrough() { m_sock_offload = false;}
	bool 	isPassthrough()  { return ! m_sock_offload;}

	int 	prepare_to_connect(const sockaddr *__to, socklen_t __tolen);

	int	bind(const struct sockaddr *__addr, socklen_t __addrlen);
	int	connect(const struct sockaddr *__to, socklen_t __tolen);
	int	getsockname(struct sockaddr *__name = NULL, socklen_t *__namelen = NULL);
	int	setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	int	getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);

	/**
	* Sampling the OS immediately by matching the rx_skip_os counter (m_rx_udp_poll_os_ratio_counter) to the limit (mce_sys.rx_udp_poll_os_ratio)
	*/
	void	set_immediate_os_sample();
	/**
	 * Reseting rx_skip_os counter to prevent sampling OS immediately
	 */
	void	unset_immediate_os_sample();
	/**
	 * Process a Rx request, we might have a ready packet, or we might block until
	 * we have one (if sockinfo::m_b_blocking == true)
	 */
	ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags, sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);
	/**
	 * Check that a call to this sockinfo rx() will not block
	 * -> meaning, we got an offloaded ready rx datagram
	 * Return 'true' if would not block, 'false' if might block.
	 *
	 * While polling CQ, the fd_array is filled with a list of newly queued packets FD's
	 */
	bool is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = NULL);
	/**
	 * Arm the event channel(s) assosiated with this sockinfo
	 * Fill the fd_set (p_rxfds) with the correct fd channel values and the p_nfds with the (max_fd + 1)
	 * Fill the p_cq_mgr_fd_map with the pointer to the cq_mgr asosiated with the fd
	 * Return count of channels (fds) that where mapped
	 */
	int rx_request_notification(uint64_t poll_sn);
	/**
	 * Process a Tx request, handle all that is needed to send the packet, we might block
	 * until the connection info is ready or a tx buffer is releast (if sockinfo::m_b_blocking == true)
	 */
	ssize_t tx(const tx_call_t call_type, const struct iovec *p_iov, const ssize_t sz_iov, const int flags = 0, const struct sockaddr *__to = NULL, const socklen_t __tolen = 0);
	/**
	 * Check that a call to this sockinof rx() will not block
	 * -> meaning, we got a ready rx packet
	 */
	bool tx_check_if_would_not_block();
	void rx_add_ring_cb(flow_tuple_with_local_if& flow_key, ring* p_ring, bool is_migration = false);
	void rx_del_ring_cb(flow_tuple_with_local_if& flow_key, ring* p_ring, bool is_migration = false);

	// This callback will handle ready rx packet notification from any ib_conn_mgr
	bool rx_input_cb(mem_buf_desc_t *p_rx_pkt_mem_buf_desc_info, void *pv_fd_ready_array = NULL);
	// This call will handle all rdma related events (bind->listen->connect_req->accept)
	void validate_igmpv2(flow_tuple_with_local_if& flow_key);
	int validate_igmpv2(char *ifname);
	void statistics_print();
	int register_callback(vma_recv_callback_t callback, void *context);
	int free_datagrams(void **pkt_desc_ids, size_t count);
	virtual inline fd_type_t get_type()
	{
		return FD_TYPE_SOCKET;
	}

private:

	struct port_socket_t {

		int port;
		int fd;

		bool operator== (const int& r_port)
		{
			return port == r_port;
		}
	};


/*	in_addr_t 	m_bound_if;
	in_port_t 	m_bound_port;
	in_addr_t 	m_connected_ip;
	in_port_t 	m_connected_port;
//*/
	in_addr_t 	m_mc_tx_if;
	bool 		m_b_mc_tx_loop;
	uint8_t 	m_n_mc_ttl;

	int32_t 	m_loops_to_go; // local param for polling loop on this socket
	uint32_t	m_rx_udp_poll_os_ratio_counter; 	// Data member which sets how many offloaded polls on the cq
							// we want to do before doing an OS poll, on this socket
	bool 		m_sock_offload;

	// Callback function pointer to support VMA extra API (vma_extra.h)
	vma_recv_callback_t m_rx_callback;
	void *m_rx_callback_context; // user context
	ip_mreq_list_t 	m_pending_mreqs;
	mc_memberships_map_t m_mc_memberships_map;

	lock_spin 	m_port_map_lock;
	std::vector<struct port_socket_t> m_port_map;
	unsigned 	m_port_map_index;

	dst_entry_map_t	m_dst_entry_map;

	bool		m_b_pktinfo;
	bool		m_b_rcvtstamp;
	bool		m_b_rcvtstampns;
	uint8_t		m_n_tsing_flags;

	int mc_change_membership(const struct ip_mreq *p_mreq, int optname);
	int mc_change_membership_start_helper(in_addr_t mc_grp, int optname);
	int mc_change_membership_end_helper(in_addr_t mc_grp, int optname);
	int mc_change_pending_mreq(const struct ip_mreq *p_mreq, int optname);
	void handle_pending_mreq();

	/* helper functions */
	void 		set_blocking(bool is_blocked);

	void 		rx_ready_byte_count_limit_update(size_t n_rx_ready_bytes_limit); // Drop rx ready packets from head of queue

	void 		save_stats_threadid_rx(); // ThreadId will only saved if logger is at least in DEBUG(4) level
	void 		save_stats_threadid_tx(); // ThreadId will only saved if logger is at least in DEBUG(4) level

	void 		save_stats_rx_offload(int bytes);
	void 		save_stats_tx_offload(int bytes, bool is_droped);

	int 		rx_wait_helper(int &poll_count, bool is_blocking);
	
	inline int 	rx_wait(bool blocking);
	inline ssize_t	poll_os();

	virtual 	mem_buf_desc_t*	get_next_desc (mem_buf_desc_t *p_desc);
	virtual		mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx);

	virtual void 	post_deqeue (bool release_buff);
	virtual int 	zero_copy_rx (iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags);
	virtual size_t	handle_msg_trunc(size_t total_rx, size_t payload_size, int* p_flags);

	inline void	handle_ip_pktinfo(struct cmsg_state *cm_state);
	inline void	handle_recv_timestamping(struct cmsg_state *cm_state);
	inline void	insert_cmsg(struct cmsg_state *cm_state, int level, int type, void *data, int len);
	inline void	handle_cmsg(struct msghdr * msg);
};
#endif
