/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef TCP_SOCKINFO_H
#define TCP_SOCKINFO_H

#include "utils/lock_wrapper.h"
#include "vma/proto/peer_key.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/dev/buffer_pool.h"
#include "vma/dev/cq_mgr.h"
#include "vma/vma_extra.h"

// LWIP includes
#include "vma/lwip/opt.h"
#include "vma/lwip/tcp_impl.h"

#include "sockinfo.h"

/**
 * Tcp socket states: rdma_offload or os_passthrough. in rdma_offload:
 * init --/bind()/ --> bound -- /listen()/ --> accept_ready -- /accept()may go to connected/ --> connected
 * init --(optional: bind()/ -- /connect()|async_connect/--> connected --/close()/--> init
 * may need to handle bind before connect in the future
 */
enum tcp_sock_offload_e {
	TCP_SOCK_PASSTHROUGH = 1, // OS handling this socket connection
//	TCP_SOCK_RDMA_CM,         // Offloaded, uses RDMA CM - SDP like connection
	TCP_SOCK_LWIP             // Offloaded, uses LWIP for wire compatible TCP impl
};

enum tcp_sock_state_e {
	TCP_SOCK_INITED = 1,
	TCP_SOCK_BOUND,
	TCP_SOCK_LISTEN_READY,    // internal state that indicate that prepareListen was called
	TCP_SOCK_ACCEPT_READY,
	TCP_SOCK_CONNECTED_RD,    // ready to rcv
	TCP_SOCK_CONNECTED_WR,    // ready to send
	TCP_SOCK_CONNECTED_RDWR,  // full duplex op
	TCP_SOCK_ASYNC_CONNECT,   // async connect in progress
	TCP_SOCK_ACCEPT_SHUT      // after shutdown on TCP_SOCK_ACCEPT_READY socket
};

/**
 * state machine for the connect() side connection establishment. Taken from VMS
 */
enum tcp_conn_state_e {
	TCP_CONN_INIT = 0,
	TCP_CONN_CONNECTING,
	TCP_CONN_CONNECTED,
	TCP_CONN_FAILED,
	TCP_CONN_TIMEOUT,
	TCP_CONN_ERROR,
	TCP_CONN_RESETED
};

struct socket_option_t {
	const int level;
	const int optname;
	const socklen_t optlen;
	void *optval;

	socket_option_t(const int _level, const int _optname, const void *_optval, const socklen_t _optlen) :
		level(_level), optname(_optname), optlen(_optlen), optval(malloc(optlen)) {
		memcpy(optval, _optval, optlen);
	}

	~socket_option_t() { if (optval) free(optval); }
};

typedef std::deque<socket_option_t*> socket_options_list_t;
typedef std::map<tcp_pcb*, int> ready_pcb_map_t;
typedef std::map<flow_tuple, tcp_pcb*> syn_received_map_t;
typedef std::map<peer_key, vma_desc_list_t> peer_map_t;

/* taken from inet_ecn.h in kernel */
enum inet_ecns {
	INET_ECN_NOT_ECT = 0,
	INET_ECN_ECT_1 = 1,
	INET_ECN_ECT_0 = 2,
	INET_ECN_CE = 3,
	INET_ECN_MASK = 3,
};

class sockinfo_tcp : public sockinfo, public timer_handler
{
public:
	static inline size_t accepted_conns_node_offset(void) {return NODE_OFFSET(sockinfo_tcp, accepted_conns_node);}
	typedef vma_list_t<sockinfo_tcp, sockinfo_tcp::accepted_conns_node_offset> sock_list_t;
	sockinfo_tcp(int fd);
	virtual ~sockinfo_tcp();

	virtual void clean_obj();

	void setPassthrough(bool _isPassthrough = true) {
		m_sock_offload = _isPassthrough ? TCP_SOCK_PASSTHROUGH : TCP_SOCK_LWIP;
		m_p_socket_stats->b_is_offloaded = ! _isPassthrough;
	}
	bool isPassthrough()  {return m_sock_offload == TCP_SOCK_PASSTHROUGH;}

	int prepareListen();
	int shutdown(int __how);

	//Not always we can close immediately TCP socket: we can do that only after the TCP connection in closed.
	//In this method we just kikstarting the TCP connection termination (empty the unsent/unacked, senf FIN...)
	//Return val: true is the socket is already closable and false otherwise
	virtual bool prepare_to_close(bool process_shutdown = false);
	virtual void force_close();
	void create_dst_entry();
	bool prepare_dst_to_send(bool is_accepted_socket = false);

	virtual int fcntl(int __cmd, unsigned long int __arg);
	virtual int ioctl(unsigned long int __request, unsigned long int __arg);
	virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);
	int getsockopt_offload(int __level, int __optname, void *__optval, socklen_t *__optlen);
	virtual int connect(const sockaddr*, socklen_t);
	virtual int bind(const sockaddr *__addr, socklen_t __addrlen);
	virtual int listen(int backlog);
	virtual int accept(struct sockaddr *__addr, socklen_t *__addrlen);
	virtual int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags);
	virtual int getsockname(sockaddr *__name, socklen_t *__namelen);
	virtual int getpeername(sockaddr *__name, socklen_t *__namelen);

	virtual	int	free_packets(struct vma_packet_t *pkts, size_t count);

	/* This function is used for socketxtreme mode */
	virtual int free_buffs(uint16_t len);

	virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);	

	//Returns the connected pcb, with 5 tuple which matches the input arguments,
	//in state "SYN Received" or NULL if pcb wasn't found

	struct tcp_pcb* get_syn_received_pcb(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr, in_port_t dest_port);

	ssize_t tx(const tx_call_t call_type, const iovec *p_iov, const ssize_t sz_iov, const int flags = 0, const struct sockaddr *__to = NULL, const socklen_t __tolen = 0);
	ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags, sockaddr *__from = NULL, socklen_t *__fromlen = NULL, struct msghdr *__msg = NULL);
#ifdef DEFINED_TSO
	static err_t ip_output(struct pbuf *p, void* v_p_conn, uint16_t flags);
	static err_t ip_output_syn_ack(struct pbuf *p, void* v_p_conn, uint16_t flags);
#else
	static err_t ip_output(struct pbuf *p, void* v_p_conn, int is_rexmit, uint8_t is_dummy);
	static err_t ip_output_syn_ack(struct pbuf *p, void* v_p_conn, int is_rexmit, uint8_t is_dummy);
#endif /* DEFINED_TSO */
	static void tcp_state_observer(void* pcb_container, enum tcp_state new_state);
	static uint16_t get_route_mtu(struct tcp_pcb *pcb);

	virtual void update_header_field(data_updater *updater);
	virtual bool rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array);
	virtual void set_rx_packet_processor(void) { }

	static struct pbuf * tcp_tx_pbuf_alloc(void* p_conn);
	static void tcp_tx_pbuf_free(void* p_conn, struct pbuf *p_buff);
	static struct tcp_seg * tcp_seg_alloc(void* p_conn);
	static void tcp_seg_free(void* p_conn, struct tcp_seg * seg);

	bool inline is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = NULL);
	bool inline is_writeable();
	bool inline is_errorable(int *errors);
	bool is_closable() { return get_tcp_state(&m_pcb) == CLOSED && m_syn_received.empty() && m_accepted_conns.empty(); }
	bool skip_os_select()
	{
		// calling os select on offloaded TCP sockets makes no sense unless it's a listen socket
		// to make things worse, it returns that os fd is ready...
		return (m_sock_offload == TCP_SOCK_LWIP && !is_server() && m_conn_state != TCP_CONN_INIT);
	}

	bool is_connected()
	{
		return m_sock_state == TCP_SOCK_CONNECTED_RDWR;
	}

	inline bool is_rtr()
	{
		return (m_n_rx_pkt_ready_list_count || m_sock_state == TCP_SOCK_CONNECTED_RD || m_sock_state == TCP_SOCK_CONNECTED_RDWR);
	}

	bool is_rts()
	{
		//ready to send
		return m_sock_state == TCP_SOCK_CONNECTED_WR || m_sock_state == TCP_SOCK_CONNECTED_RDWR;
	}

	bool is_server()
	{
		return m_sock_state == TCP_SOCK_ACCEPT_READY || m_sock_state == TCP_SOCK_ACCEPT_SHUT;
	}

	virtual void update_socket_timestamps(timestamps_t * ts)
	{
		m_rx_timestamps = *ts;
	}

	static const int CONNECT_DEFAULT_TIMEOUT_MS = 10000;
	virtual inline fd_type_t get_type()
	{
		return FD_TYPE_SOCKET;
	}

	void handle_timer_expired(void* user_data);

	list_node<sockinfo_tcp, sockinfo_tcp::accepted_conns_node_offset> accepted_conns_node;

protected:
	virtual void		lock_rx_q();
	virtual void		unlock_rx_q();
	virtual bool try_un_offloading(); // un-offload the socket if possible

private:
	//lwip specific things
	struct tcp_pcb m_pcb;
	socket_options_list_t m_socket_options_list;
	timestamps_t m_rx_timestamps;
	tcp_sock_offload_e m_sock_offload;
	tcp_sock_state_e m_sock_state;
	sockinfo_tcp *m_parent;
	//received packet source (true if its from internal thread)
	bool m_vma_thr;
	/* connection state machine */
	int m_conn_timeout;
	/* SNDBUF acconting */
	int m_sndbuff_max;
	/* RCVBUF acconting */
	int m_rcvbuff_max;
	int m_rcvbuff_current;
	int m_rcvbuff_non_tcp_recved;
	tcp_conn_state_e m_conn_state;
	fd_array_t* m_iomux_ready_fd_array;
	struct linger m_linger;

	/* local & peer addresses */
/*	struct sockaddr *m_addr_local;
	socklen_t m_local_alen;
	struct sockaddr *m_addr_peer;
	socklen_t m_peer_alen;
*/

	//Relevant only for listen sockets: map connections in syn received state
	//We need this map since for syn received connection no sockinfo is created yet!
	syn_received_map_t m_syn_received;
	uint32_t m_received_syn_num;

	/* pending connections */
	sock_list_t m_accepted_conns;

	uint32_t m_ready_conn_cnt;
	int m_backlog;

	void *m_timer_handle;
	lock_spin_recursive m_tcp_con_lock;
	bool m_timer_pending;

	bool report_connected; //used for reporting 'connected' on second non-blocking call to connect.

	int m_call_orig_close_on_dtor;

	int m_error_status;

	const buffer_batching_mode_t m_sysvar_buffer_batching_mode;
	const tcp_ctl_thread_t m_sysvar_tcp_ctl_thread;
	const internal_thread_tcp_timer_handling_t m_sysvar_internal_thread_tcp_timer_handling;

	struct tcp_seg * m_tcp_seg_list;
	int m_tcp_seg_count;
	int m_tcp_seg_in_use;

	vma_desc_list_t	m_rx_pkt_ready_list;
	vma_desc_list_t m_rx_cb_dropped_list;

	lock_spin_recursive m_rx_ctl_packets_list_lock;
	tscval_t	m_last_syn_tsc;
	vma_desc_list_t m_rx_ctl_packets_list;
	peer_map_t      m_rx_peer_packets;
	vma_desc_list_t m_rx_ctl_reuse_list;
	ready_pcb_map_t m_ready_pcbs;
	static const unsigned TX_CONSECUTIVE_EAGAIN_THREASHOLD = 10;
	unsigned	m_tx_consecutive_eagain_count;
	bool		m_sysvar_rx_poll_on_tx_tcp;

	inline void init_pbuf_custom(mem_buf_desc_t *p_desc);

	inline void lock_tcp_con();
	inline void unlock_tcp_con();
	void tcp_timer();

	bool prepare_listen_to_close();

	//Builds rfs key
	static void create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb);

	//auto accept function
	static void auto_accept_connection(sockinfo_tcp *parent, sockinfo_tcp *child);

	// accept cb func
	static err_t accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err);

	//Called when legal syn is received in order to remember the new active pcb which
	//is already created by lwip, but no sockinfo instance is created yet at this stage
	static err_t syn_received_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err);

	static err_t syn_received_drop_lwip_cb(void *arg, struct tcp_pcb *newpcb, err_t err);

	static err_t clone_conn_cb(void *arg, struct tcp_pcb **newpcb, err_t err);

	int accept_helper(struct sockaddr *__addr, socklen_t *__addrlen, int __flags = 0);

	// clone socket in accept call
	sockinfo_tcp *accept_clone();
	// connect() helper & callback func
	int wait_for_conn_ready();
	static err_t connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err);
	//tx
	unsigned tx_wait(int & err, bool is_blocking);

	void abort_connection();
	int handle_child_FIN(sockinfo_tcp* child_conn);

	//rx
	//int rx_wait(int &poll_count, bool is_blocking = true);
	static err_t ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t space);
	static err_t rx_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
	static err_t rx_drop_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
        
	// Be sure that m_pcb is initialized
	void set_conn_properties_from_pcb();
	void set_sock_options(sockinfo_tcp *new_sock);

	//Register to timer
	void register_timer();

	void handle_socket_linger();

	/*
	 * Supported only for UDP
	 */
	virtual void handle_ip_pktinfo(struct cmsg_state *) {};

	int handle_rx_error(bool is_blocking);

	/** Function prototype for tcp error callback functions. Called when the pcb
	 * receives a RST or is unexpectedly closed for any other reason.
	 *
	 * @note The corresponding pcb is already freed when this callback is called!
	 *
	 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
	 * @param err Error code to indicate why the pcb has been closed
	 *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
	 *            ERR_RST: the connection was reset by the remote host
	 */
	static void 	err_lwip_cb(void *arg, err_t err);

	// TODO: it is misleading to declare inline in file that doesn't contain the implementation as it can't help callers
	inline void 	return_pending_rx_buffs();
	inline void 	return_pending_tx_buffs();
	inline void 	reuse_buffer(mem_buf_desc_t *buff);
	virtual mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc);
	virtual	mem_buf_desc_t* get_next_desc_peek(mem_buf_desc_t *p_desc, int& rx_pkt_ready_list_idx);
	virtual timestamps_t* get_socket_timestamps();

	inline void return_reuse_buffers_postponed() {
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

	virtual void 	post_deqeue(bool release_buff);
	virtual int 	zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags);
	struct tcp_pcb* get_syn_received_pcb(const flow_tuple &key) const;
	struct tcp_pcb* get_syn_received_pcb(in_addr_t src_addr, in_port_t src_port, in_addr_t dest_addr,
            							 in_port_t dest_port, int protocol, in_addr_t local_addr);

	virtual	mem_buf_desc_t* get_front_m_rx_pkt_ready_list();
	virtual	size_t get_size_m_rx_pkt_ready_list();
	virtual	void pop_front_m_rx_pkt_ready_list();
	virtual	void push_back_m_rx_pkt_ready_list(mem_buf_desc_t* buff);

	// stats
	uint64_t m_n_pbufs_rcvd;
	uint64_t m_n_pbufs_freed;

	//lock_spin_recursive m_rx_cq_lck;
	/* pick all cqs that match given address */
	virtual int	rx_verify_available_data();
	inline int 	rx_wait(int & poll_count, bool is_blocking);
	inline int 	rx_wait_lockless(int & poll_count, bool is_blocking);
	int 		rx_wait_helper(int & poll_count, bool is_blocking);
	void 		fit_rcv_wnd(bool force_fit);
	void 		fit_snd_bufs(unsigned int new_max);
	void 		fit_snd_bufs_to_nagle(bool disable_nagle);

	inline struct tcp_seg * get_tcp_seg();
	inline void put_tcp_seg(struct tcp_seg * seg);

	void queue_rx_ctl_packet(struct tcp_pcb* pcb, mem_buf_desc_t *p_desc);
	bool process_peer_ctl_packets(vma_desc_list_t &peer_packets);
	void process_my_ctl_packets();
	void process_children_ctl_packets();
	void process_reuse_ctl_packets();
	void process_rx_ctl_packets();
	bool check_dummy_send_conditions(const int flags, const iovec* p_iov, const ssize_t sz_iov);
	static void put_agent_msg(void *arg);
};
typedef struct tcp_seg tcp_seg;

class tcp_seg_pool : lock_spin {
public:
	tcp_seg_pool(int size);
	virtual ~tcp_seg_pool();

	tcp_seg * get_tcp_segs(int amount);
	void put_tcp_segs(tcp_seg * seg_list);
	
private:
	tcp_seg *	m_tcp_segs_array;
	tcp_seg *	m_p_head;
	void		free_tsp_resources(void);
};

extern tcp_seg_pool* g_tcp_seg_pool;


class tcp_timers_collection : public timers_group , public cleanable_obj {
public:
	tcp_timers_collection(int period, int resolution);
	virtual ~tcp_timers_collection();

	void clean_obj();

	virtual void handle_timer_expired(void* user_data);

protected:
	// add a new timer
	void add_new_timer(timer_node_t* node, timer_handler* handler, void* user_data);

	// remove timer from list and free it.
	// called for stopping (unregistering) a timer
	void remove_timer(timer_node_t* node);

private:
	void* m_timer_handle;
	timer_node_t** m_p_intervals;

	int m_n_period;
	int m_n_resolution;
	int m_n_intervals_size;
	int m_n_location;
	int m_n_count;
	int m_n_next_insert_bucket;

	void free_tta_resources();
};

extern tcp_timers_collection* g_tcp_timers_collection;

#endif
