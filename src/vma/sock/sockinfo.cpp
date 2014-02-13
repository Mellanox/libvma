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


#include "sockinfo.h"

#include <sys/epoll.h>
#include <netdb.h>
#include <net/if.h>

#include "vlogger/vlogger.h"
#include "vma/proto/route_table_mgr.h"
#include "sock-redirect.h"
#include "fd_collection.h"
#include "vma/util/bullseye.h"


#define MODULE_NAME 		"si"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[fd=%d]:%d:%s() "
#undef	__INFO__
#define __INFO__		m_fd

#define si_logpanic		__log_info_panic
#define si_logerr		__log_info_err
#define si_logwarn		__log_info_warn
#define si_loginfo		__log_info_info
#define si_logdbg		__log_info_dbg
#define si_logfunc		__log_info_func
#define si_logfuncall		__log_info_funcall

#define si_logdbg_no_funcname(log_fmt, log_args...)	do { if (g_vlogger_level >= VLOG_DEBUG) vlog_printf(VLOG_DEBUG, MODULE_NAME "[fd=%d]:%d: " log_fmt "\n", m_fd, __LINE__, ##log_args); } while (0)

sockinfo::sockinfo(int fd):
		socket_fd_api(fd),
		m_b_closed(true), m_b_blocking(true), m_protocol(PROTO_UNDEFINED),
		m_lock_rcv(MODULE_NAME "::m_lock_rcv"),
		m_lock_snd(MODULE_NAME "::m_lock_snd"),
		m_p_rx_ring(0),
		m_rx_ring_map_lock(MODULE_NAME "::m_rx_ring_map_lock"),
		m_ring_alloc_logic(fd, this),
		m_n_rx_pkt_ready_list_count(0), m_rx_pkt_ready_offset(0), m_rx_ready_byte_count(0),
		m_rx_num_buffs_reuse(mce_sys.rx_num_wr_to_post_recv)
{
	m_rx_epfd = orig_os_api.epoll_create(128);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(m_rx_epfd == -1))
		si_logpanic("failed to create internal epoll (ret=%d %m)", m_rx_epfd);
	BULLSEYE_EXCLUDE_BLOCK_END

	wakeup_set_epoll_fd(m_rx_epfd);

        m_p_socket_stats = &m_socket_stats; // Save stats as local copy and allow state publisher to copy from this location
	vma_stats_instance_create_socket_block(m_p_socket_stats);
	memset(m_p_socket_stats, 0, sizeof(socket_stats_t));
	m_p_socket_stats->fd = m_fd;
	m_p_socket_stats->b_blocking = m_b_blocking;
	m_p_connected_dst_entry = NULL;
	m_so_bindtodevice_ip = 0;
	m_rx_reuse_buff.n_buff_num = 0;
	m_b_closed = false;
}

sockinfo::~sockinfo()
{
	if (m_n_rx_pkt_ready_list_count || m_rx_ready_byte_count || m_rx_pkt_ready_list.size() || m_rx_ring_map.size() || m_rx_reuse_buff.n_buff_num)
		si_logerr("not all buffers were freed. protocol=%s. m_n_rx_pkt_ready_list_count=%d, m_rx_ready_byte_count=%d, m_rx_pkt_ready_list.size()=%d, m_rx_ring_map.size()=%d, m_rx_reuse_buff.n_buff_num=%d",
				m_protocol == PROTO_TCP ? "TCP" : "UDP", m_n_rx_pkt_ready_list_count, m_rx_ready_byte_count, (int)m_rx_pkt_ready_list.size(), (int)m_rx_ring_map.size(), m_rx_reuse_buff.n_buff_num);

	m_b_closed = true;

	// Change to non-blocking socket so calling threads can exit
	m_b_blocking = false;
	orig_os_api.close(m_rx_epfd); // this will wake up any blocked thread in rx() call to orig_os_api.epoll_wait()
        vma_stats_instance_remove_socket_block(m_p_socket_stats);
}

void sockinfo::set_blocking(bool is_blocked)
{
	if (is_blocked) {
		si_logdbg("set socket to blocked mode");
		m_b_blocking = true;
	}
	else {
		si_logdbg("set socket to non-blocking mode");
		m_b_blocking = false;
	}

	// Update statistics info
	m_p_socket_stats->b_blocking = m_b_blocking;
}

int sockinfo::fcntl(int __cmd, unsigned long int __arg)
{
	switch (__cmd) {
	case F_SETFL:
		{
			si_logdbg("cmd=F_SETFL, arg=%#x", __arg);
			if (__arg & O_NONBLOCK)
				set_blocking(false);
			else
				set_blocking(true);
		}
		break;
	case F_GETFL:		/* Get file status flags.  */
		si_logfunc("cmd=F_GETFL, arg=%#x", __arg);
		break;

	case F_GETFD:		/* Get file descriptor flags.  */
		si_logfunc("cmd=F_GETFD, arg=%#x", __arg);
		break;

	case F_SETFD:		/* Set file descriptor flags.  */
		si_logfunc("cmd=F_SETFD, arg=%#x", __arg);
		break;

	default:
		si_logfunc("cmd=%d, arg=%#x", __cmd, __arg);
		break;
	}
	return orig_os_api.fcntl(m_fd, __cmd, __arg);
}

int sockinfo::ioctl(unsigned long int __request, unsigned long int __arg)
{

	int *p_arg = (int *)__arg;

	switch (__request) {
	case FIONBIO:
		{
			si_logdbg("request=FIONBIO, arg=%d", *p_arg);
			if (*p_arg)
				set_blocking(false);
			else
				set_blocking(true);
		}
		break;

	default:
	        si_logdbg("unimplemented ioctl request=%d, flags=%x", __request, __arg);
		break;
	}

	return orig_os_api.ioctl(m_fd, __request, __arg);
}

int sockinfo::get_sock_by_L3_L4(in_protocol_t protocol, in_addr_t ip, in_port_t  port)
{
	int map_size = g_p_fd_collection->get_fd_map_size();
	for (int i = 0; i < map_size; i++) {
		socket_fd_api* p_sock_i = g_p_fd_collection->get_sockfd(i);
		if (!p_sock_i || p_sock_i->get_type() != FD_TYPE_SOCKET) continue;
		sockinfo* s = (sockinfo*)p_sock_i;
		if (protocol == s->m_protocol && ip == s->m_bound.get_in_addr() && port == s->m_bound.get_in_port()) return i;
	}
	return -1;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
int sockinfo::rx_wait(int &poll_count, bool is_blocking)
{
	int ret_val = 0;
	ret_val = rx_wait_helper(poll_count, is_blocking);
	return ret_val;
}

int sockinfo::rx_wait_helper(int &poll_count, bool is_blocking)
{
	int ret;
	uint64_t poll_sn;
	epoll_event rx_epfd_events[SI_RX_EPFD_EVENT_MAX];
	rx_ring_map_t::iterator rx_ring_iter;

	// poll for completion
	si_logfunc("");

	poll_count++;

	for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
		//BULLSEYE_EXCLUDE_BLOCK_START
		if (unlikely(rx_ring_iter->second.refcnt <= 0)) {
			si_logpanic("Attempted to poll illegal cq");
		}
		//BULLSEYE_EXCLUDE_BLOCK_END
		ret = rx_ring_iter->first->poll_and_process_element_rx(&poll_sn);
		if (ret > 0) {
			si_logfuncall("got %d elements sn=%llu", ret, (unsigned long long)poll_sn);
			return ret;
		}
	}

	if (poll_count < mce_sys.rx_poll_num || mce_sys.rx_poll_num == -1) {
		return 0;
	}

	// if we polling too much - go to sleep
	si_logfunc("too many polls without data blocking=%d", is_blocking);
	if (g_b_exit)
		return -1;

	if (!is_blocking) {
		/* if we are in non blocking mode - return EAGAIN */
		errno = EAGAIN;
		return -1;
	}

	for (rx_ring_iter = m_rx_ring_map.begin(); rx_ring_iter != m_rx_ring_map.end(); rx_ring_iter++) {
		if (rx_ring_iter->second.refcnt <= 0) {
			continue;
		}
		ret = rx_ring_iter->first->request_notification(CQT_RX, poll_sn);
	}

	ret = orig_os_api.epoll_wait(m_rx_epfd, rx_epfd_events, SI_RX_EPFD_EVENT_MAX, -1);

	if (ret < 0)
		return -1;
	if (ret == 0)
		return 0;

	for (int event_idx = 0; event_idx < ret; ++event_idx) {
		int cq_channel_fd = rx_epfd_events[event_idx].data.fd;
		cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(cq_channel_fd);
		if (p_cq_ch_info) {
			ring* p_ring = p_cq_ch_info->get_ring();
			if (p_ring) {
				p_ring->wait_for_notification_and_process_element(CQT_RX, cq_channel_fd, &poll_sn);
			}
		}

		// TODO: need to handle wakeup
	}
	return 0;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void sockinfo::save_stats_rx_offload(int nbytes)
{
	if (nbytes >= 0) {
		m_p_socket_stats->counters.n_rx_bytes += nbytes;
		m_p_socket_stats->counters.n_rx_packets++;
	}
	else if (errno == EAGAIN) {
		m_p_socket_stats->counters.n_rx_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_rx_errors++;
	}
}

void sockinfo::save_stats_rx_os(int bytes)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_rx_os_bytes += bytes;
		m_p_socket_stats->counters.n_rx_os_packets++;
	}else if ( errno == EAGAIN ){
		m_p_socket_stats->counters.n_rx_os_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_rx_os_errors++;
	}
}

void sockinfo::save_stats_tx_os(int bytes)
{
	if (bytes >= 0) {
		m_p_socket_stats->counters.n_tx_os_bytes += bytes;
		m_p_socket_stats->counters.n_tx_os_packets++;
	}else if ( errno == EAGAIN ){
		m_p_socket_stats->counters.n_rx_os_eagain++;
	}
	else {
		m_p_socket_stats->counters.n_tx_os_errors++;
	}
}

size_t sockinfo::handle_msg_trunc(size_t total_rx, size_t payload_size, int* p_flags)
{
	NOT_IN_USE(payload_size);
	*p_flags &= ~MSG_TRUNC; //don't handle msg_trunc
	return total_rx;
}

bool sockinfo::attach_receiver(flow_tuple_with_local_if &flow_key)
{
	// This function should be called from within mutex protected context of the sockinfo!!!

	si_logdbg("Attaching to %s", flow_key.to_str());

	// Protect against local loopback used as local_if & peer_ip
	// rdma_cm will accept it but we don't want to offload it
	if (flow_key.is_local_loopback()) {
		si_logdbg("VMA does not offload local loopback IP address");
		return false;
	}

	if (m_rx_flow_map.find(flow_key) != m_rx_flow_map.end()) {
		si_logdbg("already attached %s", flow_key.to_str());
		return false;
	}

	net_device_resources_t* p_nd_resources = NULL;

	// Check if we are already registered to net_device with the local ip as observers
	ip_address ip_local(flow_key.get_local_if());
	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
	if (rx_nd_iter == m_rx_nd_map.end()) {

		// Need to register as observer to net_device
		net_device_resources_t nd_resources;
		nd_resources.refcnt = 0;
		nd_resources.p_nde = NULL;
		nd_resources.p_ndv = NULL;
		nd_resources.p_ring = NULL;

		BULLSEYE_EXCLUDE_BLOCK_START
		cache_entry_subject<ip_address, net_device_val*>* p_ces = NULL;
		if (!g_p_net_device_table_mgr->register_observer(ip_local, &m_rx_nd_observer, &p_ces)) {
			si_logpanic("Failed registering as observer for local ip %s", ip_local.to_str().c_str());
			return false;
		}
		nd_resources.p_nde = (net_device_entry*)p_ces;
		if (!nd_resources.p_nde) {
			si_logpanic("Got NULL net_devide_entry for local ip %s", ip_local.to_str().c_str());
			return false;
		}
		if (!nd_resources.p_nde->get_val(nd_resources.p_ndv)) {
			si_logpanic("Got net_device_val=NULL (interface is not offloaded) for local ip %s", ip_local.to_str().c_str());
			return false;
		}

		unlock_rx_q();
		m_rx_ring_map_lock.lock();
		resource_allocation_key key = 0;
		if (m_rx_ring_map.size()) {
			key = m_ring_alloc_logic.get_key();
		} else {
			key = m_ring_alloc_logic.create_new_key();
		}
		nd_resources.p_ring = nd_resources.p_ndv->reserve_ring(key);
		m_rx_ring_map_lock.unlock();
		lock_rx_q();
		if (!nd_resources.p_ring) {
			si_logpanic("Failed to reserve ring for allocation key %d on lip %s", m_ring_alloc_logic.get_key(), ip_local.to_str().c_str());
			return false;
		}

		// Add new net_device to rx_map
		m_rx_nd_map[ip_local.get_in_addr()] = nd_resources;

		rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
		if (rx_nd_iter == m_rx_nd_map.end()) {
			si_logpanic("Failed to find rx_nd_iter");
		}
		BULLSEYE_EXCLUDE_BLOCK_END

	}

	// Now we have the net_device object (created or found)
	p_nd_resources = &rx_nd_iter->second;
	p_nd_resources->refcnt++;

	// Map flow in local map
	m_rx_flow_map[flow_key] = p_nd_resources->p_ring;

	// Save the new CQ from ring
	rx_add_ring_cb(flow_key, p_nd_resources->p_ring);

	// Attach tuple
	BULLSEYE_EXCLUDE_BLOCK_START
	unlock_rx_q();
	if (!p_nd_resources->p_ring->attach_flow(flow_key, this)) {
		lock_rx_q();
		si_logerr("Failed to attach %s to ring %p", flow_key.to_str(), p_nd_resources->p_ring);
		return false;
	}
	lock_rx_q();
	BULLSEYE_EXCLUDE_BLOCK_END

	// Registered as receiver successfully
	si_logdbg("Attached %s to ring %p", flow_key.to_str(), p_nd_resources->p_ring);


        // Verify 5 tuple over 3 tuple
        if (flow_key.is_5_tuple())
        {
        	// Check and remove lesser 3 tuple
        	flow_tuple_with_local_if flow_key_3t(flow_key.get_dst_ip(), flow_key.get_dst_port(), INADDR_ANY, INPORT_ANY, flow_key.get_protocol(), flow_key.get_local_if());
        	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key_3t);
        	if (rx_flow_iter != m_rx_flow_map.end()) {
        		si_logdbg("Removing (and detaching) 3 tuple now that we added a stronger 5 tuple");
        		detach_receiver(flow_key_3t);
        	}
        }

	return true;
}

bool sockinfo::detach_receiver(flow_tuple_with_local_if &flow_key)
{
	si_logdbg("Unregistering receiver: %s", flow_key.to_str());

	// TODO ALEXR: DO we need to return a 3 tuple instead of a 5 tuple being removed?
	// if (peer_ip != INADDR_ANY && peer_port != INPORT_ANY);

	// Find ring associated with this tuple
	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.find(flow_key);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_flow_iter == m_rx_flow_map.end()) {
		si_logdbg("Failed to find ring associated with: %s", flow_key.to_str());
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	ring* p_ring = rx_flow_iter->second;

	si_logdbg("Detaching %s from ring %p", flow_key.to_str(), p_ring);

	// Detach tuple
	unlock_rx_q();
	p_ring->detach_flow(flow_key, this);
	lock_rx_q();

	// Un-map flow from local map
	rx_del_ring_cb(flow_key, p_ring);
	m_rx_flow_map.erase(rx_flow_iter);

	// Check if we are already registered to net_device with the local ip as observers
	ip_address ip_local(flow_key.get_local_if());
	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.find(ip_local.get_in_addr());
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_nd_iter == m_rx_nd_map.end()) {
		si_logpanic("Failed to net_device associated with: %s", flow_key.to_str());
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	net_device_resources_t* p_nd_resources = &(rx_nd_iter->second);
	p_nd_resources->refcnt--;
	if (p_nd_resources->refcnt == 0) {

		// Release ring reference
		BULLSEYE_EXCLUDE_BLOCK_START
		unlock_rx_q();
		if (!p_nd_resources->p_ndv->release_ring(m_ring_alloc_logic.get_key())) {
			lock_rx_q();
			si_logpanic("Failed to release ring for allocation key %d on lip %s", m_ring_alloc_logic.get_key(), ip_local.to_str().c_str());
			return false;
		}
		lock_rx_q();

		// Release observer reference
		if (!g_p_net_device_table_mgr->unregister_observer(ip_local, &m_rx_nd_observer)) {
			si_logpanic("Failed registering as observer for lip %s", ip_local.to_str().c_str());
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		m_rx_nd_map.erase(rx_nd_iter);
	}

	return true;
}

void sockinfo::do_rings_migration()
{
	m_rx_ring_map_lock.lock();
	lock_rx_q();

	resource_allocation_key old_key = m_ring_alloc_logic.get_key();
	resource_allocation_key new_key = m_ring_alloc_logic.create_new_key(old_key);

	if (old_key == new_key) {
		unlock_rx_q();
		m_rx_ring_map_lock.unlock();
		return;
	}

	rx_net_device_map_t::iterator rx_nd_iter = m_rx_nd_map.begin();
	while (rx_nd_iter != m_rx_nd_map.end()) {
		net_device_resources_t* p_nd_resources = &(rx_nd_iter->second);
		ring* p_old_ring = p_nd_resources->p_ring;
		unlock_rx_q();
		ring* new_ring = p_nd_resources->p_ndv->reserve_ring(new_key);
		if (new_ring == p_old_ring) {
			p_nd_resources->p_ndv->release_ring(old_key);
			lock_rx_q();
			rx_nd_iter++;
			continue;
		}
		lock_rx_q();
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!new_ring) {
			ip_address ip_local(rx_nd_iter->first);
			si_logpanic("Failed to reserve ring for allocation key %d on lip %s", new_key, ip_local.to_str().c_str());
			return;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
		while (rx_flow_iter !=  m_rx_flow_map.end()) {

			ring* p_ring = rx_flow_iter->second;
			if (p_ring != p_old_ring) {
				rx_flow_iter++; // Pop next flow rule
				continue;
			}

			flow_tuple_with_local_if flow_key = rx_flow_iter->first;
			// Save the new CQ from ring
			rx_add_ring_cb(flow_key, new_ring, true);

			// Attach tuple
			BULLSEYE_EXCLUDE_BLOCK_START
			unlock_rx_q();
			if (!new_ring->attach_flow(flow_key, this)) {
				lock_rx_q();
				si_logerr("Failed to attach %s to ring %p", flow_key.to_str(), new_ring);
				rx_flow_iter++; // Pop next flow rule
				continue;
			}
			lock_rx_q();
			BULLSEYE_EXCLUDE_BLOCK_END

			rx_flow_iter->second = new_ring;

			// Registered as receiver successfully
			si_logdbg("Attached %s to ring %p", flow_key.to_str(), new_ring);

			si_logdbg("Detaching %s from ring %p", flow_key.to_str(), p_old_ring);
			// Detach tuple
			unlock_rx_q();
			p_old_ring->detach_flow(flow_key, this);
			lock_rx_q();
			rx_del_ring_cb(flow_key, p_old_ring, true);

			rx_flow_iter++; // Pop next flow rule;
		}

		if (!m_p_rx_ring && m_rx_ring_map.size() == 1) {
			m_p_rx_ring = m_rx_ring_map.begin()->first;
		}

		// Release ring reference
		BULLSEYE_EXCLUDE_BLOCK_START
		unlock_rx_q();
		if (!p_nd_resources->p_ndv->release_ring(old_key)) {
			lock_rx_q();
			ip_address ip_local(rx_nd_iter->first);
			si_logpanic("Failed to release ring for allocation key %d on lip %s", old_key, ip_local.to_str().c_str());
			return;
		}
		lock_rx_q();
		BULLSEYE_EXCLUDE_BLOCK_END
		p_nd_resources->p_ring = new_ring;
		rx_nd_iter++;
	}

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();
}

void sockinfo::consider_rings_migration()
{
	if (m_ring_alloc_logic.should_migrate_ring()) {
		do_rings_migration();
		m_p_socket_stats->counters.n_rx_migrations++;
	}
}

void sockinfo::add_epoll_context(epfd_info *epfd)
{
	m_rx_ring_map_lock.lock();
	lock_rx_q();

	socket_fd_api::add_epoll_context(epfd);

	if (!notify_epoll_context_verify(epfd)) {
		unlock_rx_q();
		m_rx_ring_map_lock.unlock();
		return;
	}

	rx_ring_map_t::const_iterator sock_ring_map_iter = m_rx_ring_map.begin();
	while (sock_ring_map_iter != m_rx_ring_map.end()) {
		notify_epoll_context_add_ring(sock_ring_map_iter->first);
		sock_ring_map_iter++;
	}

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();
}

void sockinfo::remove_epoll_context(epfd_info *epfd)
{
	m_rx_ring_map_lock.lock();
	lock_rx_q();

	if (!notify_epoll_context_verify(epfd)) {
		unlock_rx_q();
		m_rx_ring_map_lock.unlock();
		return;
	}

	rx_ring_map_t::const_iterator sock_ring_map_iter = m_rx_ring_map.begin();
	while (sock_ring_map_iter != m_rx_ring_map.end()) {
		notify_epoll_context_remove_ring(sock_ring_map_iter->first);
		sock_ring_map_iter++;
	}

	socket_fd_api::remove_epoll_context(epfd);

	unlock_rx_q();
	m_rx_ring_map_lock.unlock();
}

void sockinfo::rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /*= false*/)
{
	si_logdbg("");
	NOT_IN_USE(flow_key);
	NOT_IN_USE(is_migration);

	// Add the rx ring to our rx ring map
	unlock_rx_q();
	m_rx_ring_map_lock.lock();
	lock_rx_q();
	rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(p_ring);
	if (rx_ring_iter == m_rx_ring_map.end()) {
		// First map of this cq mgr
		m_rx_ring_map[p_ring].refcnt = 1;
		m_rx_ring_map[p_ring].rx_reuse_info.n_buff_num = 0;

		notify_epoll_context_add_ring(p_ring);

		// Add this new CQ channel fd to the rx epfd handle (no need to wake up any sleeping thread about this new fd)
		struct epoll_event ev;
		ev.events = EPOLLIN;
		int num_ring_rx_fds = p_ring->get_num_resources();
		int *ring_rx_fds_array = p_ring->get_rx_channel_fds();

		for (int i = 0; i < num_ring_rx_fds; i++) {
			int cq_ch_fd = ring_rx_fds_array[i];

			ev.data.fd = cq_ch_fd;

			BULLSEYE_EXCLUDE_BLOCK_START
			if (unlikely( orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_ADD, cq_ch_fd, &ev))) {
				si_logerr("failed to add cq channel fd to internal epfd errno=%d (%m)", errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}

		do_wakeup(); // A ready wce can be pending due to the drain logic (cq channel will not wake up by itself)
	}
	else {
		// Increase ref count on cq_mgr object
		rx_ring_iter->second.refcnt++;
	}
	unlock_rx_q();
	m_rx_ring_map_lock.unlock();
	lock_rx_q();
}

void sockinfo::rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration /* = false */)
{
	si_logdbg("");
	NOT_IN_USE(flow_key);

	// Remove the rx cq_mgr from our rx cq map
	unlock_rx_q();
	m_rx_ring_map_lock.lock();
	lock_rx_q();
	descq_t temp_rx_reuse;
	descq_t temp_rx_reuse_global;
	rx_ring_map_t::iterator rx_ring_iter = m_rx_ring_map.find(p_ring);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (rx_ring_iter != m_rx_ring_map.end()) {
	BULLSEYE_EXCLUDE_BLOCK_END
		ring_info_t* p_ring_info = &rx_ring_iter->second;

		// Decrease ref count on cq_mgr object
		p_ring_info->refcnt--;

		// Is this the last reference to this cq_mgr?
		if (p_ring_info->refcnt == 0) {

			// Get rid of all rx ready buffers from this cq_mgr owner
			if (!is_migration) move_owned_rx_ready_descs(p_ring, &temp_rx_reuse);

			// Move all cq_mgr->rx_reuse buffers to temp reuse queue related to p_rx_cq_mgr
			move_owned_descs(p_ring, &temp_rx_reuse, &p_ring_info->rx_reuse_info.rx_reuse);
			if (p_ring_info->rx_reuse_info.rx_reuse.size()) {
				si_logerr("possible buffer leak, p_ring_info->rx_reuse_buff still contain %d buffers.", p_ring_info->rx_reuse_info.rx_reuse.size());
			}

			int num_ring_rx_fds = p_ring->get_num_resources();
			int *ring_rx_fds_array = p_ring->get_rx_channel_fds();

			for (int i = 0; i < num_ring_rx_fds; i++) {
				int cq_ch_fd = ring_rx_fds_array[i];
				BULLSEYE_EXCLUDE_BLOCK_START
				if (unlikely( orig_os_api.epoll_ctl(m_rx_epfd, EPOLL_CTL_DEL, cq_ch_fd, NULL))) {
					si_logerr("failed to delete cq channel fd from internal epfd (errno=%d %m)", errno);
				}
				BULLSEYE_EXCLUDE_BLOCK_END
			}

			notify_epoll_context_remove_ring(p_ring);

			m_rx_ring_map.erase(p_ring);
			if (m_p_rx_ring == p_ring) {
				if (m_rx_ring_map.size() == 1) {
					m_p_rx_ring = m_rx_ring_map.begin()->first;
				} else {
					m_p_rx_ring = NULL;
				}

				move_owned_descs(p_ring, &temp_rx_reuse, &m_rx_reuse_buff.rx_reuse);
				move_not_owned_descs(m_p_rx_ring, &temp_rx_reuse_global, &m_rx_reuse_buff.rx_reuse);

				m_rx_reuse_buff.n_buff_num = m_rx_reuse_buff.rx_reuse.size();
			}
		}
	}
	else {
		si_logerr("oops, ring not found in map, so we can't remove it ???");
	}
	unlock_rx_q();
	m_rx_ring_map_lock.unlock();

	if (temp_rx_reuse.size() > 0) { // no need for m_lock_rcv since temp_rx_reuse is on the stack
		// Get rig of all rx reuse buffers from temp reuse queue
		// Without m_lock_rcv.lock()!!!
		unsigned int counter = 1<<20;
		while (temp_rx_reuse.size() > 0 && counter--) {
			if (p_ring->reclaim_recv_buffers(&temp_rx_reuse))
				break;
			sched_yield();
		}
		if (temp_rx_reuse.size() > 0) //Awareness: we do this without buffer_poll lock after all other tries failed
			g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&temp_rx_reuse);
	}

	if (temp_rx_reuse_global.size() > 0) {
		g_buffer_pool_rx->put_buffers_after_deref_thread_safe(&temp_rx_reuse_global);
	}

	lock_rx_q();
}

// Move all owner's rx ready packets to 'toq'
void sockinfo::move_owned_rx_ready_descs(const mem_buf_desc_owner* p_desc_owner, descq_t *toq)
{
	// Assume locked by owner!!!

	mem_buf_desc_t *temp;
	descq_t *fromq = &m_rx_pkt_ready_list;
	const size_t size = fromq->size();
	for (size_t i = 0 ; i < size; i++) {
		temp = fromq->front();
		fromq->pop_front();
		if (temp->p_desc_owner != p_desc_owner) {
			fromq->push_back(temp);
			continue;
		}
		m_n_rx_pkt_ready_list_count--;
		m_p_socket_stats->n_rx_ready_pkt_count--;

		m_rx_ready_byte_count -= temp->path.rx.sz_payload;
		m_p_socket_stats->n_rx_ready_byte_count -= temp->path.rx.sz_payload;
		toq->push_back(temp);
	}
}

void sockinfo::attach_as_uc_receiver(role_t role, bool skip_rules /* = false */)
{
	sock_addr addr(m_bound.get_p_sa());

	if (addr.get_in_addr() != INADDR_ANY) {
		si_logdbg("Attaching to specific local if: %s", addr.to_str());
		transport_t target_family = TRANS_VMA;
		if (!skip_rules) target_family = find_target_family(role, addr.get_p_sa());
		if (target_family == TRANS_VMA) {
			// bind to specific local if
			flow_tuple_with_local_if flow_key(m_bound, m_connected, m_protocol, addr.get_in_addr());
			attach_receiver(flow_key);
		}
	}
	else {
		si_logdbg("Attaching to all offload local if: %s", addr.to_str());
		// bind to all interfaces if local_ip is INADDR_ANY

		local_ip_list_t::iterator lip_iter;
		local_ip_list_t lip_offloaded_list = g_p_net_device_table_mgr->get_ip_list();
		for (lip_iter = lip_offloaded_list.begin(); lip_offloaded_list.end() != lip_iter; lip_iter++)
		{
			in_addr_t local_if = *lip_iter;
			addr.set_in_addr(local_if);
			transport_t target_family = TRANS_VMA;
			if (!skip_rules) target_family = find_target_family(role, addr.get_p_sa());
			if (target_family == TRANS_VMA) {
				flow_tuple_with_local_if flow_key(addr, m_connected, m_protocol, local_if);
				attach_receiver(flow_key);
			}
		}
	}
}

transport_t sockinfo::find_target_family(role_t role, struct sockaddr* sock_addr_first, struct sockaddr* sock_addr_second /* = NULL */)
{
	transport_t target_family = TRANS_DEFAULT;
	switch (role) {
	case ROLE_TCP_SERVER:
		target_family = __vma_match_tcp_server(TRANS_VMA, mce_sys.app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_TCP_CLIENT:
		target_family = __vma_match_tcp_client(TRANS_VMA, mce_sys.app_id, sock_addr_first, sizeof(struct sockaddr), sock_addr_second, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_RECEIVER:
		target_family = __vma_match_udp_receiver(TRANS_VMA, mce_sys.app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_SENDER:
		target_family = __vma_match_udp_sender(TRANS_VMA, mce_sys.app_id, sock_addr_first, sizeof(struct sockaddr));
		break;
	case ROLE_UDP_CONNECT:
		target_family = __vma_match_udp_connect(TRANS_VMA, mce_sys.app_id, sock_addr_first, sizeof(struct sockaddr), sock_addr_second, sizeof(struct sockaddr));
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		break;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	return target_family;
}


void sockinfo::destructor_helper()
{
	// Unregister this receiver from all ring's in our list
	rx_flow_map_t::iterator rx_flow_iter = m_rx_flow_map.begin();
	while (rx_flow_iter !=  m_rx_flow_map.end()) {
		flow_tuple_with_local_if detach_key = rx_flow_iter->first;
		detach_receiver(detach_key);
		rx_flow_iter = m_rx_flow_map.begin(); // Pop next flow rule
	}

	// Delete all dst_entry in our list
	if (m_p_connected_dst_entry)
		delete m_p_connected_dst_entry;
	m_p_connected_dst_entry = NULL;
}
