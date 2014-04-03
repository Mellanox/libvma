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


#include <vlogger/vlogger.h>

#include <vma/sock/sock-redirect.h>
#include <vma/sock/socket_fd_api.h>
#include <vma/sock/fd_collection.h>
#include <vma/dev/net_device_table_mgr.h>
#include <vma/iomux/epfd_info.h>
#include "vma/util/bullseye.h"

#define MODULE_NAME "epfd_info:"

#define SUPPORTED_EPOLL_EVENTS (EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP|EPOLLRDHUP|EPOLLONESHOT|EPOLLET)

#define NUM_LOG_INVALID_EVENTS 10

#define CQ_FD_MARK 0xabcd

epfd_info::epfd_info(int epfd, int size) :
	lock_mutex_recursive("epfd_info"), m_epfd(epfd), m_size(size), m_ring_map_lock("epfd_ring_map_lock")
{
	__log_funcall("");
	int max_sys_fd = get_sys_max_fd_num();
	if (m_size<=max_sys_fd)
	{
		m_size=max_sys_fd;
		__log_dbg("using open files max limit of %d file descriptors", m_size);
	}

	m_p_offloaded_fds = new int[m_size];
	m_n_offloaded_fds = 0;
	m_ready_fd = 0;

	memset(&(m_local_stats.stats), 0, sizeof(iomux_func_stats_t));

	/* This initialization is not needed (because it is also done in shmem) but for proper code
	 * we do it in any case
	 */
	m_local_stats.enabled = true;
	m_local_stats.epfd = m_epfd;

	m_stats = &m_local_stats;

	m_log_invalid_events = NUM_LOG_INVALID_EVENTS;

	vma_stats_instance_create_epoll_block(m_epfd, &(m_stats->stats));

	wakeup_set_epoll_fd(m_epfd);
}

epfd_info::~epfd_info()
{
	__log_funcall("");

	// Meny: going over all handled fds and removing epoll context.

	lock();

	socket_fd_api* temp_sock_fd_api;
	for (int i = 0; i < m_n_offloaded_fds; i++) {
		temp_sock_fd_api = fd_collection_get_sockfd(m_p_offloaded_fds[i]);
		BULLSEYE_EXCLUDE_BLOCK_START
		if(temp_sock_fd_api) {
			unlock();
			m_ring_map_lock.lock();
			temp_sock_fd_api->remove_epoll_context(this);
			m_ring_map_lock.unlock();
			lock();
		}else {
			__log_err("Invalid temp_sock_fd_api==NULL. Deleted fds should have been removed from epfd.");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	unlock();

	vma_stats_instance_remove_epoll_block(&m_stats->stats);
	delete [] m_p_offloaded_fds;
}

int epfd_info::ctl(int op, int fd, epoll_event *event)
{
	int ret;
	epoll_event event_dummy;
	if (event == NULL) {
		memset(&event_dummy, 0, sizeof(event_dummy));
		event = &event_dummy;
	}
	
	// YossiE TODO make "event table" - and add index in that table instead
	// of real event (in orig_os_api.epoll_ctl). must have this because fd's can
	// be added after the cq.
	lock();
	
	switch (op) {
	case EPOLL_CTL_ADD:
		ret = add_fd(fd, event);
		break;
	case EPOLL_CTL_DEL:
		ret = del_fd(fd);
		break;
	case EPOLL_CTL_MOD:
		ret = mod_fd(fd, event);
		break;
	default:
		errno = EINVAL;
		ret = -1;
		break;
	}
	
	unlock();
	return ret;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int *epfd_info::get_offloaded_fds()
{
	return m_p_offloaded_fds;
}

int epfd_info::get_num_offloaded_fds()
{
	return m_n_offloaded_fds;
}

int *epfd_info::get_p_to_num_offloaded_fds()
{
	return &m_n_offloaded_fds;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void epfd_info::get_offloaded_fds_arr_and_size(int **p_p_num_offloaded_fds,
					       int **p_p_offloadded_fds)
{
	*p_p_num_offloaded_fds = &m_n_offloaded_fds;
	*p_p_offloadded_fds = m_p_offloaded_fds;
}

bool epfd_info::is_cq_fd(uint64_t data)
{
	if ((data >> 32) != CQ_FD_MARK)
		return false;

	lock();
	m_ready_cq_fd_q.push_back((int)(data & 0xffff));
	unlock();

	return true;
}

int epfd_info::add_fd(int fd, epoll_event *event)
{
	int ret;
	epoll_event evt;
	bool is_offloaded = false;
	
	__log_funcall("fd=%d", fd);

	socket_fd_api* temp_sock_fd_api = fd_collection_get_sockfd(fd);
	if (temp_sock_fd_api && temp_sock_fd_api->get_type()== FD_TYPE_SOCKET) {
		is_offloaded = true;
	}
	
	// Make sure that offloaded fd has a correct event mask
	if (is_offloaded) {
		if (m_log_invalid_events && (event->events & ~SUPPORTED_EPOLL_EVENTS)) {
			__log_dbg("invalid event mask 0x%x for offloaded fd=%d", event->events, fd);
			__log_dbg("(event->events & ~%s)=0x%x", TO_STR(SUPPORTED_EPOLL_EVENTS),
			          event->events & ~SUPPORTED_EPOLL_EVENTS);
			m_log_invalid_events--;
		}
	}

	if (temp_sock_fd_api && temp_sock_fd_api->skip_os_select()) {
		__log_dbg("fd=%d must be skipped from os epoll()", fd);
		// Checking for duplicate fds
		if (m_fd_info.find(fd) != m_fd_info.end()) {
			__log_dbg("epoll_ctl: tried to add an existing fd. (%d)", fd);
			errno = ENOENT;
			return -1;
		}
	}
	else {
		// Add an event which indirectly point to our event
		evt.events = event->events;
		evt.data.u64 = 0; //zero all data
		evt.data.fd = fd;
		ret = orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_ADD, fd, &evt);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			__log_dbg("failed to add fd=%d to epoll epfd=%d (errno=%d %m)", fd, m_epfd, errno);
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	m_fd_info[fd].events = event->events;
	m_fd_info[fd].epdata = event->data;
	m_fd_info[fd].offloaded_index = -1;
	if (is_offloaded) {  // TODO: do we need to handle offloading only for one of read/write?
		if (m_n_offloaded_fds >= m_size) {
			__log_dbg("Reached max fds for epoll (%d)", m_size);
			errno = ENOMEM;
			return -1;
		}
		m_p_offloaded_fds[m_n_offloaded_fds] = fd;
		++m_n_offloaded_fds;
		m_fd_info[fd].offloaded_index = m_n_offloaded_fds;

		//NOTE: when supporting epoll on epfd, need to add epfd ring list
		//NOTE: when having rings in pipes, need to overload add_epoll_context
		unlock();
		m_ring_map_lock.lock();
		temp_sock_fd_api->add_epoll_context(this);
		m_ring_map_lock.unlock();
		lock();

		// if the socket is ready, add it to ready events
		uint32_t events = 0;
		if ((event->events & EPOLLIN) && temp_sock_fd_api->is_readable(NULL, NULL)) {
			events |=  EPOLLIN;
		}
		if ((event->events & EPOLLOUT) && temp_sock_fd_api->is_writeable()) {
			// MNY: udp_socket is always ready to write. Both VMA and the OS will notify it.
			// Can't remove notification in VMA in case user decides to skip the OS using VMA params.
			// Meaning: user will get 2 ready WRITE events on startup of socket
			events |= EPOLLOUT;
		}
		if (events != 0) {
			insert_epoll_event(fd, events); // mutex is recursive
		}
	}
	__log_func("fd %d added in epfd %d with events=%#x and data=%#x", 
		   fd, m_epfd, event->events, event->data);
	return 0;
}

inline void epfd_info::increase_ring_ref_count_no_lock(ring* ring)
{
	ring_map_t::iterator iter = m_ring_map.find(ring);
	if (iter != m_ring_map.end()) {
		//increase ref count
		iter->second++;
	} else {
		m_ring_map[ring] = 1;

		// add cq channel fd to the epfd
		int num_ring_rx_fds = ring->get_num_resources();
		int *ring_rx_fds_array = ring->get_rx_channel_fds();
		for (int i = 0; i < num_ring_rx_fds; i++) {
			epoll_event evt;
			evt.events = EPOLLIN | EPOLLPRI;
			int fd = ring_rx_fds_array[i];
			evt.data.u64 = (((uint64_t)CQ_FD_MARK << 32) | fd);
			int ret = orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_ADD, fd, &evt);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (ret < 0) {
				__log_dbg("failed to add cq fd=%d to epoll epfd=%d (errno=%d %m)",
						fd, m_epfd, errno);
			} else {
				__log_dbg("add cq fd=%d to epfd=%d", fd, m_epfd);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
	}
}

void epfd_info::increase_ring_ref_count(ring* ring)
{
	m_ring_map_lock.lock();
	increase_ring_ref_count_no_lock(ring);
	m_ring_map_lock.unlock();
}

inline void epfd_info::decrease_ring_ref_count_no_lock(ring* ring)
{
	ring_map_t::iterator iter = m_ring_map.find(ring);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (iter == m_ring_map.end()) {
		__log_err("expected to find ring %p here!", ring);
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	//decrease ref count
	iter->second--;

	if (iter->second == 0) {
		m_ring_map.erase(iter);

		// remove cq channel fd from the epfd
		int num_ring_rx_fds = ring->get_num_resources();
		int *ring_rx_fds_array = ring->get_rx_channel_fds();
		for (int i = 0; i < num_ring_rx_fds; i++) {
			// delete cq fd from epfd
			int ret = orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_DEL, ring_rx_fds_array[i], NULL);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (ret < 0) {
				__log_dbg("failed to remove cq fd=%d from epfd=%d (errno=%d %m)",
						ring_rx_fds_array[i], m_epfd, errno);
			} else {
				__log_dbg("remove cq fd=%d from epfd=%d", ring_rx_fds_array[i], m_epfd);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
	}
}

void epfd_info::decrease_ring_ref_count(ring* ring)
{
	m_ring_map_lock.lock();
	decrease_ring_ref_count_no_lock(ring);
	m_ring_map_lock.unlock();
}

/*
 * del_fd have two modes:
 * 1. not passthrough (default) - remove the fd from the epfd, both from OS epfd and VMA epfd
 * 2. passthrough - remove the fd as offloaded fd, and keep it only on OS epfd if it was there.
 *    this is a 1 way direction from both offloaded/not-offloaded to not-offloaded only.
 */
int epfd_info::del_fd(int fd, bool passthrough)
{
	int ret;
	
	__log_funcall("fd=%d", fd);

	socket_fd_api* temp_sock_fd_api = fd_collection_get_sockfd(fd);
	if (temp_sock_fd_api && temp_sock_fd_api->skip_os_select()) {
		__log_dbg("fd=%d must be skipped from os epoll()", fd);
	}
	else if (!passthrough) {
		ret = remove_fd_from_epoll_os(fd);
	}
	
	fd_info_map_t::iterator fd_iter = m_fd_info.find(fd);
	if (fd_iter == m_fd_info.end()) {
		errno = ENOENT;
		return -1;
	}
	
	// create a copy and remove the record from m_fd_info
	epoll_fd_rec fi = fd_iter->second;
	
	if (!passthrough) m_fd_info.erase(fd_iter);

	ep_ready_fd_map_t::iterator iter = m_ready_fds.find(fd);
	if (iter != m_ready_fds.end()) {
		m_ready_fds.erase(iter);
	}

	// handle offloaded fds
	if (fi.offloaded_index > 0) {

		//check if the index of fd, which is being removed, is the last one.
		//if does, it is enough to decrease the val of m_n_offloaded_fds in order
		//to shrink the offloaded fds array.
		if (fi.offloaded_index < m_n_offloaded_fds) {
			// remove fd and replace by last fd
			m_p_offloaded_fds[fi.offloaded_index - 1] =
					m_p_offloaded_fds[m_n_offloaded_fds - 1];

			fd_iter = m_fd_info.find(m_p_offloaded_fds[m_n_offloaded_fds - 1]);

			BULLSEYE_EXCLUDE_BLOCK_START
			if (fd_iter == m_fd_info.end()) {
				__log_warn("Failed to update the index of offloaded fd: %d\n", m_p_offloaded_fds[m_n_offloaded_fds - 1]);
			BULLSEYE_EXCLUDE_BLOCK_END
			}else {
				fd_iter->second.offloaded_index = fi.offloaded_index;
			}
		}

		--m_n_offloaded_fds;
	}

	if (temp_sock_fd_api) {
		unlock();
		m_ring_map_lock.lock();
		temp_sock_fd_api->remove_epoll_context(this);
		m_ring_map_lock.unlock();
		lock();
	}

	__log_func("fd %d removed from epfd %d", fd, m_epfd);
	return 0;
}

int epfd_info::clear_events_for_fd(int fd, uint32_t events)
{
	fd_info_map_t::iterator fd_iter = m_fd_info.find(fd);
	if (fd_iter == m_fd_info.end()) {
		errno = ENOENT;
		return -1;
	}
	fd_iter->second.events &= ~events;
	return 0;
}

int epfd_info::mod_fd(int fd, epoll_event *event)
{
	epoll_event evt;
	int ret;

	__log_funcall("fd=%d", fd);

	// find the fd in local table
	fd_info_map_t::iterator fd_iter = m_fd_info.find(fd);
	if (fd_iter == m_fd_info.end()) {
		errno = ENOENT;
		return -1;
	}
	
	// check if fd is offloaded that new event mask is OK 
	if (fd_iter->second.offloaded_index > 0) {
		if (m_log_invalid_events && (event->events & ~SUPPORTED_EPOLL_EVENTS)) {
			__log_dbg("invalid event mask 0x%x for offloaded fd=%d", event->events, fd);
			__log_dbg("(event->events & ~%s)=0x%x", TO_STR(SUPPORTED_EPOLL_EVENTS),
					event->events & ~SUPPORTED_EPOLL_EVENTS);
			m_log_invalid_events--;
		}
	}

	socket_fd_api* temp_sock_fd_api = fd_collection_get_sockfd(fd);
	if (temp_sock_fd_api && temp_sock_fd_api->skip_os_select()) {
		__log_dbg("fd=%d must be skipped from os epoll()", fd);
	}
	else {
		// modify fd
		evt.events = event->events;
		evt.data.u64 = 0; //zero all data
		evt.data.fd = fd;
		ret = orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_MOD, fd, &evt);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			__log_err("failed to modify fd=%d in epoll epfd=%d (errno=%d %m)", fd, m_epfd, errno);
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	// modify fd data in local table
	fd_iter->second.epdata = event->data;
	fd_iter->second.events = event->events;
	
	bool is_offloaded = temp_sock_fd_api && temp_sock_fd_api->get_type()== FD_TYPE_SOCKET;

	uint32_t events = 0;
	if (is_offloaded) {
		// if the socket is ready, add it to ready events
		if ((event->events & EPOLLIN) && temp_sock_fd_api->is_readable(NULL, NULL)) {
			events |=  EPOLLIN;
		}
		if ((event->events & EPOLLOUT) && temp_sock_fd_api->is_writeable()) {
			// MNY: udp_socket is always ready to write. Both VMA and the OS will notify it.
			// Can't remove notification in VMA in case user decides to skip the OS using VMA params.
			// Meaning: user will get 2 ready WRITE events on startup of socket
			events |= EPOLLOUT;
		}
		if (events != 0) {
			insert_epoll_event(fd, events); // mutex is recursive
		}
	}

	if(event->events == 0 || events == 0){
		m_ready_fds.erase(fd);
	}

	__log_func("fd %d modified in epfd %d with events=%#x and data=%#x", 
		   fd, m_epfd, event->events, event->data);
	return 0;
}

bool epfd_info::get_fd_rec_by_fd(int fd, epoll_fd_rec& fd_rec)
{
	fd_info_map_t::iterator iter = m_fd_info.find(fd);
	if (iter != m_fd_info.end())
		fd_rec = iter->second;
	else {
		__log_dbg("error - could not found fd %d in m_fd_info of epfd %d", fd, m_epfd);
		return false;
	}
	return true;
}

bool epfd_info::get_data_by_fd(int fd, epoll_data *data)
{
	lock();
	fd_info_map_t::iterator iter = m_fd_info.find(fd);
	if (iter != m_fd_info.end())
		*data = m_fd_info[fd].epdata;
	else {
		__log_dbg("error - could not found fd %d in m_fd_info of epfd %d", fd, m_epfd);
		unlock();
		return false;
	}
	unlock();
	return true;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

bool epfd_info::is_offloaded_fd(int fd)
{
	fd_info_map_t::iterator iter;
	iter = m_fd_info.find(fd);
	return iter != m_fd_info.end() && iter->second.offloaded_index > 0;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void epfd_info::fd_closed(int fd, bool passthrough)
{
	lock();
	if (m_fd_info.find(fd) != m_fd_info.end()) {
		del_fd(fd, passthrough);
	}
	unlock();
}

void epfd_info::set_fd_as_offloaded_only(int fd)
{
	lock();
	if (m_fd_info.find(fd) != m_fd_info.end()) {
		remove_fd_from_epoll_os(fd);
	}
	unlock();
}

inline int epfd_info::remove_fd_from_epoll_os(int fd)
{
	int ret = orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_DEL, fd, NULL);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		__log_dbg("failed to remove fd=%d from os epoll epfd=%d (errno=%d %m)", fd, m_epfd, errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	return ret;
}

void epfd_info::insert_epoll_event_cb(int fd, uint32_t event_flags)
{
	lock();
	fd_info_map_t::iterator fd_iter = m_fd_info.find(fd);
	if (fd_iter == m_fd_info.end()) {
		unlock();
		return;
	}
	//EPOLLHUP | EPOLLERR are reported without user request
	if(event_flags & (fd_iter->second.events | EPOLLHUP | EPOLLERR)){
		insert_epoll_event(fd, event_flags);
	}
	unlock();
}

void epfd_info::insert_epoll_event(int fd, uint32_t event_flags)
{
	ep_ready_fd_map_t::iterator iter = m_ready_fds.find(fd);
	if (iter != m_ready_fds.end()) {
		iter->second |= event_flags;
	}
	else {
		m_ready_fds.insert(ep_ready_fd_map_t::value_type(fd, event_flags));
	}

	do_wakeup();
}

void epfd_info::remove_epoll_event(int fd, uint32_t event_flags)
{
	ep_ready_fd_map_t::iterator iter = m_ready_fds.find(fd);
	if (iter != m_ready_fds.end()) {
		iter->second &= ~event_flags;
	}
	if (iter->second == 0) {
		m_ready_fds.erase(iter);
	}
}

epoll_stats_t *epfd_info::stats()
{
	return m_stats;
}

int epfd_info::ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array/* = NULL*/)
{
	__log_func("");

	int ret_total = 0;

	if (m_ring_map.empty()) {
		return ret_total;
	}

	m_ring_map_lock.lock();

	for (ring_map_t::iterator iter = m_ring_map.begin(); iter != m_ring_map.end(); iter++) {
		int ret = iter->first->poll_and_process_element_rx(p_poll_sn, pv_fd_ready_array);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0 && errno != EAGAIN) {
			__log_err("Error in ring->poll_and_process_element() of %p (errno=%d %m)", iter->first, errno);
			m_ring_map_lock.unlock();
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (ret > 0)
			__log_func("ring[%p] Returned with: %d (sn=%d)", iter->first, ret, *p_poll_sn);
		ret_total += ret;
	}

	m_ring_map_lock.unlock();

	if (mce_sys.thread_mode == THREAD_MODE_PLENTY && ret_total == 0 && errno == EBUSY) pthread_yield();

	if (ret_total)
		__log_func("ret_total=%d", ret_total);
	else
		__log_funcall("ret_total=%d", ret_total);

	return ret_total;
}

int epfd_info::ring_request_notification(uint64_t poll_sn)
{
	__log_func("");
	int ret_total = 0;

	if (m_ring_map.empty()) {
		return ret_total;
	}

	m_ring_map_lock.lock();

	for (ring_map_t::iterator iter = m_ring_map.begin(); iter != m_ring_map.end(); iter++) {
		int ret = iter->first->request_notification(CQT_RX, poll_sn);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret < 0) {
			__log_err("Error ring[%p]->request_notification() (errno=%d %m)", iter->first, errno);
			m_ring_map_lock.unlock();
			return ret;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		__log_func("ring[%p] Returned with: %d (sn=%d)", iter->first, ret, poll_sn);
		ret_total += ret;
	}

	m_ring_map_lock.unlock();

	return ret_total;
}

int epfd_info::ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array /* = NULL*/)
{
	__log_func("");
	int ret_total = 0;

	while (!m_ready_cq_fd_q.empty()) {

		lock();
		if (m_ready_cq_fd_q.empty()) {
			unlock();
			break;
		}
		int fd = m_ready_cq_fd_q.back();
		m_ready_cq_fd_q.pop_back();
		unlock();

		cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
		if (p_cq_ch_info) {
			ring* p_ready_ring = p_cq_ch_info->get_ring();
			// Handle the CQ notification channel
			int ret = p_ready_ring->wait_for_notification_and_process_element(CQT_RX, fd, p_poll_sn, pv_fd_ready_array);
			if (ret < 0) {
				if (errno == EAGAIN || errno == EBUSY) {
					__log_dbg("Error in ring->wait_for_notification_and_process_element() of %p (errno=%d %m)", p_ready_ring, errno);
				}
				else {
					__log_err("Error in ring->wait_for_notification_and_process_element() of %p (errno=%d %m)", p_ready_ring, errno);
				}
				return ret;
			}
			if (ret > 0) {
				__log_func("ring[%p] Returned with: %d (sn=%d)", p_ready_ring, ret, *p_poll_sn);
			}
			ret_total += ret;
		}
		else {
			__log_dbg("failed to find channel fd. removing cq fd=%d from epfd=%d", fd, m_epfd);
			BULLSEYE_EXCLUDE_BLOCK_START
			if ((orig_os_api.epoll_ctl(m_epfd, EPOLL_CTL_DEL,
					fd, NULL)) && (errno != ENOENT)) {
				__log_err("failed to del cq channel fd=%d from os epfd=%d (errno=%d %m)", fd, m_epfd, errno);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
	}

	if (ret_total)
		__log_func("ret_total=%d", ret_total);
	else
		__log_funcall("ret_total=%d", ret_total);
	return ret_total;
}
