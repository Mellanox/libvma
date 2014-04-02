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


#include "epoll_wait_call.h"

#include <vlogger/vlogger.h>

#include <vma/util/vtypes.h>
#include <vma/sock/sock-redirect.h>
#include <vma/sock/socket_fd_api.h>
#include <vma/sock/fd_collection.h>

#include "epfd_info.h"

#define MODULE_NAME "epoll_wait_call:"

epoll_wait_call::epoll_wait_call(epoll_event *extra_events_buffer, offloaded_mode_t *off_modes_buffer,
                                 int epfd, epoll_event *events, int maxevents, 
                                 int timeout, const sigset_t *sigmask /* = NULL */) :
	io_mux_call(NULL, off_modes_buffer, 0, sigmask),  // TODO: rethink on these arguments
	m_epfd(epfd), m_events(events), m_maxevents(maxevents), m_timeout(timeout),
	m_p_ready_events(extra_events_buffer)
{
	// get epfd_info
	m_epfd_info = fd_collection_get_epfd(epfd);
	if (!m_epfd_info || maxevents <= 0) {
		__log_dbg("error, epfd %d not found or maxevents <= 0 (=%d)", epfd, maxevents);
		errno = maxevents <= 0 ? EINVAL : EBADF;
		throw io_mux_call::io_error();
	}

	// create stats
	m_p_stats = &m_epfd_info->stats()->stats;
}

void epoll_wait_call::init_offloaded_fds()
{
	// copy offloaded_fds pointer and count
	m_epfd_info->get_offloaded_fds_arr_and_size(&m_p_num_all_offloaded_fds, &m_p_all_offloaded_fds);
	m_num_all_offloaded_fds = *m_p_num_all_offloaded_fds; // TODO: fix orig ugly code, and then remove this

	__log_func("building: epfd=%d, m_epfd_info->get_fd_info().size()=%d, *m_p_num_all_offloaded_fds=%d", m_epfd, (int)m_epfd_info->get_fd_info().size(), (int)*m_p_num_all_offloaded_fds  );

}

int epoll_wait_call::get_current_events()
{
	if (m_epfd_info->m_ready_fds.empty()) {
		return m_n_all_ready_fds;
	}

	vector<socket_fd_api *> socket_fd_vec;
	lock();
	int i,r,w;
	i = r = w = m_n_all_ready_fds;
	socket_fd_api *p_socket_object;
	epoll_fd_rec fd_rec;
	ep_ready_fd_map_t::iterator iter = m_epfd_info->m_ready_fds.begin();
	while (iter != m_epfd_info->m_ready_fds.end() && i < m_maxevents) {
		ep_ready_fd_map_t::iterator iter_cpy = iter; // for protection needs
		++iter;
		p_socket_object = fd_collection_get_sockfd(iter_cpy->first);
		if (p_socket_object)
		{
			if(!m_epfd_info->get_fd_rec_by_fd(iter_cpy->first, fd_rec)) continue;

			m_events[i].events = 0; //initialize

			bool got_event = false;

			//epoll_wait will always wait for EPOLLERR and EPOLLHUP; it is not necessary to set it in events.
			uint32_t mutual_events = iter_cpy->second & (fd_rec.events | EPOLLERR | EPOLLHUP);

			//EPOLLHUP & EPOLLOUT are mutually exclusive. see poll man pages. epoll adapt poll behavior.
			if (mutual_events & EPOLLHUP & EPOLLOUT) {
				mutual_events &= ~EPOLLOUT;
			}

			if (mutual_events & EPOLLIN) {
				if (handle_epoll_event(p_socket_object->is_readable(NULL), EPOLLIN, iter_cpy, fd_rec, i)) {
					r++;
					got_event = true;
				}
				mutual_events &= ~EPOLLIN;
			}

			if (mutual_events & EPOLLOUT) {
				if (handle_epoll_event(p_socket_object->is_writeable(), EPOLLOUT, iter_cpy, fd_rec, i)) {
					w++;
					got_event = true;
				}
				mutual_events &= ~EPOLLOUT;
			}

			if (mutual_events) {
				if (handle_epoll_event(true, mutual_events, iter_cpy, fd_rec, i)) {
					got_event = true;
				}
			}

			if (got_event) {
				socket_fd_vec.push_back(p_socket_object);
				++i;
			}
		}
		else {
			m_epfd_info->m_ready_fds.erase(iter_cpy);
		}
	}

	int ready_rfds = r - m_n_all_ready_fds; //MNY: not only rfds, different counters for read/write ?
	int ready_wfds = w - m_n_all_ready_fds;
	m_n_ready_rfds += ready_rfds;
	m_n_ready_wfds += ready_wfds;
	m_p_stats->n_iomux_rx_ready += ready_rfds;

	unlock();

	/*
	 * for checking ring migration we need a socket context.
	 * in epoll we separate the rings from the sockets, so only here we access the sockets.
	 * therefore, it is most convenient to check it here.
	 * we need to move the ring migration to the epfd, going over the registered sockets,
	 * when polling the rings was not fruitful.
	 * this  will be more similar to the behavior of select/poll.
	 * see RM task 212058
	 */
	for (unsigned int j = 0; j < socket_fd_vec.size(); j++) {
		socket_fd_vec[j]->consider_rings_migration();
	}

	return (i);
}

epoll_wait_call::~epoll_wait_call()
{
}

void epoll_wait_call::prepare_to_poll()
{
	// Empty
}

void epoll_wait_call::prepare_to_block()
{
	// Empty
}

bool epoll_wait_call::_wait(int timeout) 
{
	int i, ready_fds, fd;
	bool cq_ready = false;

	__log_func("calling os epoll: %d", m_epfd);

	if (timeout) {
		lock();
		if (m_epfd_info->m_ready_fds.empty()) {
			m_epfd_info->going_to_sleep();
		} else {
			timeout = 0;
		}
		unlock();
	}

	if (m_sigmask) {
		ready_fds = orig_os_api.epoll_pwait(m_epfd, m_p_ready_events, m_maxevents, timeout, m_sigmask);
	} else {
		ready_fds = orig_os_api.epoll_wait(m_epfd, m_p_ready_events, m_maxevents, timeout);
	}

	if (timeout) {
		lock();
		m_epfd_info->return_from_sleep();
		unlock();
	}

	if (ready_fds < 0) {
		throw io_mux_call::io_error();
	} 
	
	// convert the returned events to user events and mark offloaded fds
	m_n_all_ready_fds = 0;
	for (i = 0; i < ready_fds; ++i) {
		fd = m_p_ready_events[i].data.fd;

		// wakeup event
		if(m_epfd_info->is_wakeup_fd(fd))
		{
			lock();
			m_epfd_info->remove_wakeup_fd();
			unlock();
			continue;
		}

		// If it's CQ
		if (m_epfd_info->is_cq_fd(m_p_ready_events[i].data.u64)) {
			cq_ready = true;
			continue;
		}
		
		if ((m_p_ready_events[i].events & EPOLLIN)) {
			socket_fd_api* temp_sock_fd_api = fd_collection_get_sockfd(fd);
			if (temp_sock_fd_api) {
				// Instructing the socket to sample the OS immediately to prevent hitting EAGAIN on recvfrom(),
				// after iomux returned a shadow fd as ready (only for non-blocking sockets)
				temp_sock_fd_api->set_immediate_os_sample();
			}
		}

		// Copy event bits and data
		m_events[m_n_all_ready_fds].events = m_p_ready_events[i].events;
		if (!m_epfd_info->get_data_by_fd(fd, &m_events[m_n_all_ready_fds].data)) {
			continue;
		}
		++m_n_all_ready_fds;
	}
	
	return cq_ready;
}

bool epoll_wait_call::wait_os(bool zero_timeout)
{
	return _wait(zero_timeout ? 0 : m_timeout);
}
	
bool epoll_wait_call::wait(const timeval &elapsed)
{
	int timeout;

	if (m_timeout < 0) {
		timeout = m_timeout;
	} else {
		timeout = m_timeout - tv_to_msec(&elapsed);
		if (timeout < 0) {
			// Already reached timeout
			return false;
		}
	}

	return _wait(timeout);
}

bool epoll_wait_call::is_timeout(const timeval &elapsed)
{
	return m_timeout >= 0 && m_timeout <= tv_to_msec(&elapsed);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void epoll_wait_call::set_offloaded_rfd_ready(int fd_index)
{
	// Empty - event inserted via event callback
	NOT_IN_USE(fd_index);
}

void epoll_wait_call::set_offloaded_wfd_ready(int fd_index)
{
	// Empty
	NOT_IN_USE(fd_index);
}

void epoll_wait_call::set_rfd_ready(int fd)
{
	// Empty
	NOT_IN_USE(fd);
}

void epoll_wait_call::set_wfd_ready(int fd)
{
	// Empty
	NOT_IN_USE(fd);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void epoll_wait_call::lock()
{
	m_epfd_info->lock();
}

void epoll_wait_call::unlock()
{
	m_epfd_info->unlock();
}

bool epoll_wait_call::check_all_offloaded_sockets(uint64_t *p_poll_sn)
{
	NOT_IN_USE(p_poll_sn);
	m_n_all_ready_fds = get_current_events();

	if (!m_n_ready_rfds)
	{
		// check cq for acks
		ring_poll_and_process_element(&m_poll_sn, NULL);
		m_n_all_ready_fds = get_current_events();
	}

	__log_func("m_n_all_ready_fds=%d, m_n_ready_rfds=%d, m_n_ready_wfds=%d", m_n_all_ready_fds, m_n_ready_rfds, m_n_ready_wfds);
	return m_n_all_ready_fds;
}

bool epoll_wait_call::immidiate_return()
{
	return false;
}

bool epoll_wait_call::handle_epoll_event(bool is_ready, uint32_t events, ep_ready_fd_map_t::iterator iter, epoll_fd_rec fd_rec, int index)
{
	if (is_ready) {

		m_events[index].data = fd_rec.epdata;
		m_events[index].events |= events;

		if (fd_rec.events & EPOLLONESHOT) {
			m_epfd_info->clear_events_for_fd(iter->first, events);
		}
		if (fd_rec.events & EPOLLET) {
			m_epfd_info->remove_epoll_event(iter->first, events);
		}
		return true;
	}
	else {
		// not readable, need to erase from our ready list (LT support)
		m_epfd_info->remove_epoll_event(iter->first, events);
		return false;
	}

}

int epoll_wait_call::ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array/* = NULL*/)
{
	return m_epfd_info->ring_poll_and_process_element(p_poll_sn, pv_fd_ready_array);
}

int epoll_wait_call::ring_request_notification(uint64_t poll_sn)
{
	return m_epfd_info->ring_request_notification(poll_sn);
}

int epoll_wait_call::ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array /* = NULL*/)
{
	return m_epfd_info->ring_wait_for_notification_and_process_element(p_poll_sn, pv_fd_ready_array);
}
