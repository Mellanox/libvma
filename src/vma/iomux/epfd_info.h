/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef VMA_EPOLL_H
#define VMA_EPOLL_H

#include <vma/util/wakeup_pipe.h>
#include <vma/sock/cleanable_obj.h>
#include <vma/sock/sockinfo.h>

typedef vma_list_t<socket_fd_api, socket_fd_api::ep_ready_fd_node_offset>   ep_ready_fd_list_t;
typedef vma_list_t<socket_fd_api, socket_fd_api::ep_info_fd_node_offset>    fd_info_list_t;
typedef std::tr1::unordered_map<int, epoll_fd_rec>                          fd_info_map_t;
typedef std::tr1::unordered_map<ring*, int /*ref count*/>                   ring_map_t;
typedef std::deque<int>                                                     ready_cq_fd_q_t;

class epfd_info : public lock_mutex_recursive, public cleanable_obj, public wakeup_pipe
{
public:
	epfd_info(int epfd, int size);
	~epfd_info();

	/**
	 * Lock and perform epoll_ctl.
	 * Arguments the same as for epoll_ctl()
	 */
	int ctl(int op, int fd, epoll_event *event);

	/**
	 * Get the offloaded fds array and its length.
	 * @param adress of the pointer to number of offloaded fds.
	 * @param adress of the offloaded fds array.
	 */
	void get_offloaded_fds_arr_and_size(int **p_p_num_offloaded_fds,
				            int **p_p_offloadded_fds);

	/**
	 * check if fd is cq fd according to the data.
	 * if it is, save the fd in ready cq fds queue.
	 * @param data field from event data
	 * @return true if fd is cq fd
	 */
	bool is_cq_fd(uint64_t data);

	/**
	 * Get the original user data posted with this fd.
	 * @param fd File descriptor.
	 * @return Pointer to user data if the data for this fd was found.
	 */
	epoll_fd_rec* get_fd_rec(int fd);

	/**
	 * Called when fd is closed, to remove it from this set.
	 * @param fd Closed file descriptor.
	 */
	void fd_closed(int fd, bool passthrough = false);

	ep_ready_fd_list_t              m_ready_fds;

	/**
	 * @return Pointer to statistics block for this group
	 */
	epoll_stats_t  *stats();

	int ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);

	int ring_request_notification(uint64_t poll_sn);

	int ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);

	virtual void clean_obj();

	void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);

	// Called from the internal thread to mark that non offloaded data is available.
	void set_os_data_available();

	// Register this epfd to the internal thread, Called after non offloaded data has been received.
	void register_to_internal_thread();

	// Thread safe function which returns true if non offloaded data is available.
	// Will also set m_b_os_data_available to false.
	bool get_and_unset_os_data_available();

	// Returns true if non offloaded data is available.
	inline bool get_os_data_available() {return m_b_os_data_available;}

	static inline size_t epfd_info_node_offset(void) {return NODE_OFFSET(epfd_info, epfd_info_node);}
	list_node<epfd_info, epfd_info::epfd_info_node_offset>	epfd_info_node;

private:

	const int              m_epfd;
	int                    m_size;
	int                    *m_p_offloaded_fds;
	int                    m_n_offloaded_fds;
	fd_info_map_t          m_fd_non_offloaded_map;
	fd_info_list_t         m_fd_offloaded_list;
	ring_map_t             m_ring_map;
	lock_mutex_recursive   m_ring_map_lock;
	lock_spin              m_lock_poll_os;
	const thread_mode_t    m_sysvar_thread_mode;
	ready_cq_fd_q_t        m_ready_cq_fd_q;
	epoll_stats_t          m_local_stats;
	epoll_stats_t          *m_stats;
	int                    m_log_invalid_events;
	bool                   m_b_os_data_available; // true when non offloaded data is available

	int add_fd(int fd, epoll_event *event);
	int del_fd(int fd, bool passthrough = false);
	int mod_fd(int fd, epoll_event *event);

public:
	int get_epoll_fd() {return m_epfd;};
	int remove_fd_from_epoll_os(int fd);
	inline size_t get_fd_non_offloaded_size() {return  m_fd_non_offloaded_map.size();}
	inline size_t get_fd_offloaded_size() {return  m_fd_offloaded_list.size();}
	void insert_epoll_event_cb(socket_fd_api* sock_fd, uint32_t event_flags);
	void insert_epoll_event(socket_fd_api *sock_fd, uint32_t event_flags);
	void remove_epoll_event(socket_fd_api *sock_fd, uint32_t event_flags);
	void increase_ring_ref_count(ring* ring);
	void decrease_ring_ref_count(ring* ring);
};

#endif

