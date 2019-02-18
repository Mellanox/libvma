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


#ifndef FD_COLLECTION_H
#define FD_COLLECTION_H

#include <map>
#include <rdma/rdma_cma.h>
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/iomux/epfd_info.h"

#include "vma/sock/socket_fd_api.h"
#include "vma/event/timer_handler.h"
#include "vma/event/event_handler_manager.h"
#include <vma/sock/cleanable_obj.h>
#include "vma/dev/ring_tap.h"

typedef vma_list_t<socket_fd_api, socket_fd_api::pendig_to_remove_node_offset> sock_fd_api_list_t;
typedef vma_list_t<epfd_info, epfd_info::epfd_info_node_offset> epfd_info_list_t;

typedef std::tr1::unordered_map<pthread_t, int> offload_thread_rule_t;

#if (VMA_MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define fdcoll_logfuncall(log_fmt, log_args...)         ((void)0)
#else
#define fdcoll_logfuncall(log_fmt, log_args...)		do { if (g_vlogger_level >= VLOG_FUNC_ALL) vlog_printf(VLOG_FUNC_ALL, "fdc:%d:%s() " log_fmt "\n", __LINE__, __FUNCTION__, ##log_args); } while (0)
#endif /* VMA_MAX_DEFINED_LOG_LEVEL */

class cq_channel_info: public cleanable_obj
{
public:
	cq_channel_info(ring* p_ring) : m_p_ring(p_ring) {};
	~cq_channel_info() {};
	ring*	get_ring() const { return m_p_ring; };

protected:
	ring*	m_p_ring;
};


class fd_collection : private lock_mutex_recursive, public timer_handler
{
public:
	fd_collection();
	~fd_collection();

	/**
	 * Create and add a sockinfo. Use get_sock() to get it.
	 * @param domain e.g AF_INET.
	 * @param type e.g SOCK_DGRAM.
	 * @return socket fd or -1 on failure.
	 */
	int			addsocket(int fd, int domain, int type, bool check_offload = false);
	
	/**
	 * Create pipeinfo. Use get_sock() to get it.
	 * @param fdrd Read fd.
	 * @param fdwr Write fd.
	 * @return 0 on success, -1 on failure.
	 */
	int			addpipe(int fdrd, int fdwr);
	
	/**
	 * Create epfd_info. Use get_epfd() to get it.
	 * @param epfd epoll fd.
	 * @param size epoll fd size (as passed to epoll_create).
	 * @return 0 on success, -1 on failure.
	 */
	int			addepfd(int epfd, int size);

	/**
	 * Create cq_channel_info. Use get_cq_channel_info() to get it.
	 * @param cq_ch_fd: cq channel fd.
	 * @param p_ring: pointer to ring which is the relevant rx_cq owner.
	 * @return 0 on success, -1 on failure.
	 */
	int			add_cq_channel_fd(int cq_ch_fd, ring* p_ring);
	
	/**
	 * Add tap fd index to tap_map.
	 * @param tapfd: tap fd.
	 * @param p_ring: pointer to ring owner of the tap.
	 * @return 0 on success, -1 on failure.
	 */
	int			addtapfd(int tapfd, ring_tap* p_ring);

	/**
	 * Remove pipeinfo/sockinfo.
	 */
	int			del_sockfd(int fd, bool b_cleanup = false);
	
	/**
	 * Remove epfd_info.
	 */
	int			del_epfd(int fd, bool b_cleanup = false);
	void			remove_epfd_from_list(epfd_info* epfd);

	/**
	 * Remove cq_channel_info.
	 */
	int			del_cq_channel_fd(int fd, bool b_cleanup = false);

	/**
	 * Remove tap_fd from tap_map.
	 */
	void		del_tapfd(int fd);

	/**
	 * Call set_immediate_os_sample of the input fd.
	 */
	inline bool set_immediate_os_sample(int fd);

	/**
	 * Get sock_fd_api (sockinfo or pipeinfo) by fd.
	 */
	inline socket_fd_api*	get_sockfd(int fd);
	
	/**
	 * Get epfd_info by fd.
	 */
	inline epfd_info*	get_epfd(int fd);

	/**
	 * Get cq_channel_info by fd.
	 */
	inline cq_channel_info* get_cq_channel_fd(int fd);

	/**
	 * Get rint_tap by tap fd.
	 */
	inline ring_tap* get_tapfd(int fd);

	/**
	 * Get the fd_map size.
	 */
	inline int 	get_fd_map_size();

	/**
	 * Remove fd from the collection of all epfd's
	 */
	void remove_from_all_epfds(int fd, bool passthrough);
	
	/**
	 * Remove everything from the collection.
	 */
	void 			clear();
	void 			prepare_to_close();

	void			offloading_rule_change_thread(bool offloaded, pthread_t tid);

	/**
	 * Dump fd statistics using VMA logger.
	 */
	void 			statistics_print(int fd, vlog_levels_t log_level);

private:
	template <typename cls>	int del(int fd, bool b_cleanup, cls **map_type);
	template <typename cls>	inline cls* get(int fd, cls **map_type);
	
	int				m_n_fd_map_size;
	socket_fd_api**			m_p_sockfd_map;
	epfd_info**			m_p_epfd_map;
	cq_channel_info**		m_p_cq_channel_map;
	ring_tap**		m_p_tap_map;

	epfd_info_list_t		m_epfd_lst;
	//Contains fds which are in closing process
	sock_fd_api_list_t		m_pendig_to_remove_lst;

	void*				m_timer_handle;

	const bool			m_b_sysvar_offloaded_sockets;

	//if (m_b_sysvar_offloaded_sockets is true) contain all threads that need not be offloaded.
	//else contain all threads that need to be offloaded.
	offload_thread_rule_t		m_offload_thread_rule;

	inline bool  			is_valid_fd(int fd);

	inline bool			create_offloaded_sockets();

	//Fd collection timer implementation
	//This gives context to handle pending to remove fds.
	//In case of TCP we recheck if TCP socket is closable and delete
	//it if it does otherwise we run handle_timer of the socket to
	//progress the TCP connection.
	void  				handle_timer_expired(void* user_data);

	void 				statistics_print_helper(int fd, vlog_levels_t log_level);
};


inline bool fd_collection::is_valid_fd(int fd)
{
	if (fd < 0 || fd >= m_n_fd_map_size)
		return false;
	return true;
}

template <typename cls>	
inline cls* fd_collection::get(int fd, cls **map_type)
{
	if (!is_valid_fd(fd))
		return NULL;

	cls* obj = map_type[fd];
	return obj;
}

inline bool fd_collection::set_immediate_os_sample(int fd)
{
	epfd_info* epfd_fd;
	ring_tap* p_ring;

	auto_unlocker locker(*this);

	if ((p_ring = get_tapfd(fd))) {
		p_ring->set_tap_data_available();
		return true;
	}

	if ((epfd_fd = get_epfd(fd))){
		epfd_fd->set_os_data_available();
		return true;
	}

	return false;
}

inline socket_fd_api* fd_collection::get_sockfd(int fd)
{
	return get(fd, m_p_sockfd_map);
}

inline epfd_info* fd_collection::get_epfd(int fd)
{
	return get(fd, m_p_epfd_map);
}

inline cq_channel_info* fd_collection::get_cq_channel_fd(int fd)
{
	return get(fd, m_p_cq_channel_map);
}

inline ring_tap* fd_collection::get_tapfd(int fd)
{
	return get(fd, m_p_tap_map);
}

inline int fd_collection::get_fd_map_size()
{
	return m_n_fd_map_size;
}

extern fd_collection* g_p_fd_collection;

inline socket_fd_api* fd_collection_get_sockfd(int fd)
{
	if (g_p_fd_collection) 
		return g_p_fd_collection->get_sockfd(fd);
	return NULL;
}

inline epfd_info* fd_collection_get_epfd(int fd)
{
	if (g_p_fd_collection) 
		return g_p_fd_collection->get_epfd(fd);
	return NULL;
}

#endif
