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


#ifndef FD_COLLECTION_H
#define FD_COLLECTION_H

#include <map>
#include <list>
#include <rdma/rdma_cma.h>
#include "vlogger/vlogger.h"

#include "vma/util/lock_wrapper.h"
#include "vma/iomux/epfd_info.h"

#include "vma/sock/socket_fd_api.h"
#include "vma/event/timer_handler.h"
#include "vma/event/event_handler_manager.h"
#include <vma/sock/cleanable_obj.h>

typedef std::list<socket_fd_api*> sock_fd_api_list_t;

typedef std::tr1::unordered_map<pthread_t, int> offload_thread_rule_t;

#define fdcoll_logfuncall(log_fmt, log_args...)		do { if (g_vlogger_level >= VLOG_FUNC_ALL) vlog_printf(VLOG_FUNC_ALL, "fdc:%d:%s() " log_fmt "\n", __LINE__, __FUNCTION__, ##log_args); } while (0)


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
	 * Remove pipeinfo/sockinfo.
	 */
	int			del_sockfd(int fd, bool b_cleanup = false);
	
	/**
	 * Remove epfd_info.
	 */
	int			del_epfd(int fd, bool b_cleanup = false);

	/**
	 * Remove cq_channel_info.
	 */
	int			del_cq_channel_fd(int fd, bool b_cleanup = false);

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

private:
	template <typename cls>	int del(int fd, bool b_cleanup, cls **map_type);
	template <typename cls>	inline cls* get(int fd, cls **map_type);
	
	int				m_n_fd_map_size;
	socket_fd_api**			m_p_sockfd_map;
	epfd_info**			m_p_epfd_map;
	cq_channel_info**		m_p_cq_channel_map;

	//Contains fds which are in closing process
	sock_fd_api_list_t		m_pendig_to_remove_lst;

	rdma_event_channel* 		m_p_cma_event_channel;
	void*				m_timer_handle;

	//if (mce_sys.offloaded_sockets is true) contain all threads that need not be offloaded.
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
	fdcoll_logfuncall("fd=%d %sFound", fd, (obj ? "" : "Not "));
	return obj;
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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
inline int fd_collection::get_fd_map_size()
{
	return m_n_fd_map_size;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

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
