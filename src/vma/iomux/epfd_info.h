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


#ifndef VMA_EPOLL_H
#define VMA_EPOLL_H

#include <sys/epoll.h>
#include <limits.h>

#include <vma/util/lock_wrapper.h>
#include <vma/util/vma_stats.h>
#include <vma/sock/cleanable_obj.h>
#include <vma/util/wakeup.h>
#include <vma/dev/ring.h>
#include <vma/sock/sockinfo.h>
#include <tr1/unordered_map>

#define EP_MAX_EVENTS (int)((INT_MAX / sizeof(struct epoll_event)))

typedef std::tr1::unordered_map<int , uint32_t> ep_ready_fd_map_t;

struct epoll_fd_rec
{
	uint32_t events;
	epoll_data 	epdata;
	int		offloaded_index; // offloaded fd index + 1
	epoll_fd_rec():events(0), offloaded_index(0){}
};


typedef std::tr1::unordered_map<int, epoll_fd_rec> fd_info_map_t;
typedef std::tr1::unordered_map<ring*, int /*ref count*/> ring_map_t;
typedef std::deque<int> ready_cq_fd_q_t;

class epfd_info : public lock_mutex_recursive, public cleanable_obj, public wakeup
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
	 * @return Pointer to array of offloaded fd's.
	 */
	int *get_offloaded_fds();
	
	/**
	 * @return Number of offloaded fds.
	 */
	int get_num_offloaded_fds();
	
	/**
	 * @return pointer to the number of offloaded fds.
	 */
	int *get_p_to_num_offloaded_fds();

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
	 * Translates events from returned data to original user data
	 * @return Number of events in dst
	 */
	int translate_ready_events(epoll_event *dst, epoll_event *src, int count);
	
	/**
	 * Get the original user data posted with this fd.
	 * @param fd File descriptor.
	 * @param data Pointer to fill with user data.
	 */
	bool get_data_by_fd(int fd, epoll_data *data);

	bool get_fd_rec_by_fd(int fd, epoll_fd_rec& fd_rec);

	/**
	 * @param fd File descriptor.
	 * @return Whether given fd is and offloaded fd in this epfd set.
	 */
	bool is_offloaded_fd(int fd);

	/**
	 * Called when fd is closed, to remove it from this set.
	 * @param fd Closed file descriptor.
	 */
	void fd_closed(int fd, bool passthrough = false);

	ep_ready_fd_map_t               m_ready_fds;
	uint32_t m_ready_fd;
	int clear_events_for_fd(int fd, uint32_t events);

	/**
	 * @return Pointer to statistics block for this group
	 */
	epoll_stats_t  *stats();

	int ring_poll_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);

	int ring_request_notification(uint64_t poll_sn);

	int ring_wait_for_notification_and_process_element(uint64_t *p_poll_sn, void* pv_fd_ready_array = NULL);

private:

	const int			m_epfd;
	int					m_size;
	int				*m_p_offloaded_fds;
	int				m_n_offloaded_fds;
	fd_info_map_t                   m_fd_info;
	ring_map_t			m_ring_map;
	lock_mutex_recursive		m_ring_map_lock;
	ready_cq_fd_q_t			m_ready_cq_fd_q;
	epoll_stats_t                   m_local_stats;
	epoll_stats_t                   *m_stats;
	int				m_log_invalid_events;

	/**
	 * check whether a given file-descriptor is attached to epfd (offloaded)
	 * ARGS: a file-descriptor to check for
	 */
	bool is_fd_in_use(int fd);

	int add_fd(int fd, epoll_event *event);

	int del_fd(int fd, bool passthrough = false);

	int mod_fd(int fd, epoll_event *event);

	void increase_ring_ref_count_no_lock(ring* ring);
	void decrease_ring_ref_count_no_lock(ring* ring);

	inline int remove_fd_from_epoll_os(int fd);

public:
	const fd_info_map_t& get_fd_info() {return  m_fd_info;} // TODO: remove
	void insert_epoll_event_cb(int fd, uint32_t event_flags);
	void insert_epoll_event(int fd, uint32_t event_flags);
	void remove_epoll_event(int fd, uint32_t event_flags);
	void increase_ring_ref_count(ring* ring);
	void decrease_ring_ref_count(ring* ring);
	void set_fd_as_offloaded_only(int fd);

};


#if 0
/**
 *-----------------------------------------------------------------------------
 *  class Epoll_fd_tbl
 *  Track the usage of epoll file descriptors per process
 *-----------------------------------------------------------------------------
 */

class Epoll_fd_tbl {
public:

	typedef std::map<int /*epfd*/, epfd_info> epoll_handle_map_t;


	// CTOR/DTOR
	Epoll_fd_tbl()		{};
	~Epoll_fd_tbl() 	{vlog_printf(VLOG_DEBUG,"%s\n", __func__);};

	int insert_epfd(int epfd) {  // insert
		epfd_info  newVal;
		newVal.m_is_poll_last = false;
		newVal.m_epfd = epfd;
		epfd_map_mtx.lock();
		//Sr_lock_t srl(&mtx);	// lock!
		epoll_handle_map_t::iterator iter = epoll_handle_map.find(epfd);
		if (iter != epoll_handle_map.end()) {
			// 'epfd' entry exists in epoll_handle_map
			epfd_map_mtx.unlock();
			vlog_printf(VLOG_ERROR,"%s: epfd %d is already in poll_handle_map\n",__func__,epfd);
			return -1;
		}
		else
			epoll_handle_map[epfd] = newVal;    // insert entry into tbl & mark 'fd' valid
		epfd_map_mtx.unlock();
		return 0;
	}

	int del_epfd(int epfd) {  //del
		vlog_printf(VLOG_FUNC,"%s epfd=%d\n",__func__,epfd);
		epfd_map_mtx.lock();
		epoll_handle_map_t::iterator iter = epoll_handle_map.find(epfd);
		if (iter != epoll_handle_map.end()) {
			iter->second.m_epfd_info_mtx.lock(); // Lock epfd
			epoll_handle_map.erase(iter);
			epfd_map_mtx.unlock();
			vlog_printf(VLOG_DEBUG,"%s: epfd %d is deleted\n",__func__,epfd);
			return 0;
		}
		// 'epfd' entry doesn't exist in tbl
		vlog_printf(VLOG_ERROR,"%s: epfd %d doesn't exist\n",__func__,epfd);
		epfd_map_mtx.unlock();
		return -1;
	}


	bool find_and_lock_epfd_info(int epfd, epfd_info ** pData) {
		epfd_map_mtx.lock();
		epoll_handle_map_t::iterator iter = epoll_handle_map.find(epfd);
		if (iter != epoll_handle_map.end()) {  // 'fd' entry exists in tbl
			iter->second.m_epfd_info_mtx.lock();
			*pData = &(iter->second);
			epfd_map_mtx.unlock();
			return true;
		}
		epfd_map_mtx.unlock();
		vlog_printf(VLOG_DEBUG,"%s: epfd %d wasn't found\n",__func__, epfd);
		pData = NULL;
		errno = EINVAL;
		return false;
	}


	/**
	 * check whether given epoll file-descriptor is in the epoll_handle_map (i.e. used by the app)
	 * ARGS:    I: file-descriptor to check for
	 */
	bool is_epfd_in_use(int epfd) {
		epfd_map_mtx.lock();
		epoll_handle_map_t::const_iterator iter = epoll_handle_map.find(epfd);
		if (iter != epoll_handle_map.end()) {
			// 'epfd' entry exists in tbl
			epfd_map_mtx.unlock();
			return true;
		}
		epfd_map_mtx.unlock();
		return false;
	}



	 /**
	  * erase a given file-descriptor from the DB ( offloaded map or not offloaded map).
	  * ARGS:    I: file-descriptor to check for
	  */
	void del_fd(int fd) {
		vlog_printf(VLOG_FUNC,"%s: fd %d\n",__func__,fd);
		epfd_map_mtx.lock();
		for (epoll_handle_map_t::iterator iter = epoll_handle_map.begin(); iter != epoll_handle_map.end(); iter++) {
			iter->second.m_epfd_info_mtx.lock();
			iter->second.del_not_offloaded_fd(fd);
			iter->second.del_fd(fd);
			iter->second.m_epfd_info_mtx.unlock();
		 }
		 epfd_map_mtx.unlock();
	}


	// list the content of the table - For Debug!
	void list_epoll_fd_tbl() {
		vlog_printf(VLOG_DEBUG,"%s: tbl contains %d socket(s)\n",__func__, epoll_handle_map.size());
		//int num = 0;
		for (epoll_handle_map_t::iterator iter = epoll_handle_map.begin(); iter != epoll_handle_map.end(); iter++) {
			printf("%s: epfd=%d\n",__func__,iter->first);
			for (epfd_info::offloaded_epoll_fd_map_t::iterator fd_iter = iter->second.m_offloaded_epoll_fd_map.begin(); fd_iter != iter->second.m_offloaded_epoll_fd_map.end(); fd_iter++)
				printf("%s: \t offloaded fd = %d events = %d  events.fd = %d \n",__func__,fd_iter->first, fd_iter->second.events, fd_iter->second.data.fd);

			for (epfd_info::not_offloaded_epoll_fd_map_t::iterator fd2_iter = iter->second.m_not_offloaded_epoll_fd_map.begin(); fd2_iter != iter->second.m_not_offloaded_epoll_fd_map.end(); fd2_iter++)
				printf("%s: \t not offloaded fd = %d user fd = %ld\n",__func__, fd2_iter->first, (long int)fd2_iter->second);
		}
	}

private:
	epoll_handle_map_t	epoll_handle_map;
	lock_mutex		epfd_map_mtx;
};




extern Epoll_fd_tbl * g_p_epfd_map;

#endif
#endif

