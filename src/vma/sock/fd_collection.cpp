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


#include "fd_collection.h"

#include <sys/resource.h>
#include <vma/iomux/epfd_info.h>

#include "sock-redirect.h"
#include "socket_fd_api.h"
#include "sockinfo_udp.h"
#include "pipeinfo.h"
#include "sockinfo_tcp.h"
#include <vma/util/libvma.h>
#include "vma/util/bullseye.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"fdc:"
#undef  MODULE_HDR
#define MODULE_HDR	 	MODULE_NAME "%d:%s() "

#define fdcoll_logpanic		__log_panic
#define fdcoll_logerr		__log_err
#define fdcoll_logwarn		__log_warn
#define fdcoll_loginfo		__log_info
#define fdcoll_logdbg		__log_dbg
#define fdcoll_logfunc		__log_func


fd_collection* g_p_fd_collection = NULL;

fd_collection::fd_collection() :
	lock_mutex_recursive("fd_collection"),
	m_p_cma_event_channel(NULL),
	m_timer_handle(0)
{
	fdcoll_logfunc("");

	m_n_fd_map_size = 1024;
	struct rlimit rlim;
	if ((getrlimit(RLIMIT_NOFILE, &rlim) == 0) && ((int)rlim.rlim_max > m_n_fd_map_size))
		m_n_fd_map_size = rlim.rlim_max;
	fdcoll_logdbg("using open files max limit of %d file descriptors", m_n_fd_map_size);

	m_p_sockfd_map = new socket_fd_api*[m_n_fd_map_size];
	memset(m_p_sockfd_map, 0, m_n_fd_map_size * sizeof(socket_fd_api*));

	m_p_epfd_map = new epfd_info*[m_n_fd_map_size];
	memset(m_p_epfd_map, 0, m_n_fd_map_size * sizeof(epfd_info*));

	m_p_cq_channel_map = new cq_channel_info*[m_n_fd_map_size];
	memset(m_p_cq_channel_map, 0, m_n_fd_map_size * sizeof(cq_channel_info*));
}

fd_collection::~fd_collection()
{
	fdcoll_logfunc("");

	m_n_fd_map_size = -1;
	clear();

	delete [] m_p_sockfd_map;
	m_p_sockfd_map = NULL;

	delete [] m_p_epfd_map;
	m_p_epfd_map = NULL;

	delete [] m_p_cq_channel_map;
	m_p_cq_channel_map = NULL;
}

//Triggers connection close of all handled fds.
//This is important for TCP connection which needs some time to terminate the connection,
//before the connection can be finally and properly closed.
void fd_collection::prepare_to_close()
{
	lock();
	for (int fd = 0; fd < m_n_fd_map_size; ++fd) {
		if (m_p_sockfd_map[fd]) {
			if(!g_is_forked_child) {
				socket_fd_api *p_sfd_api = get_sockfd(fd);
				if (p_sfd_api) {
					p_sfd_api->prepare_to_close(true);
				}
			}
		}
	}
	unlock();
}

void fd_collection::clear()
{
	int fd;

	fdcoll_logfunc("");

	if (!m_p_sockfd_map)
		return;

	lock();

	if (m_timer_handle) {
		g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
		m_timer_handle = 0;
	}

	//internal thread should be already dead and these sockets should have been deleted through the internal thread.
	sock_fd_api_list_t::iterator itr;
	for (itr = m_pendig_to_remove_lst.begin(); itr != m_pendig_to_remove_lst.end(); itr++) {
		(*itr)->force_close();
	}

	// Clean up all left overs sockinfo
	for (fd = 0; fd < m_n_fd_map_size; ++fd) {
		if (m_p_sockfd_map[fd]) {
			if(!g_is_forked_child) {
				socket_fd_api *p_sfd_api = get_sockfd(fd);
				if (p_sfd_api) {
					p_sfd_api->statistics_print();
					p_sfd_api->destructor_helper();
				}
			}
	/**** Problem here - if one sockinfo is in a blocked call rx()/tx() then this will block too!!!
	 * also - statistics_print() and destructor_helper() should not be called in two lines above, because they are called from the dtor
			delete m_p_sockfd_map[fd];
	*/
			m_p_sockfd_map[fd] = NULL;
			fdcoll_logdbg("destroyed fd=%d", fd);
		}

		if (m_p_epfd_map[fd]) {
			epfd_info *p_epfd = get_epfd(fd);
			if (p_epfd) {
				delete p_epfd;
			}
			m_p_epfd_map[fd] = NULL;
			fdcoll_logdbg("destroyed epfd=%d", fd);
		}

		if (m_p_cq_channel_map[fd]) {
			cq_channel_info *p_cq_ch_info = get_cq_channel_fd(fd);
			if (p_cq_ch_info) {
				delete p_cq_ch_info;
			}
			m_p_cq_channel_map[fd] = NULL;
			fdcoll_logdbg("destroyed cq_channel_fd=%d", fd);
		}
	}


	if (!g_is_forked_child && m_p_cma_event_channel) {
		fdcoll_logdbg("Removing rdma_cm event_channel");

		// Set event channel as non-blocking
		set_fd_block_mode(m_p_cma_event_channel->fd, false);

		// Remove all pending events in cahnnel
		struct rdma_cm_event* p_rdma_cm_event = NULL;
		while (rdma_get_cm_event(m_p_cma_event_channel, &p_rdma_cm_event) == 0) {
			rdma_ack_cm_event(p_rdma_cm_event);
		}

		rdma_destroy_event_channel(m_p_cma_event_channel);
	}

	m_p_cma_event_channel = NULL;
	unlock();
	fdcoll_logfunc("done");
}

int fd_collection::addsocket(int fd, int domain, int type, bool check_offload /*= false*/)
{
	transport_t transport;
	const int SOCK_TYPE_MASK = 0xf;
	int sock_type = type & SOCK_TYPE_MASK;
	int sock_flags = type & ~SOCK_TYPE_MASK;

	if (check_offload && !create_offloaded_sockets()) {
		fdcoll_logdbg("socket [fd=%d, domain=%d, type=%d] is not offloaded by thread rules or by VMA_OFFLOADED_SOCKETS", fd, domain, type);
		return -1;
	}

	// IPV4 domain only (at least today)
	if (domain != AF_INET)
		return -1;

	fdcoll_logfunc("fd=%d", fd);

	if (!is_valid_fd(fd))
		return -1;

	// On-demand creation of the fd_collection dedicated rdma event channel
	if (m_p_cma_event_channel == NULL) {
		m_p_cma_event_channel = rdma_create_event_channel();
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_p_cma_event_channel == NULL) {
			fdcoll_logpanic("failed to create event channel");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		fdcoll_logdbg("On-demand creation of cma event channel on fd=%d", m_p_cma_event_channel->fd);
	}

	lock();

	// Sanity check to remove any old sockinfo object using the same fd!!
	socket_fd_api* p_sfd_api_obj = get_sockfd(fd);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_sfd_api_obj) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", fd, p_sfd_api_obj);
		unlock();
		handle_close(fd);
		lock();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	unlock();
	switch (sock_type) {
		case SOCK_DGRAM:
		{	transport = __vma_match_by_program(PROTO_UDP, mce_sys.app_id);
			if (transport == TRANS_OS) {
				fdcoll_logdbg("All UDP rules are consistent and instructing to use OS. TRANSPORT: OS");
				return -1;
			}
			fdcoll_logdbg("UDP rules are either not consistent or instructing to use VMA. TRANSPORT: VMA");
			p_sfd_api_obj = new sockinfo_udp(fd);
			break;
		}
		case SOCK_STREAM:
		{
			transport = __vma_match_by_program(PROTO_TCP, mce_sys.app_id);
			if (transport == TRANS_OS) {
				fdcoll_logdbg("All TCP rules are consistent and instructing to use OS.transport == USE_OS");
				return -1;
			}
			fdcoll_logdbg("TCP rules are either not consistent or instructing to use VMA.transport == USE_VMA");
			p_sfd_api_obj = new sockinfo_tcp(fd);
			break;
		}
		default:
			fdcoll_logdbg("unsupported socket type=%d", sock_type);
			return -1;
	}

	lock();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_sfd_api_obj == NULL) {
		fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", fd);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (sock_flags) {
		if (sock_flags & SOCK_NONBLOCK)
			p_sfd_api_obj->fcntl(F_SETFL, O_NONBLOCK);
		if (sock_flags & SOCK_CLOEXEC)
			p_sfd_api_obj->fcntl(F_SETFD, FD_CLOEXEC);
	}

	m_p_sockfd_map[fd] = p_sfd_api_obj;

	unlock();

	return fd;
}

bool fd_collection::create_offloaded_sockets()
{
	bool ret = mce_sys.offloaded_sockets;

	lock();
	if (m_offload_thread_rule.find(pthread_self()) == m_offload_thread_rule.end()) {
		unlock();
		return ret;
	}
	unlock();

	return !ret;
}

/*
 * Create sockets on the given thread as offloaded/not-offloaded.
 * pass true for offloaded, false for not-offloaded.
 */
void fd_collection::offloading_rule_change_thread(bool offloaded, pthread_t tid)
{
	fdcoll_logdbg("tid=%ul, offloaded=%d", tid, offloaded);

	lock();
	if (offloaded == mce_sys.offloaded_sockets) {
		m_offload_thread_rule.erase(tid);
	} else {
		m_offload_thread_rule[tid] = 1;
	}
	unlock();
}

int fd_collection::addpipe(int fdrd, int fdwr)
{
	fdcoll_logfunc("fdrd=%d, fdwr=%d", fdrd, fdwr);

	if (!is_valid_fd(fdrd) || !is_valid_fd(fdwr))
		return -1;

	lock();

	// Sanity check to remove any old objects using the same fd!!
	socket_fd_api* p_fdrd_api_obj = get_sockfd(fdrd);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_fdrd_api_obj) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate object (%p)", fdrd, p_fdrd_api_obj);
		unlock();
		handle_close(fdrd, true);
		lock();
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	socket_fd_api* p_fdwr_api_obj = get_sockfd(fdwr);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_fdwr_api_obj) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate object (%p)", fdwr, p_fdwr_api_obj);
		unlock();
		handle_close(fdwr, true);
		lock();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	unlock();
	p_fdrd_api_obj = new pipeinfo(fdrd);
	p_fdwr_api_obj = new pipeinfo(fdwr);
	lock();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_fdrd_api_obj == NULL) {
		fdcoll_logpanic("[fd=%d] Failed creating new pipeinfo (%m)", fdrd);
	}
	if (p_fdwr_api_obj == NULL) {
		fdcoll_logpanic("[fd=%d] Failed creating new pipeinfo (%m)", fdwr);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	m_p_sockfd_map[fdrd] = p_fdrd_api_obj;
	m_p_sockfd_map[fdwr] = p_fdwr_api_obj;

	unlock();

	return 0;
}

int fd_collection::addepfd(int epfd, int size)
{
	fdcoll_logfunc("epfd=%d", epfd);

	if (!is_valid_fd(epfd))
		return -1;

	lock();

	// Sanity check to remove any old sockinfo object using the same fd!!
	epfd_info* p_fd_info = get_epfd(epfd);
	if (p_fd_info) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", epfd, p_fd_info);
		unlock();
		handle_close(epfd, true);
		lock();
	}

	unlock();
	p_fd_info = new epfd_info(epfd, size);
	lock();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_fd_info == NULL) {
		fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", epfd);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	m_p_epfd_map[epfd] = p_fd_info;

	unlock();

	return 0;
}

int fd_collection::add_cq_channel_fd(int cq_ch_fd, ring* p_ring)
{
	fdcoll_logfunc("cq_ch_fd=%d", cq_ch_fd);

	if (!is_valid_fd(cq_ch_fd))
		return -1;

	lock();

	epfd_info* p_fd_info = get_epfd(cq_ch_fd);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_fd_info) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", cq_ch_fd, p_fd_info);
		unlock();
		handle_close(cq_ch_fd, true);
		lock();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Sanity check to remove any old objects using the same fd!!
	socket_fd_api* p_cq_ch_fd_api_obj = get_sockfd(cq_ch_fd);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_cq_ch_fd_api_obj) {
		fdcoll_logwarn("[fd=%d] Deleting old duplicate object (%p)", cq_ch_fd, p_cq_ch_fd_api_obj);
		unlock();
		handle_close(cq_ch_fd, true);
		lock();
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// Check if cq_channel_info was already created
	cq_channel_info* p_cq_ch_info = get_cq_channel_fd(cq_ch_fd);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_cq_ch_info) {
		fdcoll_logwarn("cq channel fd already exists in fd_collection");
		m_p_cq_channel_map[cq_ch_fd] = NULL;
		delete p_cq_ch_info;
		p_cq_ch_info = NULL;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	unlock();
	p_cq_ch_info = new cq_channel_info(p_ring);
	lock();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (p_cq_ch_info == NULL) {
		fdcoll_logpanic("[fd=%d] Failed creating new cq_channel_info (%m)", cq_ch_fd);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	m_p_cq_channel_map[cq_ch_fd] = p_cq_ch_info;

	unlock();

	return 0;
}

int fd_collection::del_sockfd(int fd, bool b_cleanup /*=false*/)
{
	int ret_val = -1;
	socket_fd_api *p_sfd_api;

	p_sfd_api = get_sockfd(fd);

	if (p_sfd_api) {
		//TCP socket need some timer to before it can be deleted,
		//in order to gracefuly terminate TCP connection
		//so we have to stages:
		//1. Prepare to close: kikstarts TCP connection termination
		//2. Socket deletion when TCP connection == CLOSED
		if (p_sfd_api->prepare_to_close()) {
			//the socket is already closable
			ret_val = del(fd, b_cleanup, m_p_sockfd_map);
		}
		else {
			lock();
			//The socket is not ready for close.
			//Delete it from fd_col and add it to pending_to_remove list.
			//This socket will be handled and destroyed now by fd_col.
			//This will be done from fd_col timer handler.
			m_p_sockfd_map[fd] = NULL;
			m_pendig_to_remove_lst.push_front(p_sfd_api);				
			
			if (m_pendig_to_remove_lst.size() == 1) {
				//Activate timer
				m_timer_handle = g_p_event_handler_manager->register_timer_event(250, this, PERIODIC_TIMER, 0);
			}
			unlock();
			ret_val = 0;
		}
	}

	return ret_val;
}

int fd_collection::del_epfd(int fd, bool b_cleanup /*=false*/)
{
	return del(fd, b_cleanup, m_p_epfd_map);
}

int fd_collection::del_cq_channel_fd(int fd, bool b_cleanup /*=false*/)
{
	return del(fd, b_cleanup, m_p_cq_channel_map);
}

template <typename cls>
int fd_collection::del(int fd, bool b_cleanup, cls **map_type)
{
	fdcoll_logfunc("fd=%d%s", fd, 
	               b_cleanup ? ", cleanup case: trying to remove old socket handler":"");

	if (!is_valid_fd(fd))
		return -1;

	lock();
	cls* p_obj = map_type[fd];
	if (p_obj) {
		map_type[fd] = NULL;
		unlock();
		p_obj->clean_obj();
		return 0;
	}
	if (!b_cleanup) {
		fdcoll_logdbg("[fd=%d] Could not find related object", fd);
	}
	unlock();
	return -1;
}

void  fd_collection::handle_timer_expired(void* user_data)
{
	sock_fd_api_list_t::iterator itr;
	fdcoll_logfunc();

	lock();

	NOT_IN_USE(user_data);

	for (itr = m_pendig_to_remove_lst.begin(); itr != m_pendig_to_remove_lst.end(); ) {
		if((*itr)->is_closable()) {
			fdcoll_logfunc("Closing:%d", (*itr)->get_fd());
			//The socket is ready to be closed, remove it from the list + delete it
			sock_fd_api_list_t::iterator to_delete = itr;
			socket_fd_api* p_sock_fd = *to_delete;

			if (p_sock_fd) {
				p_sock_fd->clean_obj();
				p_sock_fd = NULL;
			}
			itr++;
			m_pendig_to_remove_lst.erase(to_delete);

			//Deactivate the timer since there are no any pending to remove socket to handle anymore
			if (!m_pendig_to_remove_lst.size()) {
				if (m_timer_handle) {
					g_p_event_handler_manager->unregister_timer_event(this, m_timer_handle);
					m_timer_handle = 0;
				}
			}
		}
		else { //The socket is not closable yet
			sockinfo_tcp* si_tcp = dynamic_cast<sockinfo_tcp*>(*itr);

			if (si_tcp) {
				//In case of TCP socket progress the TCP connection
				fdcoll_logfunc("Call to handler timer of TCP socket:%d", (*itr)->get_fd());
				si_tcp->handle_timer_expired(NULL);
			}
			itr++;
		}
	}

	unlock();
}

void fd_collection::remove_from_all_epfds(int fd, bool passthrough)
{
	int epfd;

	lock();
	for (epfd = 0; epfd < m_n_fd_map_size; ++epfd) {
		if (m_p_epfd_map[epfd]) {
			m_p_epfd_map[epfd]->fd_closed(fd, passthrough);
		}
	}
	unlock();

	return;
}
