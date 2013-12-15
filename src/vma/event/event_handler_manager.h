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


#ifndef EVENT_HANDLER_MANAGER_H
#define EVENT_HANDLER_MANAGER_H

#include <map>
#include <list>
#include <deque>
#include "vma/util/lock_wrapper.h"
#include "vma/util/wakeup.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/infra/subject_observer.h"
#include "vma/event/command.h"
#include "vma/event/delta_timer.h"
#include "vma/event/timers_group.h"

class timer_handler;
class event_handler_ibverbs;
class event_handler_rdma_cm;

typedef std::map<void* /*event_handler_id*/, event_handler_rdma_cm* /*p_event_handler*/> event_handler_rdma_cm_map_t;

typedef enum {
	REGISTER_TIMER,
	UNREGISTER_TIMER,
	UNREGISTER_TIMERS_AND_DELETE,
	REGISTER_IBVERBS,
	UNREGISTER_IBVERBS,
	REGISTER_RDMA_CM,
	UNREGISTER_RDMA_CM,
	REGISTER_COMMAND,
	UNREGISTER_COMMAND
} event_action_type_e;


struct ibverbs_event_t {
	event_handler_ibverbs*	handler;
	void*			user_data;
};

struct rdma_cm_ev_t {
	int				n_ref_count; // number of event_handler on this fd
	event_handler_rdma_cm_map_t	map_rdma_cm_id; // each event_handler class maps with it's own event_handler_id (referenced as void*)
	void*				cma_channel; // meaning here for the rdma_event_channel object
};

typedef std::map<event_handler_ibverbs*, ibverbs_event_t> ibverbs_event_map_t;

struct ibverbs_ev_t {
	int     		fd;
	void*			channel;
	ibverbs_event_map_t 	ev_map;
};

struct command_ev_t {
	command*	cmd;
};

struct timer_reg_info_t {
	timer_handler*		handler; 
	void* 			node;
	unsigned int		timeout_msec;
	void*			user_data;
	timers_group*		group;
	timer_req_type_t	req_type;
};

struct ibverbs_reg_info_t {
	event_handler_ibverbs*	handler;
	int			fd;
	void*			channel;
	void*			user_data;
};

struct rdma_cm_reg_info_t {
	event_handler_rdma_cm*	handler;
	int			fd;
	void*			id;
	void*			cma_channel;
};

struct command_reg_info_t {
	int 			fd;
	command* 		cmd;
};

struct reg_action_t {
	event_action_type_e		type;
	union {
		timer_reg_info_t	timer;
		ibverbs_reg_info_t	ibverbs;
		rdma_cm_reg_info_t	rdma_cm;
		command_reg_info_t   	cmd;
	} info;
};

typedef std::deque<struct reg_action_t>	reg_action_q_t;

enum {
	EV_IBVERBS,
	EV_RDMA_CM,
	EV_COMMAND,
};


struct event_data_t {
	int type;
	ibverbs_ev_t ibverbs_ev;
	rdma_cm_ev_t rdma_cm_ev;
	command_ev_t command_ev;
};

typedef std::map<int /*fd*/, event_data_t> event_handler_map_t;
typedef std::map<timer_handler*, void *> timer_list_t;


/*
** Class event_handler_manager
** The event manager object listens on the registered channels and distributes the incoming events
** to the appropriate registered event_handlers objects by their registered id's.
** All registered objects must implememtn the event_handler class which is the registered callback function.
*/
class event_handler_manager : public wakeup
{
public:
	event_handler_manager();
	~event_handler_manager();

	void*	register_timer_event(int timeout_msec, timer_handler* handler, timer_req_type_t req_type, void* user_data, timers_group* group = NULL);
	void	unregister_timer_event(timer_handler* handler, void* node);
	void 	unregister_timers_event_and_delete(timer_handler* handler);

	void 	register_ibverbs_event(int fd, event_handler_ibverbs* handler, void* channel, void* user_data);
	void 	unregister_ibverbs_event(int fd, event_handler_ibverbs* handler);

	void 	register_rdma_cm_event(int fd, void* id, void* cma_channel, event_handler_rdma_cm* handler);
	void 	unregister_rdma_cm_event(int fd, void* id);

	void 	register_command_event(int fd, command* cmd);
	void 	unregister_command_event(int fd);

	void*   thread_loop();
	void    stop_thread();

private:
	pthread_t		m_event_handler_tid;
	bool			m_b_continue_running;
	int 			m_cq_epfd;
	int			m_epfd;

	// pipe for the event registration handling
	reg_action_q_t		m_reg_action_q;
	lock_spin		m_reg_action_q_lock;
	timer			m_timer;

	event_handler_map_t	m_event_handler_map;

	void	priv_register_timer_handler(timer_reg_info_t& info);
	void	priv_unregister_timer_handler(timer_reg_info_t& info);
	void	priv_unregister_all_handler_timers(timer_reg_info_t& info);
	void	priv_register_ibverbs_events(ibverbs_reg_info_t& info);
	void	priv_unregister_ibverbs_events(ibverbs_reg_info_t& info);
	void	priv_register_rdma_cm_events(rdma_cm_reg_info_t& info);
	void	priv_unregister_rdma_cm_events(rdma_cm_reg_info_t& info);
	void 	priv_register_command_events(command_reg_info_t& info);
	void 	priv_unregister_command_events(command_reg_info_t& info);
	void	priv_prepare_ibverbs_async_event_queue(event_handler_map_t::iterator& i);

	const char* reg_action_str(event_action_type_e	reg_action_type);
	void    post_new_reg_action(reg_action_t& reg_action);
	void    handle_registration_action(reg_action_t& reg_action);
	void	process_ibverbs_event(event_handler_map_t::iterator &i);
	void	process_rdma_cm_event(event_handler_map_t::iterator &i);
	int     start_thread();
	void    update_epfd(int fd, int operation);

	void 	event_channel_post_process_for_rdma_events(void* p_event);
	void* 	event_channel_pre_process_for_rdma_events(void* p_event_channel_handle, void** p_event);
};


extern event_handler_manager* g_p_event_handler_manager;

extern pthread_t g_n_internal_thread_id;

#endif
