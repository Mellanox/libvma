/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef NETLINK_SOCK_MGR_H
#define NETLINK_SOCK_MGR_H

#include <stdint.h>

#include <queue>

#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "vma/util/if.h"
#include "vma/util/vtypes.h"
#include "vma/util/vma_list.h"
#include "vma/util/utils.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "vma/proto/route_val.h"
#include "vma/proto/route_lookup_key.h"
#include "vma/event/delta_timer.h"

#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((uint8_t *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define MSG_BUFFER_SIZE 16384
#define INITIAL_POOL_SIZE 100
#define BITS_PER_BYTE 8

class netlink_sock_mgr 
{
public:
	netlink_sock_mgr();
	virtual ~netlink_sock_mgr();
	
	bool	route_resolve(route_lookup_key key, route_val *found_route_val = NULL, long timeout_usec = INFINITE_TIMEOUT);

protected:
	lock_mutex	m_buff_pool_lock;
	std::queue<char*> m_buffer_pool;
	uint32_t 	m_pid;
	
	int		create_nl_socket();	
	char*	reserve_buffer();
	void	build_route_get_request(route_lookup_key key, char* buf_ptr);
	void	fill_route_request_addr(int rta_type, in_addr_t addr, struct nlmsghdr *nl_msg);	
	bool	send_request(int fd, struct nlmsghdr *nl_msg);
	int		recv_info(int fd, char* buf_ptr, long timeout_usec);
	bool	init_timer(long timeout_usec, struct timespec* ts_timeout, struct timespec* ts_start);
	bool	update_timer(long timeout_usec, struct timespec* ts_timeout, struct timespec* ts_start);	
	bool	parse_route_entry(nlmsghdr *nl_header, route_val* p_route_val);
	void	parse_route_attr(struct rtattr *rt_attribute, route_val *p_val);
	void 	fill_route_attr_tb(struct rtattr *tb[], int max, struct rtattr *rta, int len);
	void 	fill_nh(struct rtattr *rt_attribute, route_val *p_val);
	void	free_buffer(char* buf_ptr);	

};

#endif /* NETLINK_SOCK_MGR_H */
