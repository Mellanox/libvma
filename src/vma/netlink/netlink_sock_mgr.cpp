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

 
#include <unistd.h>
#include <bits/sockaddr.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "utils/bullseye.h"
#include "netlink_sock_mgr.h"

#define MODULE_NAME	"netlink_sock_mgr:"

#define nl_sock_mgr_logerr		__log_err
#define nl_sock_mgr_logwarn		__log_warn
#define nl_sock_mgr_logdbg		__log_dbg

netlink_sock_mgr::netlink_sock_mgr() : m_buff_pool_lock(MODULE_NAME "::m_buff_pool_lock")
{
	nl_sock_mgr_logdbg("");
	m_pid = getpid();
	char* buf_ptr;
	for (int i = 0; i < INITIAL_POOL_SIZE; i++) {
		buf_ptr = (char*) malloc(sizeof(char) * MSG_BUFFER_SIZE);
		if(buf_ptr) {
			m_buffer_pool.push(buf_ptr);
		}	
	}
	nl_sock_mgr_logdbg("Done");
}

netlink_sock_mgr::~netlink_sock_mgr()
{
	nl_sock_mgr_logdbg("");
	while (!m_buffer_pool.empty())
	{
		free(m_buffer_pool.front());
		m_buffer_pool.pop();
	}
	nl_sock_mgr_logdbg("Done");
}

bool netlink_sock_mgr::route_resolve(route_lookup_key key, route_val *found_route_val, long timeout_usec) 
{
	int len = 0, fd = -1;
	char *buf_ptr = NULL;
	bool is_resolved = false;

	if (!found_route_val) {
		nl_sock_mgr_logwarn("Illegal argument. user pass NULL route_val to fill");
		goto out;
	}
		
	if ((fd = create_nl_socket()) < 0) {
		goto out;
	}

	buf_ptr = reserve_buffer();
	if (!buf_ptr) {
		nl_sock_mgr_logerr("Error while reserving buffer");
		goto out;
	}

	build_route_get_request(key, buf_ptr);

	if (!send_request(fd, (struct nlmsghdr *) buf_ptr)) {
		goto out;
	}
	
	if((len = recv_info(fd, buf_ptr, timeout_usec)) < 0) {
		nl_sock_mgr_logerr("Read From Socket Failed, error = %d", errno);
		goto out;
	}
	
	if (!NLMSG_OK((struct nlmsghdr *) buf_ptr, (u_int)len)){
		nl_sock_mgr_logerr("Error in returned data");		
		goto out;
	}
	
	if (!parse_route_entry((struct nlmsghdr *) buf_ptr, found_route_val)) {
		nl_sock_mgr_logerr("Can't parse returned data in route_val object");
		goto out;
	} 
	
	nl_sock_mgr_logdbg("Resolved route : %s", found_route_val->to_str());
	is_resolved = true;
	
out:
	if(fd >= 0){
		orig_os_api.close(fd);
	}
	free_buffer(buf_ptr);
	
	return is_resolved;
}

int netlink_sock_mgr::create_nl_socket()
{
	int fd = -1;
	int buff_size = MSG_BUFFER_SIZE;

	BULLSEYE_EXCLUDE_BLOCK_START
	if ((fd = orig_os_api.socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		nl_sock_mgr_logerr("NL socket Creation, error = %d", errno);
		goto error;
	}

	if (orig_os_api.fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		nl_sock_mgr_logerr("NL socket Non-blocking, error = %d", errno);
		goto error;
	}
		
	if (orig_os_api.setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buff_size, sizeof(buff_size))) {
		nl_sock_mgr_logwarn("NL socket setsockopt SO_SNDBUF, error = %d", errno);
		goto error;
	}

   	if (orig_os_api.setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buff_size, sizeof(buff_size))) {
		nl_sock_mgr_logwarn("NL socket setsockopt SO_RCVBUF, error = %d", errno);
		goto error;
	}

	if (orig_os_api.fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		nl_sock_mgr_logwarn("NL socket fail in fctl, error = %d", errno);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	
	return fd;
	
	error:
	if(fd >= 0){
		orig_os_api.close(fd);
	}
	return -1;	
}

char* netlink_sock_mgr::reserve_buffer()
{	
	auto_unlocker lock(m_buff_pool_lock);
	
	char* buf_ptr;
	if(m_buffer_pool.size() > 0) {
		buf_ptr = m_buffer_pool.front();
		m_buffer_pool.pop();
	}
	else {
		buf_ptr = (char*) malloc(sizeof(char) * MSG_BUFFER_SIZE);
	}
	return buf_ptr;
}

void netlink_sock_mgr::build_route_get_request(route_lookup_key key, char* buf_ptr)
{
	struct nlmsghdr *nl_msg;
	struct rtmsg *rt_msg;
	memset(buf_ptr, 0, MSG_BUFFER_SIZE);

	// point the header and the msg structure pointers into the buffer
	nl_msg = (struct nlmsghdr *) buf_ptr;
	rt_msg = (struct rtmsg *)NLMSG_DATA(nl_msg);

	//Fill in the nlmsg header
	nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nl_msg->nlmsg_seq = 0;
	nl_msg->nlmsg_pid = m_pid;
	nl_msg->nlmsg_type = RTM_GETROUTE;
	nl_msg->nlmsg_flags = NLM_F_REQUEST;
	
	rt_msg->rtm_family = AF_INET;
	rt_msg->rtm_table = RT_TABLE_UNSPEC;

	in_addr_t dst_addr = key.get_dst_ip();
	if (dst_addr > 0) {
		fill_route_request_addr(RTA_DST, dst_addr, nl_msg);	
	}
	
	in_addr_t src_addr = key.get_src_ip();
	if (src_addr > 0) {
		fill_route_request_addr(RTA_SRC, src_addr, nl_msg);
	}
	
	uint32_t oif_index = key.get_oif_index();
	if (oif_index > 0) {
		size_t byte_len = sizeof(oif_index);
		int nl_len = RTA_LENGTH(byte_len);
		struct rtattr *rta;
		rta = NLMSG_TAIL(nl_msg);
		rta->rta_type = RTA_OIF;
		rta->rta_len = nl_len;
		memcpy(RTA_DATA(rta), &oif_index, byte_len);
		nl_msg->nlmsg_len = NLMSG_ALIGN(nl_msg->nlmsg_len) + nl_len;			
	}
}

void netlink_sock_mgr::fill_route_request_addr(int rta_type, in_addr_t addr, struct nlmsghdr *nl_msg)
{
	struct rtmsg *rt_msg;
	rt_msg = (struct rtmsg *)NLMSG_DATA(nl_msg);

	size_t addr_byte_len = sizeof(addr);
	int rta_len = RTA_LENGTH(addr_byte_len);
	
	struct rtattr *rta;
	rta = NLMSG_TAIL(nl_msg);
	rta->rta_type = rta_type;
	rta->rta_len = rta_len;
	memcpy(RTA_DATA(rta), &addr, addr_byte_len);
	nl_msg->nlmsg_len = NLMSG_ALIGN(nl_msg->nlmsg_len) + RTA_ALIGN(rta_len);
	if(RTA_DST) {
		rt_msg->rtm_dst_len = addr_byte_len * BITS_PER_BYTE;
	}
	else if (RTA_SRC) {
		rt_msg->rtm_src_len = addr_byte_len * BITS_PER_BYTE;
	}	
}

bool netlink_sock_mgr::send_request(int fd, struct nlmsghdr *nl_msg)
{
	struct sockaddr_nl addr;
	memset(&addr,0,sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	
	struct iovec iov;
	iov.iov_base = (void*) nl_msg;
	iov.iov_len = nl_msg->nlmsg_len;
	
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg)); 
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	BULLSEYE_EXCLUDE_BLOCK_START
	if(orig_os_api.sendmsg(fd, &msg, 0) < 0){
		nl_sock_mgr_logerr("Write To NL Socket Failed, error = %d", errno);
		return false;
	}
	
	return true;
}

int netlink_sock_mgr::recv_info(int fd, char* buf_ptr, long timeout_usec)
{
	struct timespec ts_timeout, ts_start;
	struct pollfd fds;	
	struct nlmsghdr *nlHdr = NULL;
	int readLen = 0, msgLen = 0;	
	struct sockaddr_nl addr;	
	struct iovec iov;
	struct msghdr msg;

	memset(buf_ptr, 0, MSG_BUFFER_SIZE);
	memset(&ts_timeout, 0, sizeof(struct timespec));
	memset(&ts_start, 0, sizeof(struct timespec));
	memset(&addr,0,sizeof(struct sockaddr_nl));
	memset(&msg, 0, sizeof(msg)); 	
	
	if (!init_timer(timeout_usec, &ts_timeout, &ts_start)) {
			return -1;
	}
	
	fds.fd = fd;
	fds.events = POLLIN;
	addr.nl_family = AF_NETLINK;
	iov.iov_base = (void*) buf_ptr;
	iov.iov_len = MSG_BUFFER_SIZE;
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;	
	do{
		BULLSEYE_EXCLUDE_BLOCK_START
		if(orig_os_api.ppoll(&fds, 1, (timeout_usec >= 0) ? &ts_timeout : NULL, NULL) < 0) {
			nl_sock_mgr_logerr("Failed to poll NL socket, error = %d", errno);
			return -1;
		}

		if((readLen = orig_os_api.recvmsg(fd, &msg, 0)) < 0){
			if (errno == EAGAIN) {
				continue;
			} else {
				nl_sock_mgr_logerr("Failed to recv NL socket, error = %d", errno);
				return -1;
			}
		}
		
		nlHdr = (struct nlmsghdr *) iov.iov_base;

		//Check if the header is valid
		if((NLMSG_OK(nlHdr, (u_int)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
			nl_sock_mgr_logerr("Error in received packet, readLen = %d, msgLen = %d, type=%d, bufLen = %d", readLen, nlHdr->nlmsg_len, nlHdr->nlmsg_type, MSG_BUFFER_SIZE);
			if (nlHdr->nlmsg_len == MSG_BUFFER_SIZE) {
				nl_sock_mgr_logerr("The buffer we pass to netlink is too small for reading the whole table");
			}
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		//Check if the its the last message
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		}
		else{
			iov.iov_base = (char*) iov.iov_base + readLen;
			iov.iov_len -= readLen;
			msgLen += readLen;
		}

		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
		
		if(!update_timer(timeout_usec, &ts_timeout, &ts_start)) {
			return -1;
		}
	} while((nlHdr->nlmsg_seq != 0) || (nlHdr->nlmsg_pid != m_pid));
	return msgLen;
}

bool netlink_sock_mgr::init_timer(long timeout_usec, struct timespec* ts_timeout, struct timespec* ts_start)
{
	if (timeout_usec >= 0) {
		ts_timeout->tv_sec = timeout_usec / USEC_PER_SEC;
		ts_timeout->tv_nsec = (timeout_usec % USEC_PER_SEC) * NSEC_PER_USEC;
		int ret = gettime(ts_start);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret) {
			nl_sock_mgr_logerr("gettime() returned with error (errno %d %m)", ret);
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}
	return true;
} 

bool netlink_sock_mgr::update_timer(long timeout_usec, struct timespec* ts_timeout, struct timespec* ts_start)
{
	int ret;
	struct timespec ts_now;

	if (timeout_usec >= 0) {
		ret = gettime(&ts_now);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (ret) {
			nl_sock_mgr_logerr("gettime() returned with error (errno %d %m)", ret);
			return false;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		ts_sub(&ts_now, ts_start, ts_start);
		ts_sub(ts_timeout, ts_start, ts_timeout);
		if (ts_to_usec(ts_timeout) < 0){
			nl_sock_mgr_logerr("Route resolve time-out", ret);
			return false;			
		}
		ts_start->tv_sec = ts_now.tv_sec;
		ts_start->tv_nsec = ts_now.tv_nsec;
	}
	return true;
}

bool netlink_sock_mgr::parse_route_entry(nlmsghdr *nl_header, route_val* p_route_val)
{
	struct rtmsg *rt_msg;
	// get route entry header
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_header);

	// we are not concerned about the local and default route table
	if (rt_msg->rtm_family != AF_INET)
		return false;

	p_route_val->set_protocol(rt_msg->rtm_protocol);
	p_route_val->set_scope(rt_msg->rtm_scope);
	p_route_val->set_type(rt_msg->rtm_type);
	p_route_val->set_tos(rt_msg->rtm_tos);
	p_route_val->set_table_id(rt_msg->rtm_table);
	p_route_val->set_dst_len(rt_msg->rtm_dst_len);
	p_route_val->set_src_len(rt_msg->rtm_src_len);
	p_route_val->set_flags(rt_msg->rtm_flags);

	struct rtattr *tb[RTA_MAX+1];
	fill_route_attr_tb(tb, RTA_MAX, (struct rtattr *) RTM_RTA(rt_msg), RTM_PAYLOAD(nl_header));

	for (int i = 1; i<= RTA_MAX; i++) {
		if(tb[i]) {
			parse_route_attr(tb[i], p_route_val);
		}
	}

	p_route_val->set_state(true);
	p_route_val->set_str();

	return true;
}

void netlink_sock_mgr::fill_route_attr_tb(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

void netlink_sock_mgr::parse_route_attr(struct rtattr *rt_attribute, route_val *p_val)
{
	switch (rt_attribute->rta_type) {
	case RTA_DST:
		p_val->set_dst_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// next hop IPv4 address
	case RTA_GATEWAY:
		p_val->set_gw(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	// unique ID associated with the network interface
	case RTA_OIF:
		p_val->set_oif_index(*(uint32_t *)RTA_DATA(rt_attribute));
		char oif_name[IFNAMSIZ];
		if_indextoname(p_val->get_oif_index(),oif_name);
		p_val->set_oif_name(oif_name);
		break;
	case RTA_IIF:
		p_val->set_iif_name((char *)RTA_DATA(rt_attribute));
		break;
	case RTA_SRC:
		p_val->set_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	case RTA_PREFSRC:
		p_val->set_pref_src_addr(*(in_addr_t *)RTA_DATA(rt_attribute));
		break;
	case RTA_PRIORITY:
		p_val->set_priority(*(uint32_t *)RTA_DATA(rt_attribute));
		break;		
	case RTA_FLOW:
		p_val->set_realms(*(uint32_t *)RTA_DATA(rt_attribute));
		break;
	case RTA_METRICS:
		struct rtattr *metrics[RTAX_MAX+1];
		fill_route_attr_tb(metrics, RTAX_MAX, (struct rtattr *) RTA_DATA(rt_attribute), RTA_PAYLOAD(rt_attribute));
		for (int i = 1; i <= RTAX_MAX; i++) {
			if(metrics[i]) {
				p_val->set_metric(i, *(uint32_t *)RTA_DATA(metrics[i]));
			}
		}
		break;
	case RTA_MULTIPATH:
		fill_nh(rt_attribute, p_val);
		break;		
	default:
		break;
	}
}

void netlink_sock_mgr::fill_nh(struct rtattr *rt_attribute, route_val *p_val)
{
	struct rtnexthop *nh = (struct rtnexthop *) RTA_DATA(rt_attribute);
	int len = RTA_PAYLOAD(rt_attribute);
	while(((unsigned int)len >= sizeof(*nh)) && (nh->rtnh_len <= len)) {
		if (nh->rtnh_len > sizeof(*nh)) {
			struct nh_info_t nh_info;
			nh_info.weight = nh->rtnh_hops + 1;				
			nh_info.flags = nh->rtnh_flags;
			nh_info.oif_index = nh->rtnh_ifindex;
			nh_info.gw = 0;
			nh_info.realm = 0;
			struct rtattr *tb[RTA_MAX+1];
			fill_route_attr_tb(tb, RTA_MAX, RTNH_DATA(nh), nh->rtnh_len - sizeof(*nh));
			if (tb[RTA_GATEWAY]) {
				nh_info.gw = *(uint32_t *)RTA_DATA(tb[RTA_GATEWAY]);
			}
			if (tb[RTA_FLOW]) {
				nh_info.realm = *(uint32_t *)RTA_DATA(tb[RTA_FLOW]);
			}
			p_val->add_nh(&nh_info);
		}
		len -= NLMSG_ALIGN(nh->rtnh_len);
		nh = RTNH_NEXT(nh);
	}
}

void netlink_sock_mgr::free_buffer(char* buf_ptr)
{	
	auto_unlocker lock(m_buff_pool_lock);
	
	if(buf_ptr) {
		m_buffer_pool.push(buf_ptr);
	}	
}
