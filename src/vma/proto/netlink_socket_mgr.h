/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef NETLINK_SOCKET_MGR_H
#define NETLINK_SOCKET_MGR_H

#include <unistd.h>
#include <bits/sockaddr.h>
#include <tr1/unordered_map>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "vlogger/vlogger.h"
#include "vma/util/vtypes.h"
#include "vma/util/lock_wrapper.h"
#include "vma/util/utils.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"
#include "vma/util/bullseye.h"


#ifndef MODULE_NAME
#define MODULE_NAME	"netlink_socket_mgr:"
#endif

#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((uint8_t *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define MAX_TABLE_SIZE 4096
#define MSG_BUFF_SIZE 81920

// This enum specify the type of data to be retrieve using netlink socket.
enum nl_data_t
{
	RULE_DATA_TYPE,
	ROUTE_DATA_TYPE
};

/*
* This class manage retrieving data (Rule, Route) from kernel using netlink socket.
*/
template <typename Type>
class netlink_socket_mgr 
{
public:
	netlink_socket_mgr(nl_data_t data_type);
	virtual ~netlink_socket_mgr();

protected:	
	typedef struct
	{
		Type 		value[MAX_TABLE_SIZE];
		uint16_t	entries_num;
	} table_t;

	table_t m_tab;

	virtual bool parse_enrty(nlmsghdr *nl_header, Type *p_val) = 0;
	virtual void update_tbl();
	virtual void print_val_tbl();
	
	void	build_request(struct nlmsghdr **nl_msg);
	bool	query(struct nlmsghdr *&nl_msg, int &len);
	int	recv_info();
	void	parse_tbl(int len, int *p_ent_num = NULL);
	
private:
	nl_data_t	m_data_type;

	int 		m_fd; // netlink socket to communicate with the kernel
	uint32_t 	m_pid; // process pid
	uint32_t 	m_seq_num; // seq num of the netlink messages
	char 		m_msg_buf[MSG_BUFF_SIZE]; // we use this buffer for sending/receiving netlink messages
	uint32_t 	m_buff_size;
};

/*********************************Implementation ********************************/

template <typename Type>
netlink_socket_mgr <Type>::netlink_socket_mgr(nl_data_t data_type)
{
	__log_dbg("");

	m_data_type = data_type;
	m_pid = getpid();
	m_buff_size = MSG_BUFF_SIZE;
	m_seq_num = 0;

	memset(m_msg_buf, 0, m_buff_size);

	// Create Socket
	BULLSEYE_EXCLUDE_BLOCK_START
	if ((m_fd = orig_os_api.socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		__log_err("NL socket Creation: ");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	__log_dbg("Done");
}

template <typename Type>
netlink_socket_mgr <Type>::~netlink_socket_mgr()
{
	__log_dbg("");
	if (m_fd) {
		orig_os_api.close(m_fd);
		m_fd = -1;
	}
	
	__log_dbg("Done");
}

// This function build Netlink request to retrieve data (Rule, Route) from kernel.
// Parameters : 
//		nl_msg	: request to be returned  
template <typename Type>
void netlink_socket_mgr <Type>::build_request(struct nlmsghdr **nl_msg)
{
	struct rtmsg *rt_msg;

	memset(m_msg_buf, 0, m_buff_size);

	// point the header and the msg structure pointers into the buffer
	*nl_msg = (struct nlmsghdr *)m_msg_buf;
	rt_msg = (struct rtmsg *)NLMSG_DATA(*nl_msg);

	//Fill in the nlmsg header
	(*nl_msg)->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	(*nl_msg)->nlmsg_seq = m_seq_num++;
	(*nl_msg)->nlmsg_pid = m_pid;
	rt_msg->rtm_family = AF_INET;

	if (m_data_type == RULE_DATA_TYPE)
	{
		(*nl_msg)->nlmsg_type = RTM_GETRULE;
	}
	else if (m_data_type == ROUTE_DATA_TYPE)
	{
		(*nl_msg)->nlmsg_type = RTM_GETROUTE;
	}
	
	(*nl_msg)->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

}

// Query built request and receive requested data (Rule, Route)
// Parameters: 
//		nl_msg	: request that is built previously.
//		len		: length of received data.
template <typename Type>
bool netlink_socket_mgr <Type>::query(struct nlmsghdr *&nl_msg, int &len)
{
	if(m_fd < 0)
		return false;

	BULLSEYE_EXCLUDE_BLOCK_START
	if(orig_os_api.send(m_fd, nl_msg, nl_msg->nlmsg_len, 0) < 0){
		__log_err("Write To Socket Failed...\n");
		return false;
	}
	if((len = recv_info()) < 0) {
		__log_err("Read From Socket Failed...\n");
		return false;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	return true;
}

// Receive requested data and save it locally.
// Return length of received data. 
template <typename Type>
int netlink_socket_mgr <Type>::recv_info()
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	char *buf_ptr = m_msg_buf;

	do{
		//Receive response from the kernel
		BULLSEYE_EXCLUDE_BLOCK_START
		if((readLen = orig_os_api.recv(m_fd, buf_ptr, MSG_BUFF_SIZE - msgLen, 0)) < 0){
			__log_err("SOCK READ: ");
			return -1;
		}

		nlHdr = (struct nlmsghdr *)buf_ptr;

		//Check if the header is valid
		if((NLMSG_OK(nlHdr, (u_int)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
			__log_err("Error in received packet, readLen = %d, msgLen = %d, type=%d, bufLen = %d", readLen, nlHdr->nlmsg_len, nlHdr->nlmsg_type, MSG_BUFF_SIZE);
			if (nlHdr->nlmsg_len == MSG_BUFF_SIZE) {
				__log_err("The buffer we pass to netlink is too small for reading the whole table");
			}
			return -1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		//Check if the its the last message
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		}
		else{
			buf_ptr += readLen;
			msgLen += readLen;
		}

		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			break;
		}
	} while((nlHdr->nlmsg_seq != m_seq_num) || (nlHdr->nlmsg_pid != m_pid));
	return msgLen;
}

// Update data in a table
template <typename Type>
void netlink_socket_mgr <Type>::update_tbl()
{
	struct nlmsghdr *nl_msg = NULL;
	int counter = 0;
	int len = 0;

	m_tab.entries_num = 0;

	// Build Netlink request to get route entry
	build_request(&nl_msg);

	// Query built request and receive requested data
	if (!query(nl_msg, len))
		return;

	// Parse received data in custom object (route_val)
	parse_tbl(len, &counter);

	m_tab.entries_num = counter;

	if (counter >= MAX_TABLE_SIZE) {
		__log_warn("reached the maximum route table size");
	}
}

// Parse received data in a table
// Parameters: 
//		len				: length of received data.
//		p_ent_num		: number of rows in received data.
template <typename Type>
void netlink_socket_mgr <Type>::parse_tbl(int len, int *p_ent_num)
{
	struct nlmsghdr *nl_header;
	int entry_cnt = 0;

	nl_header = (struct nlmsghdr *) m_msg_buf;
	for(;NLMSG_OK(nl_header, (u_int)len) && entry_cnt < MAX_TABLE_SIZE; nl_header = NLMSG_NEXT(nl_header, len))
	{
		if (parse_enrty(nl_header, &m_tab.value[entry_cnt])) {
			entry_cnt++;
		}
	}
	if (p_ent_num)
		*p_ent_num = entry_cnt;
}

//print the table
template <typename Type>
void netlink_socket_mgr <Type>::print_val_tbl()
{
	Type *p_val;
	for (int i = 0; i < m_tab.entries_num; i++)
	{
		p_val = &m_tab.value[i];
		p_val->print_val();
	}
}

#undef MODULE_NAME

#endif /* NETLINK_SOCKET_MGR_H */
