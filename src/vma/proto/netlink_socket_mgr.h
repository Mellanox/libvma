/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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


#ifndef NETLINK_SOCKET_MGR_H
#define NETLINK_SOCKET_MGR_H

#include <cstddef>
#include <unistd.h>
#include <bits/sockaddr.h>
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
#include <fcntl.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#include <netlink/route/link.h>

#include "utils/bullseye.h"
#include "utils/lock_wrapper.h"
#include "vlogger/vlogger.h"
#include "vma/util/if.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/netlink_event.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "vma/sock/socket_fd_api.h"
#include "vma/sock/sock-redirect.h"


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

	virtual bool parse_entry(struct nl_object *nl_obj, void *p_val_context) = 0;
	virtual void update_tbl();
	virtual void print_val_tbl();
	
	void	build_request(struct nlmsghdr **nl_msg);
	bool	query(struct nlmsghdr *&nl_msg, int &len);
	int	recv_info();
	void	parse_tbl_from_latest_cache(struct nl_cache *cache_state);
	
private:
	nl_data_t	m_data_type;

	nl_sock 	*m_sock; // netlink socket to communicate with the kernel
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
	m_sock = nl_socket_alloc();
	if (m_sock == nullptr) {
		__log_err("NL socket Creation: ");
		return;
	}

	if (nl_connect(m_sock, NETLINK_ROUTE) < 0) {
		__log_err("NL socket Connection: ");
		nl_socket_free(m_sock);
		m_sock = nullptr;
		return;
	}

	BULLSEYE_EXCLUDE_BLOCK_END

	__log_dbg("Done");
}

template <typename Type>
netlink_socket_mgr <Type>::~netlink_socket_mgr()
{
	__log_dbg("");
	if (m_sock != nullptr) {
		nl_socket_free(m_sock);
		m_sock = nullptr;
	}

	__log_dbg("Done");
}

// Update data in a table
template <typename Type>
void netlink_socket_mgr <Type>::update_tbl()
{
	m_tab.entries_num = 0;

	struct nl_cache *cache_state = nullptr;
	int err = 0;

	// cache allocation fetches the latest existing rules/routes
	if (m_data_type == RULE_DATA_TYPE) {
		err = rtnl_rule_alloc_cache(m_sock, AF_INET, &cache_state);
	} else if (m_data_type == ROUTE_DATA_TYPE) {
		err = rtnl_route_alloc_cache(m_sock, AF_INET, 0, &cache_state);
	}

	if (err < 0) {
		if (cache_state) {
			nl_cache_free(cache_state);
		}
		
		throw_vma_exception("Failed to allocate route cache");
	}

	// Parse received data in custom object (route_val)
	parse_tbl_from_latest_cache(cache_state);

	if (cache_state) {
			nl_cache_free(cache_state);
	}
}

// Parse received data in a table
// Parameters:
//		len				: length of received data.
//		p_ent_num		: number of rows in received data.
template <typename Type>
void netlink_socket_mgr<Type>::parse_tbl_from_latest_cache(struct nl_cache *cache_state)
{
	uint16_t entry_cnt = 0;

	struct nl_iterator_context {
		Type *p_val_array;
		uint16_t &entry_cnt;
		netlink_socket_mgr<Type> *this_ptr;
	} iterator_context = {m_tab.value, entry_cnt, this};

	// a lambda can't be casted to a c-fptr with ref captures - so we provide context ourselves
	nl_cache_foreach(
		cache_state,
		[](struct nl_object *nl_obj, void *context) {
			nl_iterator_context *operation_context =
				reinterpret_cast<nl_iterator_context *>(context);
			const bool is_valid_entry = operation_context->this_ptr->parse_entry(
				nl_obj, operation_context->p_val_array + operation_context->entry_cnt);
			if (is_valid_entry) {
				++operation_context->entry_cnt;
			}
		},
		&iterator_context);

	m_tab.entries_num = entry_cnt;
	if (m_tab.entries_num >= MAX_TABLE_SIZE) {
		__log_warn("reached the maximum route table size");
	}
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
