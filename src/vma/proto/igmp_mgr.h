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


#include "vma/proto/igmp_handler.h"
#include <tr1/unordered_map>

#ifndef IGMP_MANAGER_H
#define IGMP_MANAGER_H


typedef std::tr1::unordered_map<igmp_key, igmp_handler *> igmp_hdlr_map_t;

class igmp_mgr : public lock_mutex
{
public:
				igmp_mgr() {};
				~igmp_mgr();
	void 			process_igmp_packet(struct iphdr* p_ip_h, in_addr_t local_if);

private:
	igmp_hdlr_map_t 	m_igmp_hash;
	igmp_handler* 		get_igmp_handler(const igmp_key &key, uint8_t igmp_code);
};

extern igmp_mgr *g_p_igmp_mgr;

#endif

