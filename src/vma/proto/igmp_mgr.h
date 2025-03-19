/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#include "vma/proto/igmp_handler.h"
#include <unordered_map>

#ifndef IGMP_MANAGER_H
#define IGMP_MANAGER_H


typedef std::unordered_map<igmp_key, igmp_handler *> igmp_hdlr_map_t;

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

