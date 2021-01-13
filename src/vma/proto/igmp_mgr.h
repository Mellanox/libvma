/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

