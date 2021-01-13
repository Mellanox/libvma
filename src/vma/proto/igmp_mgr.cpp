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


#include <errno.h>
#include <arpa/inet.h>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "igmp_mgr.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/dev/net_device_val.h"



#define MODULE_NAME 		"igmp_mgr"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME "[%s]:%d:%s() "

#undef	__INFO__
#define __INFO__		""

#define igmp_mgr_logpanic		__log_info_panic
#define igmp_mgr_logerr			__log_info_err
#define igmp_mgr_logwarn		__log_info_warn
#define igmp_mgr_loginfo		__log_info_info
#define igmp_mgr_logdbg			__log_info_dbg
#define igmp_mgr_logfunc		__log_info_func
#define igmp_mgr_logfuncall		__log_info_funcall


igmp_mgr *g_p_igmp_mgr = NULL;

igmp_mgr::~igmp_mgr()
{
	igmp_handler* p_igmp_hdlr = NULL;
	igmp_hdlr_map_t::iterator iter = m_igmp_hash.begin();
	while (iter != m_igmp_hash.end()) {
		p_igmp_hdlr = iter->second;
		igmp_mgr_logdbg("Delete existing igmp handler '%s'", p_igmp_hdlr->to_str().c_str());
		m_igmp_hash.erase(iter);
		p_igmp_hdlr->clean_obj();
		p_igmp_hdlr = NULL;
		iter = m_igmp_hash.begin();
	}
}

void igmp_mgr::process_igmp_packet(struct iphdr* p_ip_h, in_addr_t local_if)
{
	igmp_mgr_logfunc("");
	igmp_handler* p_igmp_hdlr = NULL;
	uint16_t ip_h_hdr_len = (int)(p_ip_h->ihl)*4;
	struct igmphdr* p_igmp_h = (struct igmphdr*)(((uint8_t*)p_ip_h) + ip_h_hdr_len);

	net_device_val* p_ndvl = g_p_net_device_table_mgr->get_net_device_val(local_if);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!p_ndvl){
		igmp_mgr_logerr("Failed getting relevant net device");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	igmp_key key(ip_address(p_igmp_h->group), p_ndvl);
	p_igmp_hdlr = get_igmp_handler(key, p_igmp_h->code);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!p_igmp_hdlr){
		igmp_mgr_logerr("Failed getting relevant igmp_handler");
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	switch (p_igmp_h->type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		p_igmp_hdlr->handle_query(p_igmp_h->code);
		break;

	case IGMP_HOST_MEMBERSHIP_REPORT:
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		p_igmp_hdlr->handle_report();
		break;

	default:
		break;
	}
}

igmp_handler* igmp_mgr::get_igmp_handler(const igmp_key &key, uint8_t igmp_code)
{
	igmp_handler *p_igmp_hdlr = NULL;

	lock();
	igmp_hdlr_map_t::iterator iter = m_igmp_hash.find(key);
	if (iter != m_igmp_hash.end()) {
		p_igmp_hdlr = iter->second;
		igmp_mgr_logdbg("Found existing igmp handler '%s'", p_igmp_hdlr->to_str().c_str());
	}
	else {
		p_igmp_hdlr = new igmp_handler(key, igmp_code);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!p_igmp_hdlr) {
			igmp_mgr_logerr("Failed allocating new igmp handler for mc_address = %d.%d.%d.%d, local_if= %d.%d.%d.%d",
						NIPQUAD(key.get_in_addr()), NIPQUAD(key.get_net_device_val()->get_local_addr()));
			unlock();
			return p_igmp_hdlr;
		}
		if (!p_igmp_hdlr->init(key)) {
			igmp_mgr_logerr("Failed to initialize new igmp handler '%s'", p_igmp_hdlr->to_str().c_str());
			delete(p_igmp_hdlr);
			p_igmp_hdlr = NULL;
			unlock();
			return p_igmp_hdlr;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		m_igmp_hash.insert(igmp_hdlr_map_t::value_type(key, p_igmp_hdlr));
		igmp_mgr_logdbg("Created new igmp handler '%s'", p_igmp_hdlr->to_str().c_str());
	}
	unlock();
	return p_igmp_hdlr;
}

