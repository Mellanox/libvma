/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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

#include <vector>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/util/verbs_extra.h"
#include "ib_ctx_handler_collection.h"
#include "vma/util/utils.h"
#include "vma/event/event_handler_manager.h"

#define MODULE_NAME             "ib_ctx_collection"


#define ibchc_logpanic           __log_panic
#define ibchc_logerr             __log_err
#define ibchc_logwarn            __log_warn
#define ibchc_loginfo            __log_info
#define ibchc_logdbg             __log_info_dbg
#define ibchc_logfunc            __log_info_func
#define ibchc_logfuncall         __log_info_funcall

ib_ctx_handler_collection* g_p_ib_ctx_handler_collection = NULL;

ib_ctx_handler_collection::ib_ctx_handler_collection() :
		m_ctx_time_conversion_mode(TS_CONVERSION_MODE_DISABLE)
{
	ibchc_logdbg("");

	/* Read ib table from kernel and save it in local variable. */
	update_tbl();

	//Print table
	print_val_tbl();

	ibchc_logdbg("Done");
}

ib_ctx_handler_collection::~ib_ctx_handler_collection()
{
	ibchc_logdbg("");

	ib_context_map_t::iterator ib_ctx_iter;
	while ((ib_ctx_iter = m_ib_ctx_map.begin()) != m_ib_ctx_map.end()) {
		ib_ctx_handler* p_ib_ctx_handler = ib_ctx_iter->second;
		delete p_ib_ctx_handler;
		m_ib_ctx_map.erase(ib_ctx_iter);
	}

	ibchc_logdbg("Done");
}

void ib_ctx_handler_collection::update_tbl()
{
	struct ibv_device **dev_list = NULL;
	ib_ctx_handler * p_ib_ctx_handler = NULL;
	int num_devices = 0;
	int i;
	std::vector<struct ibv_device*> cache_objs;

	dev_list = vma_ibv_get_device_list(&num_devices);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!dev_list) {
		ibchc_logwarn("Failure in vma_ibv_get_device_list() (error=%d %m)", errno);
		ibchc_logwarn("Please check OFED installation");
		throw_vma_exception("No IB capable devices found!");
	}
	if (!num_devices) {
		ibchc_logdbg("*************************************************************");
		ibchc_logdbg("* VMA does not detect IB capable devices                    *");
		ibchc_logdbg("* No performance gain is expected in current configuration  *");
		ibchc_logdbg("*************************************************************");
	}

	BULLSEYE_EXCLUDE_BLOCK_END

	ibchc_logdbg("Checking for offload capable IB devices...");

	/* Get common time conversion mode for all devices */
	m_ctx_time_conversion_mode = time_converter::get_devices_converter_status(dev_list, num_devices);
	ibchc_logdbg("TS converter status was set to %d", m_ctx_time_conversion_mode);


	/* update_tbl() function is implemented to support removing unused(removed)
	 * ib devices in case plugout scenario and adding new devices during
	 * plugin flow.
	 * Algorithm:
	 * 1. save current ib elements in cache_objs before processing device list returned by netlink
	 * 2. remove from cache_objs record about elements that exist in netlink respond
	 * 3. add ib that is not found in cache_objs during processing netlink information
	 * 4. remove all ib elements that remain in cache_objs on final stage
	 */
	/* 1. Initialize cache */
	{
		ib_context_map_t::iterator iter;
		cache_objs.reserve(m_ib_ctx_map.size());
		for (iter = m_ib_ctx_map.begin(); iter != m_ib_ctx_map.end(); iter++) {
			cache_objs.push_back(iter->first);
		}
	}

	for (i = 0; i < num_devices; i++) {
		struct ib_ctx_handler::ib_ctx_handler_desc desc = {dev_list[i], m_ctx_time_conversion_mode};

		/* 2. Skip existing devices (compare by name) */
		ib_context_map_t::iterator ib_ctx_itr;
		for (ib_ctx_itr = m_ib_ctx_map.begin(); ib_ctx_itr != m_ib_ctx_map.end(); ib_ctx_itr++) {
			if (strcmp(dev_list[i]->name, ib_ctx_itr->first->name) == 0) {
				std::vector<struct ibv_device*>::iterator cache_iter;
				while ((cache_iter = cache_objs.begin()) != cache_objs.end()) {
					if (strcmp(dev_list[i]->name, (*cache_iter)->name) == 0) {
						cache_objs.erase(cache_iter);
						break;
					}
				}
				goto next;
			}
		}

#ifdef DEFINED_SOCKETXTREME
		// only support mlx5 device in this mode
		if(strncmp(dev_list[i]->name, "mlx4", 4) == 0) {
			ibchc_logdbg("Blocking offload: mlx4 interfaces in socketxtreme mode");
			continue;
		}
#endif // DEFINED_SOCKETXTREME
		/* 3. Add new ib devices */
		p_ib_ctx_handler = new ib_ctx_handler(&desc);
		if (!p_ib_ctx_handler) {
			ibchc_logerr("failed allocating new ib_ctx_handler (errno=%d %m)", errno);
			continue;
		}
		m_ib_ctx_map[p_ib_ctx_handler->get_ibv_device()] = p_ib_ctx_handler;

next:
		continue;
	}

	/* 4. Cleanup devices that are not found after update */
	std::vector<struct ibv_device*>::iterator cache_iter;
	while ((cache_iter = cache_objs.begin()) != cache_objs.end()) {
		ib_context_map_t::iterator dev_iter = m_ib_ctx_map.find(*cache_iter);
		if (dev_iter != m_ib_ctx_map.end()) {
			delete dev_iter->second;
			m_ib_ctx_map.erase(dev_iter);
			cache_objs.erase(cache_iter);
		}
	}

	ibchc_logdbg("Check completed. Found %d offload capable IB devices", m_ib_ctx_map.size());

	if (dev_list) {
		ibv_free_device_list(dev_list);
	}
}

void ib_ctx_handler_collection::print_val_tbl()
{
	ib_context_map_t::iterator itr;
	for (itr = m_ib_ctx_map.begin(); itr != m_ib_ctx_map.end(); itr++) {
		ib_ctx_handler* p_ib_ctx_handler = itr->second;
		p_ib_ctx_handler->print_val();
	}
}

ib_ctx_handler* ib_ctx_handler_collection::get_ib_ctx(const char *ifa_name)
{
	struct ifaddrs slave;
	char active_slave[IFNAMSIZ] = {0};
	ib_context_map_t::iterator ib_ctx_iter;

	if (check_netvsc_device_exist(ifa_name)) {
		if (!get_netvsc_slave(ifa_name, &slave)) {
			return NULL;
		}
		ifa_name = (const char *)slave.ifa_name;
	} else if (check_device_exist(ifa_name, BOND_DEVICE_FILE)) {
		/* active/backup: return active slave */
		if (!get_bond_active_slave_name(ifa_name, active_slave, sizeof(active_slave))) {
			char slaves[IFNAMSIZ * 16] = {0};
			char* slave_name;
			char* save_ptr;

			/* active/active: return the first slave */
			if (!get_bond_slaves_name_list(ifa_name, slaves, sizeof(slaves))) {
				return NULL;
			}
			slave_name = strtok_r(slaves, " ", &save_ptr);
			if (NULL == slave_name) {
				return NULL;
			}
			save_ptr = strchr(slave_name, '\n');
			if (save_ptr) *save_ptr = '\0'; // Remove the tailing 'new line" char
			strncpy(active_slave, slave_name, sizeof(active_slave) - 1);
		}
		ifa_name = (const char *)active_slave;
	}

	for (ib_ctx_iter = m_ib_ctx_map.begin(); ib_ctx_iter != m_ib_ctx_map.end(); ib_ctx_iter++) {
		int n = -1;
		int fd = -1;
		char ib_path[IBV_SYSFS_PATH_MAX]= {0};

		n = snprintf(ib_path, sizeof(ib_path), "/sys/class/infiniband/%s/device/net/%s/ifindex",
				ib_ctx_iter->second->get_ibname(), ifa_name);
		if (likely((0 < n) && (n < (int)sizeof(ib_path)))) {
			fd = open(ib_path, O_RDONLY);
			if (fd >= 0) {
				close(fd);
				return ib_ctx_iter->second;
			}
		}
	}

	return NULL;
}

void ib_ctx_handler_collection::del_ib_ctx(ib_ctx_handler* ib_ctx)
{
	if (ib_ctx) {
		ib_context_map_t::iterator ib_ctx_iter = m_ib_ctx_map.find(ib_ctx->get_ibv_device());
		if (ib_ctx_iter != m_ib_ctx_map.end()) {
			delete ib_ctx_iter->second;
			m_ib_ctx_map.erase(ib_ctx_iter);
		}
	}
}
