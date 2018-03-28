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

	dev_list = ibv_get_device_list(&num_devices);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!dev_list) {
		ibchc_logwarn("Failure in ibv_get_device_list() (error=%d %m)", errno);
		ibchc_logwarn("Please check OFED installation");
		throw_vma_exception("No IB capable devices found!");
	}
	if (!num_devices) {
		ibchc_logdbg("No IB capable devices found!");
		throw_vma_exception("No IB capable devices found!");
	}

	BULLSEYE_EXCLUDE_BLOCK_END

	ibchc_logdbg("Checking for offload capable IB devices...");

	/* Get common time conversion mode for all devices */
	m_ctx_time_conversion_mode = time_converter::get_devices_converter_status(dev_list, num_devices);
	ibchc_logdbg("TS converter status was set to %d", m_ctx_time_conversion_mode);

	for (i = 0; i < num_devices; i++) {
		p_ib_ctx_handler = new ib_ctx_handler(dev_list[i], m_ctx_time_conversion_mode);
		if (!p_ib_ctx_handler) {
			ibchc_logerr("failed allocating new ib_ctx_handler (errno=%d %m)", errno);
			continue;
		}
		m_ib_ctx_map[p_ib_ctx_handler->get_ibv_context()] = p_ib_ctx_handler;
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

ib_ctx_handler* ib_ctx_handler_collection::get_ib_ctx(struct ibv_context* p_ibv_context)
{
	if (m_ib_ctx_map.count(p_ibv_context) > 0)
		return m_ib_ctx_map[p_ibv_context];
	return NULL;
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
		if (!get_bond_active_slave_name(ifa_name, active_slave, sizeof(active_slave))) {
			return NULL;
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
