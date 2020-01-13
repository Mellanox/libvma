/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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
#include "ib_ctx_handler_collection.h"

#include "vma/ib/base/verbs_extra.h"
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

void check_flow_steering_log_num_mgm_entry_size()
{
	static bool checked_mlx4_steering = false;
	if (checked_mlx4_steering) {
		return;
	}

	checked_mlx4_steering = true;
	char flow_steering_val[4] = {0};
	if (priv_safe_try_read_file((const char*)FLOW_STEERING_MGM_ENTRY_SIZE_PARAM_FILE, flow_steering_val, sizeof(flow_steering_val)) == -1) {
		vlog_printf(VLOG_DEBUG, "Flow steering option for mlx4 driver does not exist in current OFED version\n");
	} else if (flow_steering_val[0] != '-' || (strtol(&flow_steering_val[1], NULL, 0) % 2) == 0) {
		char module_info[3] = {0};
		if (!run_and_retreive_system_command("modinfo mlx4_core > /dev/null 2>&1 ; echo $?",
				module_info, sizeof(module_info)) &&
				(strlen(module_info) > 0)) {
			if (module_info[0] == '0') {
				vlog_printf(VLOG_WARNING, "***************************************************************************************\n");
				vlog_printf(VLOG_WARNING, "* VMA will not operate properly while flow steering option is disabled                *\n");
				vlog_printf(VLOG_WARNING, "* In order to enable flow steering please restart your VMA applications after running *\n");
				vlog_printf(VLOG_WARNING, "* the following:                                                                      *\n");
				vlog_printf(VLOG_WARNING, "* For your information the following steps will restart your network interface        *\n");
				vlog_printf(VLOG_WARNING, "* 1. \"echo options mlx4_core log_num_mgm_entry_size=-1 > /etc/modprobe.d/mlnx.conf\"   *\n");
				vlog_printf(VLOG_WARNING, "* 2. Restart openibd or rdma service depending on your system configuration           *\n");
				vlog_printf(VLOG_WARNING, "* Read more about the Flow Steering support in the VMA's User Manual                  *\n");
				vlog_printf(VLOG_WARNING, "***************************************************************************************\n");
			} else {
				vlog_printf(VLOG_DEBUG, "***************************************************************************************\n");
				vlog_printf(VLOG_DEBUG, "* VMA will not operate properly while flow steering option is disabled                *\n");
				vlog_printf(VLOG_DEBUG, "* Read more about the Flow Steering support in the VMA's User Manual                  *\n");
				vlog_printf(VLOG_DEBUG, "***************************************************************************************\n");
			}
		}
	}
}

ib_ctx_handler_collection::ib_ctx_handler_collection()
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

void ib_ctx_handler_collection::update_tbl(const char *ifa_name)
{
	struct ibv_device **dev_list = NULL;
	ib_ctx_handler * p_ib_ctx_handler = NULL;
	int num_devices = 0;
	int i;

	ibchc_logdbg("Checking for offload capable IB devices...");

	dev_list = vma_ibv_get_device_list(&num_devices);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!dev_list) {
		ibchc_logerr("Failure in vma_ibv_get_device_list() (error=%d %m)", errno);
		ibchc_logerr("Please check rdma configuration");
		throw_vma_exception("No IB capable devices found!");
	}
	if (!num_devices) {
		vlog_levels_t _level = ifa_name ? VLOG_DEBUG : VLOG_ERROR; // Print an error only during initialization.
		vlog_printf(_level, "VMA does not detect IB capable devices\n");
		vlog_printf(_level, "No performance gain is expected in current configuration\n");
	}

	BULLSEYE_EXCLUDE_BLOCK_END

	for (i = 0; i < num_devices; i++) {
		struct ib_ctx_handler::ib_ctx_handler_desc desc = {dev_list[i]};

		/* 2. Skip existing devices (compare by name) */
		if (ifa_name && !check_device_name_ib_name(ifa_name, dev_list[i]->name)) {
			continue;
		}

		if (ib_ctx_handler::is_mlx4(dev_list[i]->name)) {
			// Note: mlx4 does not support this capability.
			if(safe_mce_sys().enable_socketxtreme) {
				ibchc_logdbg("Blocking offload: mlx4 interfaces in socketxtreme mode");
				continue;
			}

			// Check if mlx4 steering creation is supported.
			check_flow_steering_log_num_mgm_entry_size();
		}

		/* 3. Add new ib devices */
		p_ib_ctx_handler = new ib_ctx_handler(&desc);
		if (!p_ib_ctx_handler) {
			ibchc_logerr("failed allocating new ib_ctx_handler (errno=%d %m)", errno);
			continue;
		}
		m_ib_ctx_map[p_ib_ctx_handler->get_ibv_device()] = p_ib_ctx_handler;
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
	char active_slave[IFNAMSIZ] = {0};
	unsigned int slave_flags = 0;
	ib_context_map_t::iterator ib_ctx_iter;

	if (check_netvsc_device_exist(ifa_name)) {
		if (!get_netvsc_slave(ifa_name, active_slave, slave_flags)) {
			return NULL;
		}
		ifa_name = (const char *)active_slave;
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
		if (check_device_name_ib_name(ifa_name, ib_ctx_iter->second->get_ibname())) {
			return ib_ctx_iter->second;
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
