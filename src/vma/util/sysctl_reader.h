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


#ifndef SYSCNTL_READER_H_
#define SYSCNTL_READER_H_

#include "vlogger/vlogger.h"
#include "utils.h"

struct sysctl_tcp_mem {
	int min_value;
	int default_value;
	int max_value;
};

class sysctl_reader_t {

private:

	int sysctl_read(const char* path, int argument_num ,const char *format, ...){

		FILE* pfile = fopen (path, "r");
		int ans;

		if (pfile == NULL) {
			return -1;
		}

		va_list arg;
		va_start (arg, format);
		ans = vfscanf(pfile, format, arg);
		va_end (arg);

		if (ans != argument_num) {
			return -1;
		}

		return 0;
	}

	void init(){
	}

	sysctl_reader_t() {
		this->init();
		this->update_all();
	}

public :

	static sysctl_reader_t & instance() {
		static sysctl_reader_t the_instance;
		return the_instance;
	}

	void update_all(){

		get_tcp_max_syn_backlog(true);
		get_listen_maxconn(true);
		get_tcp_wmem(true);
		get_tcp_rmem(true);
		get_tcp_window_scaling(true);
		get_net_core_rmem_max(true);
		get_net_core_wmem_max(true);
	}

	int get_tcp_max_syn_backlog(bool update = false) {
		static int val;
		if (update)
			val = read_file_to_int("/proc/sys/net/ipv4/tcp_max_syn_backlog", 1024);
		return val;
	}

	int get_listen_maxconn(bool update = false) {
		static int val;
		if (update)
			val = read_file_to_int("/proc/sys/net/core/somaxconn", SOMAXCONN);
		return val;
	}

	const sysctl_tcp_mem *get_tcp_wmem(bool update = false) {
		static sysctl_tcp_mem tcp_mem;
		if (update) {
			if (sysctl_read("/proc/sys/net/ipv4/tcp_wmem", 3, "%d %d %d", &tcp_mem.min_value, &tcp_mem.default_value, &tcp_mem.max_value) == -1) {
				tcp_mem.min_value = 4096;
				tcp_mem.default_value = 16384;
				tcp_mem.max_value = 4194304;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.ipv4.tcp_wmem values - Using defaults : %d %d %d\n", tcp_mem.min_value, tcp_mem.default_value, tcp_mem.max_value);
			}
		}
		return &tcp_mem;
	}

	const sysctl_tcp_mem *get_tcp_rmem(bool update = false) {
		static sysctl_tcp_mem tcp_mem;
		if (update) {
			if (sysctl_read("/proc/sys/net/ipv4/tcp_rmem", 3, "%d %d %d", &tcp_mem.min_value, &tcp_mem.default_value, &tcp_mem.max_value) == -1) {
				// defaults were taken based on man (7) tcp
				tcp_mem.min_value = 4096;
				tcp_mem.default_value = 87380;
				tcp_mem.max_value = 4194304;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.ipv4.tcp_rmem values - Using defaults : %d %d %d\n", tcp_mem.min_value, tcp_mem.default_value, tcp_mem.max_value);
			}
		}
		return &tcp_mem;
	}

	int get_tcp_window_scaling(bool update = false) {
		static int val;
		if (update)
			val = read_file_to_int("/proc/sys/net/ipv4/tcp_window_scaling", 0);
		return val;
	}

	int get_net_core_rmem_max(bool update = false) {
		static int val;
		if (update)
			val = read_file_to_int("/proc/sys/net/core/rmem_max", 229376);
		return val;
	}

	int get_net_core_wmem_max(bool update = false) {
		static int val;
		if (update)
			val = read_file_to_int("/proc/sys/net/core/wmem_max", 229376);
		return val;
	}
};

#endif /* SYSCNTL_READER_H_ */
