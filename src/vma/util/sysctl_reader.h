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

#define SYSCTL_INT_FORMAT 						"%d"
#define SYSCTL_3_INT_FORMAT 					"%d %d %d"

#define SYSCTL_TCP_RMEM_MIN_DEFAULT				4096
#define SYSCTL_TCP_RMEM_DEFAULT_DEFAULT			87380
#define SYSCTL_TCP_RMEM_MAX_DEFAULT				4194304
#define SYSCTL_TCP_RMEM_PATH 					"/proc/sys/net/ipv4/tcp_rmem"
#define SYSCTL_TCP_RMEM_FORMAT 					SYSCTL_3_INT_FORMAT

#define SYSCTL_TCP_WMEM_MIN_DEFAULT				4096
#define SYSCTL_TCP_WMEM_DEFAULT_DEFAULT			16384
#define SYSCTL_TCP_WMEM_MAX_DEFAULT				4194304
#define SYSCTL_TCP_WMEM_PATH 					"/proc/sys/net/ipv4/tcp_wmem"
#define SYSCTL_TCP_WMEM_FORMAT 					SYSCTL_3_INT_FORMAT

#define SYSCTL_WINDOW_SCALING_DEFAULT			0
#define SYSCTL_WINDOW_SCALING_PATH 				"/proc/sys/net/ipv4/tcp_window_scaling"
#define SYSCTL_WINDOW_SCALING_FORMAT 			SYSCTL_INT_FORMAT

#define SYSCTL_NET_CORE_RMEM_MAX_DEFAULT		229376
#define SYSCTL_NET_CORE_RMEM_MAX_PATH			"/proc/sys/net/core/rmem_max"
#define SYSCTL_NET_CORE_RMEM_MAX_FORMAT			SYSCTL_INT_FORMAT

#define SYSCTL_NET_CORE_WMEM_MAX_DEFAULT		229376
#define SYSCTL_NET_CORE_WMEM_MAX_PATH			"/proc/sys/net/core/wmem_max"
#define SYSCTL_NET_CORE_WMEM_MAX_FORMAT			SYSCTL_INT_FORMAT

struct sysctl_tcp_mem {
	int min_value;
	int default_value;
	int max_value;
};

typedef enum {
	SYSCTL_ENUM_TYPE_START, // SYSCTL_ENUM_TYPE_START must be the first ENUM
	SYSCTL_NET_TCP_RMEM,
	SYSCTL_NET_TCP_WMEM,
	SYSCTL_WINDOW_SCALING,
	SYSCTL_NET_CORE_RMEM_MAX,
	SYSCTL_NET_CORE_WMEM_MAX,
	SYSCTL_ENUM_TYPE_END // SYSCTL_ENUM_TYPE_END must be the last ENUM
} sysctl_var_enum;


class sysctl_reader_t {

private:

	sysctl_tcp_mem tcp_rmem;
	sysctl_tcp_mem tcp_wmem;
	int tcp_window_scaling;
	int net_core_rmem_max;
	int net_core_wmem_max;

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

public :

	sysctl_reader_t(){

		memset(&tcp_rmem, 0 , sizeof(tcp_rmem));
		memset(&tcp_wmem, 0 , sizeof(tcp_wmem));
		memset(&tcp_window_scaling, 0, sizeof(tcp_window_scaling));
		memset(&net_core_rmem_max, 0, sizeof(net_core_rmem_max));
		memset(&net_core_wmem_max, 0, sizeof(net_core_wmem_max));

		this->update_all();
	}

	int update(sysctl_var_enum requested_var) {

		switch(requested_var) {
		case SYSCTL_NET_TCP_RMEM:

			if (sysctl_read(SYSCTL_TCP_RMEM_PATH, 3, SYSCTL_TCP_RMEM_FORMAT, &tcp_rmem.min_value, &tcp_rmem.default_value, &tcp_rmem.max_value) == -1) {
				tcp_rmem.min_value = SYSCTL_TCP_RMEM_MIN_DEFAULT;
				tcp_rmem.default_value = SYSCTL_TCP_RMEM_DEFAULT_DEFAULT;
				tcp_rmem.max_value = SYSCTL_TCP_RMEM_MAX_DEFAULT;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.ipv4.tcp_rmem values - Using defaults : %d %d %d\n", tcp_rmem.min_value, tcp_rmem.default_value, tcp_rmem.max_value);
				return -1;
			}

			break;

		case SYSCTL_NET_TCP_WMEM:

			if (sysctl_read(SYSCTL_TCP_WMEM_PATH, 3, SYSCTL_TCP_WMEM_FORMAT, &tcp_wmem.min_value, &tcp_wmem.default_value, &tcp_wmem.max_value) == -1) {
				tcp_wmem.min_value = SYSCTL_TCP_WMEM_MIN_DEFAULT;
				tcp_wmem.default_value = SYSCTL_TCP_WMEM_DEFAULT_DEFAULT;
				tcp_wmem.max_value = SYSCTL_TCP_WMEM_MAX_DEFAULT;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.ipv4.tcp_wmem values - Using defaults : %d %d %d\n", tcp_wmem.min_value, tcp_wmem.default_value, tcp_wmem.max_value);
				return -1;
			}

			break;

		case SYSCTL_WINDOW_SCALING:

			if (sysctl_read(SYSCTL_WINDOW_SCALING_PATH, 1, SYSCTL_WINDOW_SCALING_FORMAT, &tcp_window_scaling) == -1) {
				tcp_window_scaling = SYSCTL_WINDOW_SCALING_DEFAULT;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.ipv4.tcp_window_scaling - Using default : %d\n", tcp_window_scaling);
				return -1;
			}

			break;

		case SYSCTL_NET_CORE_RMEM_MAX:

			if (sysctl_read(SYSCTL_NET_CORE_RMEM_MAX_PATH, 1, SYSCTL_NET_CORE_RMEM_MAX_FORMAT, &net_core_rmem_max) == -1) {
				net_core_rmem_max = SYSCTL_NET_CORE_RMEM_MAX_DEFAULT;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.core.rmem_max - Using default : %d\n", net_core_rmem_max);
				return -1;
			}

			break;

		case SYSCTL_NET_CORE_WMEM_MAX:

			if (sysctl_read(SYSCTL_NET_CORE_WMEM_MAX_PATH, 1, SYSCTL_NET_CORE_WMEM_MAX_FORMAT, &net_core_wmem_max) == -1) {
				net_core_wmem_max = SYSCTL_NET_CORE_WMEM_MAX_DEFAULT;
				vlog_printf(VLOG_WARNING, "sysctl_reader failed to read net.core.wmem_max - Using default : %d\n", net_core_wmem_max);
				return -1;
			}

			break;

		default:
			// Invalid argument.
			return -1;
		}
		return 0;
	}

	int get(sysctl_var_enum requested_var, void *val, size_t len) {

		size_t option_size;
		switch(requested_var) {
		case SYSCTL_NET_TCP_RMEM:
			option_size =  sizeof(tcp_rmem);
			if (len >=  option_size){
				memcpy(val, &tcp_rmem , option_size);
			} else {
				return -1;
			}
			break;

		case SYSCTL_NET_TCP_WMEM:
			option_size =  sizeof(tcp_wmem);
			if (len >=  option_size){
				memcpy(val, &tcp_wmem , option_size);
			} else {
				return -1;
			}
			break;

		case SYSCTL_WINDOW_SCALING:
			option_size =  sizeof(tcp_window_scaling);
			if (len >=  option_size){
				memcpy(val, &tcp_window_scaling , option_size);
			} else {
				return -1;
			}
			break;

		case SYSCTL_NET_CORE_RMEM_MAX:
			option_size =  sizeof(net_core_rmem_max);
			if (len >=  option_size){
				memcpy(val, &net_core_rmem_max , option_size);
			} else {
				return -1;
			}
			break;

		case SYSCTL_NET_CORE_WMEM_MAX:
			option_size =  sizeof(net_core_wmem_max);
			if (len >=  option_size){
				memcpy(val, &net_core_wmem_max , option_size);
			} else {
				return -1;
			}
			break;

		default:
			// Invalid argument.
			return -1;
		}
		return 0;
	}

	int update_and_get(sysctl_var_enum requested_var, void *val, size_t len){
		int res = this->update(requested_var);
		if (res == 0)
			return this->get(requested_var, val, len);
		else
			return res;
	}

	int update_all(){
		int sysctl_int = SYSCTL_ENUM_TYPE_START;
		int ans = 0;

		while (++sysctl_int != SYSCTL_ENUM_TYPE_END) {
			ans |=  this->update(static_cast<sysctl_var_enum>(sysctl_int));
		}
		return ans;
	}
};

#endif /* SYSCNTL_READER_H_ */
