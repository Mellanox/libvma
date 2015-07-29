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

#include <linux/sysctl.h>
#include <sys/syscall.h>
#include "vlogger/vlogger.h"

#define SYSCTL_DEFAULT_TCP_RMEM_MIN				4096
#define SYSCTL_DEFAULT_TCP_RMEM_DEFAULT			87380
#define SYSCTL_DEFAULT_TCP_RMEM_MAX				4194304

#define SYSCTL_DEFAULT_TCP_WMEM_MIN				4096
#define SYSCTL_DEFAULT_TCP_WMEM_DEFAULT			16384
#define SYSCTL_DEFAULT_TCP_WMEM_MAX				4194304

#define SYSCTL_DEFAULT_WINDOW_SCALING			0

#define SYSCTL_DEFAULT_NET_CORE_RMEM_MAX		229376

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
	SYSCTL_ENUM_TYPE_END // SYSCTL_ENUM_TYPE_END must be the last ENUM
} sysctl_var_enum;


class sysctl_reader_t {

private:

	sysctl_tcp_mem rmem;
	sysctl_tcp_mem wmem;
	bool tcp_window_scaling;
	int net_core_rmem_max;

	void init_sysctl_args(struct __sysctl_args* args, int* name, size_t nlen, void* oldval, size_t oldlen){
		memset(args, 0, sizeof(*args));
		args->name = name;
		args->nlen = nlen;
		args->oldval = oldval;
		args->oldlenp = &oldlen;
	}

public :

	sysctl_reader_t(){
		memset(&rmem, 0 , sizeof(rmem));
		memset(&wmem, 0 , sizeof(wmem));
		memset(&tcp_window_scaling, 0, sizeof(tcp_window_scaling));
		memset(&net_core_rmem_max, 0, sizeof(net_core_rmem_max));

		this->update_all();
	}

	int update(sysctl_var_enum requested_var) {
		struct __sysctl_args args;
		int name[3];

		switch(requested_var) {
		case SYSCTL_NET_TCP_RMEM:
			name[0] = CTL_NET;
			name[1] = NET_IPV4;
			name[2] = NET_TCP_RMEM;
			init_sysctl_args(&args, name, 3, &rmem, sizeof(rmem));

			if (syscall(SYS__sysctl, &args) == -1) {
				rmem.min_value = SYSCTL_DEFAULT_TCP_RMEM_MIN;
				rmem.default_value = SYSCTL_DEFAULT_TCP_RMEM_DEFAULT;
				rmem.max_value = SYSCTL_DEFAULT_TCP_RMEM_MAX;
				vlog_printf(VLOG_WARNING," sysctl failed to read net.ipv4.tcp_rmem values - Using defaults : %d %d %d\n", rmem.min_value ,rmem.default_value , rmem.max_value);
				return -1;
			}
			break;

		case SYSCTL_NET_TCP_WMEM:
			name[0] = CTL_NET;
			name[1] = NET_IPV4;
			name[2] = NET_TCP_WMEM;
			init_sysctl_args(&args, name, 3, &wmem, sizeof(wmem));

			if (syscall(SYS__sysctl, &args) == -1) {
				wmem.min_value = SYSCTL_DEFAULT_TCP_WMEM_MIN;
				wmem.default_value = SYSCTL_DEFAULT_TCP_WMEM_DEFAULT;
				wmem.max_value = SYSCTL_DEFAULT_TCP_WMEM_DEFAULT;
				vlog_printf(VLOG_WARNING," sysctl failed to read net.ipv4.tcp_wmem values - Using defaults : %d %d %d\n", wmem.min_value ,wmem.default_value , wmem.max_value);
				return -1;
			}
			break;

		case SYSCTL_WINDOW_SCALING:
			name[0] = CTL_NET;
			name[1] = NET_IPV4;
			name[2] = NET_IPV4_TCP_WINDOW_SCALING;
			init_sysctl_args(&args, name, 3, &tcp_window_scaling, sizeof(tcp_window_scaling));

			if (syscall(SYS__sysctl, &args) == -1) {
				tcp_window_scaling = SYSCTL_DEFAULT_WINDOW_SCALING;
				vlog_printf(VLOG_WARNING," sysctl failed to read net.ipv4.tcp_window_scaling - Using default : %d\n", tcp_window_scaling);
				return -1;
			}
			break;

		case SYSCTL_NET_CORE_RMEM_MAX:
			name[0] = CTL_NET;
			name[1] = NET_CORE;
			name[2] = NET_CORE_RMEM_MAX;
			init_sysctl_args(&args, name, 3, &net_core_rmem_max, sizeof(net_core_rmem_max));
			if (syscall(SYS__sysctl, &args) == -1) {
				net_core_rmem_max = SYSCTL_DEFAULT_NET_CORE_RMEM_MAX;
				vlog_printf(VLOG_WARNING," sysctl failed to read net.core.rmem_max - Using default : %d\n", net_core_rmem_max);
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
			option_size =  sizeof(rmem);
			if (len >=  option_size){
				memcpy(val, &rmem , option_size);
			} else {
				return -1;
			}
			break;

		case SYSCTL_NET_TCP_WMEM:
			option_size =  sizeof(wmem);
			if (len >=  option_size){
				memcpy(val, &wmem , option_size);
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
