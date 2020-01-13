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

#include "utils/rdtsc.h"
#include "vlogger/vlogger.h"

#include "vma/event/event_handler_manager.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/lwip/init.h"
#include "vma/lwip/tcp_impl.h"
#include "vma_lwip.h"

// debugging macros
#define MODULE_NAME 		"lwip"
#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO         MODULE_NAME ":%s%d:%s() "
#undef  __INFO__
#define __INFO__	""


#define lwip_logpanic             __log_info_panic
#define lwip_logerr               __log_info_err
#define lwip_logwarn              __log_info_warn
#define lwip_loginfo              __log_info_info
#define lwip_logdbg               __log_info_dbg
#define lwip_logfunc              __log_info_func
#define lwip_logfuncall           __log_info_funcall

int32_t enable_wnd_scale = 0;
u32_t rcv_wnd_scale = 0;

u32_t vma_lwip::sys_now(void)
{
	struct timespec now;

	gettimefromtsc(&now);
	return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

u8_t vma_lwip::read_tcp_timestamp_option(void)
{
	u8_t res = (safe_mce_sys().tcp_ts_opt == TCP_TS_OPTION_FOLLOW_OS) ? safe_mce_sys().sysctl_reader.get_net_ipv4_tcp_timestamps() : (safe_mce_sys().tcp_ts_opt == TCP_TS_OPTION_ENABLE ? 1 : 0);
	if (res) {
#if LWIP_TCP_TIMESTAMPS
		lwip_logdbg("TCP timestamp option has been enabled");
#else
		lwip_logwarn("Cannot enable TCP timestamp option because LWIP_TCP_TIMESTAMPS is not defined");
		res = 0;
#endif
	}
	return res;
}

vma_lwip *g_p_lwip = 0;

/**
 * LWIP "network" driver code
 */

vma_lwip::vma_lwip()
{
	m_run_timers = false;

	if (*g_p_vlogger_level >= VLOG_DEBUG)
		__vma_print_conf_file(__instance_list);

	lwip_logdbg("");

	lwip_cc_algo_module = (enum cc_algo_mod)safe_mce_sys().lwip_cc_algo_mod;

	lwip_tcp_mss = get_lwip_tcp_mss(safe_mce_sys().mtu, safe_mce_sys().lwip_mss);
	BULLSEYE_EXCLUDE_BLOCK_END

	enable_ts_option = read_tcp_timestamp_option();
	int is_window_scaling_enabled = safe_mce_sys().sysctl_reader.get_tcp_window_scaling();
	if(is_window_scaling_enabled) {
		int rmem_max_value = safe_mce_sys().sysctl_reader.get_tcp_rmem()->max_value;
		int core_rmem_max = safe_mce_sys().sysctl_reader.get_net_core_rmem_max();
		enable_wnd_scale = 1;
		rcv_wnd_scale = get_window_scaling_factor(rmem_max_value, core_rmem_max);
	} else {
		enable_wnd_scale = 0;
		rcv_wnd_scale = 0;
	}

	 //Bring up LWIP
	lwip_init();
	lwip_logdbg("LWIP subsystem initialized");

	register_tcp_tx_pbuf_alloc(sockinfo_tcp::tcp_tx_pbuf_alloc);
	register_tcp_tx_pbuf_free(sockinfo_tcp::tcp_tx_pbuf_free);
	register_tcp_seg_alloc(sockinfo_tcp::tcp_seg_alloc);
	register_tcp_seg_free(sockinfo_tcp::tcp_seg_free);
	register_ip_output(sockinfo_tcp::ip_output);
	register_tcp_state_observer(sockinfo_tcp::tcp_state_observer);
	register_ip_route_mtu(sockinfo_tcp::get_route_mtu);
	register_sys_now(sys_now);
	register_sys_readv(orig_os_api.readv);
	set_tmr_resolution(safe_mce_sys().tcp_timer_resolution_msec);
	//tcp_ticks increases in the rate of tcp slow_timer
	void *node = g_p_event_handler_manager->register_timer_event(safe_mce_sys().tcp_timer_resolution_msec * 2, this, PERIODIC_TIMER, 0);
	if (!node) {
		lwip_logdbg("LWIP: failed to register timer event");
		free_lwip_resources();
		throw_vma_exception("LWIP: failed to register timer event");
	}
}

vma_lwip::~vma_lwip()
{
	free_lwip_resources(); 
}

void vma_lwip::free_lwip_resources(void)
{
	/* TODO - revert the constructor */
}

void vma_lwip::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);
	tcp_ticks++;
}

uint32_t get_lwip_tcp_mss(uint32_t mtu, uint32_t lwip_mss)
{
	uint32_t  _lwip_tcp_mss;

	/*	
	 * lwip_tcp_mss calculation
	 * 1. safe_mce_sys().mtu==0 && safe_mce_sys().lwip_mss==0 ==> lwip_tcp_mss = 0 (namelyl-must be calculated per interface)
	 * 2. safe_mce_sys().mtu==0 && safe_mce_sys().lwip_mss!=0 ==> lwip_tcp_mss = safe_mce_sys().lwip_mss
	 * 3. safe_mce_sys().mtu!=0 && safe_mce_sys().lwip_mss==0 ==> lwip_tcp_mss = safe_mce_sys().mtu - IP header len - TCP header len (must be positive)
	 * 4. safe_mce_sys().mtu!=0 && safe_mce_sys().lwip_mss!=0 ==> lwip_tcp_mss = safe_mce_sys().lwip_mss
	 */
	switch (lwip_mss) {
	case MSS_FOLLOW_MTU: /* 0 */
		switch(mtu) {
		case MTU_FOLLOW_INTERFACE:
			_lwip_tcp_mss = 0; /* MSS must follow the specific MTU per interface */ 
			break;
		default:
			// set MSS to match VMA_MTU, MSS is equal to (VMA_MTU-40), but forced to be at least 1.
			_lwip_tcp_mss = (MAX(mtu, (IP_HLEN+TCP_HLEN+1)) - IP_HLEN-TCP_HLEN);
			break;
		}
		break;
	default:
		_lwip_tcp_mss = (MAX(lwip_mss, 1));
		break;
	}
	return _lwip_tcp_mss;
}
