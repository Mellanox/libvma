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


#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netif/etharp.h>

#include <vlogger/vlogger.h>
#include "vma/util/rdtsc.h"
#include "vma/util/vtypes.h"
#include "vma/util/utils.h"
#include "vma/util/verbs_extra.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/event/event_handler_manager.h"
#include <vma/dev/ib_ctx_handler_collection.h>
#include "vma/sock/sock-redirect.h"
#include "vma/iomux/io_mux_call.h"
#include "vma_lwip.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/util/bullseye.h"

#include "lwip/opt.h"
#include "lwip/init.h"
#include "lwip/sys.h"
#include "lwip/tcp_impl.h"
#include "lwip/stats.h"
#include "lwip/memp.h"

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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
/* required system support functions for LWIP */
u32_t sys_jiffies(void)
{
	tscval_t now;

	gettimeoftsc(&now);
	return (u32_t)now;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

u32_t sys_now(void)
{
	struct timespec now;

	gettimefromtsc(&now);
	return now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

vma_lwip *g_p_lwip = 0;

/**
 * LWIP "network" driver code
 */

vma_lwip::vma_lwip() : lock_spin_recursive("vma_lwip"), m_lwip_bufs(NULL)
{
	m_run_timers = false;

	if (*g_p_vlogger_level >= VLOG_DEBUG)
		__vma_print_conf_file(__instance_list);

	lwip_logdbg("");

	lwip_cc_algo_module = (enum cc_algo_mod)mce_sys.lwip_cc_algo_mod;

	lwip_tcp_mss = get_lwip_tcp_mss(mce_sys.mtu, mce_sys.lwip_mss);

	memp_update_custom_pool(0,0);

	m_lwip_bufs = new char[memp_get_pool_size()];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_lwip_bufs){
		memp_set_pool_start(m_lwip_bufs);
	} else
		lwip_logerr("failed allocting memory for lwip\n");
	BULLSEYE_EXCLUDE_BLOCK_END

	if(mce_sys.window_scaling == USE_OS_WINDOW_SCALING) {
		mce_sys.window_scaling = get_window_scaling_factor();
	}

	if(mce_sys.window_scaling <= DISABLE_WINDOW_SCALING) {
		enable_wnd_scale = 0;
		rcv_wnd_scale = 0;
	}else {
		enable_wnd_scale = 1;
		rcv_wnd_scale = mce_sys.window_scaling;
	}

	//Bring up LWIP
	lwip_init();

	lwip_logdbg("LWIP subsystem initialized");

	register_tcp_tx_pbuf_alloc(sockinfo_tcp::tcp_tx_pbuf_alloc);
	register_tcp_tx_pbuf_free(sockinfo_tcp::tcp_tx_pbuf_free);
	register_tcp_seg_alloc(sockinfo_tcp::tcp_seg_alloc);
	register_tcp_seg_free(sockinfo_tcp::tcp_seg_free);
	register_ip_output(sockinfo_tcp::ip_output);
	register_ip_route_mtu(vma_ip_route_mtu);

	//tcp_ticks increases in the rate of tcp slow_timer
	g_p_event_handler_manager->register_timer_event(mce_sys.tcp_timer_resolution_msec * 2, this, PERIODIC_TIMER, 0);
}

vma_lwip::~vma_lwip()
{
	if (m_lwip_bufs) {
		delete m_lwip_bufs;
		m_lwip_bufs = NULL;
	}

	__vma_free_resources();
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

int vma_lwip::sockaddr2ipaddr(const sockaddr *__to, socklen_t __tolen, ip_addr_t &ip, uint16_t &port)
{
	NOT_IN_USE(__tolen);
	if (get_sa_family(__to)	 != AF_INET)
		return -1;

	ip.addr = get_sa_ipv4_addr(__to);
	port = htons(get_sa_port(__to));
	return 0;
}

err_t vma_lwip::vma_lwip_netif_init(struct netif *lwip_if)
{
	qp_mgr *p_qp_mgr = (qp_mgr *)lwip_if->state;

	if (!p_qp_mgr)
		lwip_logpanic("Failed to init lwip netif since it state is not initialized properly");

/* TODO ALEXR TX
	struct net_dev_info_t* p_net_dev_info = p_qp_mgr->get_netdev_info();
	//lwip_if->linkoutput = vma_output;
	lwip_if->output = vma_output;
	lwip_if->mtu = p_net_dev_info->if_mtu;
	lwip_if->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
	lwip_if->hwaddr_len = p_net_dev_info->hw_addr_len;
	lwip_if->name[0] = p_net_dev_info->if_name[0];
        lwip_if->name[1] = p_net_dev_info->if_name[strlen(p_net_dev_info->if_name) - 1];
	memcpy(lwip_if->hwaddr, p_net_dev_info->hw_addr, p_net_dev_info->hw_addr_len);
//*/
	return ERR_OK;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

u16_t vma_lwip::vma_ip_route_mtu(ip_addr_t *dest)
{
	struct sockaddr_in addr;
	int ifmtu = 0;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	
	in_addr_t dst_ip	= dest->addr;
	in_addr_t src_ip	= 0;
	uint8_t tos		= 0;
	uint8_t table_id 	= 0;

	if (!g_p_rule_table_mgr->rule_resolve(rule_table_key(dst_ip, src_ip, tos), &table_id))
	{
		lwip_logdbg("Unable to find table ID : No rule match destination IP");
		return 0;
	}
	
	g_p_route_table_mgr->route_resolve(dest->addr, table_id, &addr.sin_addr.s_addr);
	net_device_val* ndv = g_p_net_device_table_mgr->get_net_device_val(addr.sin_addr.s_addr);
	if (ndv) {
		ifmtu = ndv->get_mtu();
	}

	if (ifmtu <= 0) {
		return 0;
	}

	return ifmtu;
}

void vma_lwip::handle_timer_expired(void* user_data) {
	NOT_IN_USE(user_data);
	tcp_ticks++;
}

uint32_t get_lwip_tcp_mss(uint32_t mtu, uint32_t lwip_mss)
{
	uint32_t  lwip_tcp_mss;
	switch (lwip_mss) {
	case MSS_FOLLOW_MTU:
		// set MSS to match VMA_MTU, MSS is equal to (VMA_MTU-40), but forced to be at least 1.
		lwip_tcp_mss = (MAX(mtu, (40+1)) - 40);
		break;
	default:
		lwip_tcp_mss = (MAX(lwip_mss, 1));
		break;
	}
	return lwip_tcp_mss;
}
