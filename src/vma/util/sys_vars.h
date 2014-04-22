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


#ifndef SYS_VARS_H
#define SYS_VARS_H

#include <stdio.h>
#include <sched.h>
#include <string>
#include <netinet/in.h>

#include "vtypes.h"
#include "config.h"
#include "verbs_extra.h"


typedef enum {
	MCE_SPEC_DEFAULT = 0,
	MCE_SPEC_29WEST_LBM_29 = 29,
	MCE_SPEC_WOMBAT_FH_LBM_554 = 554,
	MCE_SPEC_RTI_784 = 784,
	MCE_SPEC_NETEFFECT_63 = 63,
	MCE_SPEC_MCD_623 = 623,
	MCE_SPEC_MCD_IRQ_624 = 624
} mce_spec_t;

typedef enum {
	ALLOC_TYPE_ANON = 0,
	ALLOC_TYPE_CONTIG,
	ALLOC_TYPE_HUGEPAGES,
	ALLOC_TYPE_LAST,
} alloc_mode_t;

typedef enum {
	TX_DROP_NOTHING = 0, 		// Test Mode: Null TX - Drop all Tx'ed buffers
	TX_DROP_ALL     = 1,
	TX_DROP_MC      = 2,
	TX_DROP_UC      = 3,
	TX_DROP_LAST
} tx_drop_mode_t;

typedef enum {
	RING_LOGIC_PER_INTERFACE = 0,
	RING_LOGIC_PER_SOCKET = 10,
	RING_LOGIC_PER_THREAD = 20,
	RING_LOGIC_PER_CORE = 30,
	RING_LOGIC_PER_CORE_ATTACH_THREADS = 31,
	RING_LOGIC_LAST
} ring_logic_t;

static inline bool is_ring_logic_valid(ring_logic_t logic)
{
	switch (logic) {
	case RING_LOGIC_PER_INTERFACE:
	case RING_LOGIC_PER_SOCKET:
	case RING_LOGIC_PER_THREAD:
	case RING_LOGIC_PER_CORE:
	case RING_LOGIC_PER_CORE_ATTACH_THREADS:
		return true;
	default:
		return false;
	}
}

static inline const char* ring_logic_str(ring_logic_t logic)
{
	switch (logic) {
	case RING_LOGIC_PER_INTERFACE:		return "(Ring per interface)";
	case RING_LOGIC_PER_SOCKET:		return "(Ring per socket)";
	case RING_LOGIC_PER_THREAD:		return "(Ring per thread)";
	case RING_LOGIC_PER_CORE:		return "(Ring per core)";
	case RING_LOGIC_PER_CORE_ATTACH_THREADS: return "(Ring per core - attach threads)";
	default:				break;
	}
	return "unsupported";
}

typedef enum {
	THREAD_MODE_SINGLE = 0,
	THREAD_MODE_MULTI,
	THREAD_MODE_MUTEX,
	THREAD_MODE_PLENTY,
	THREAD_MODE_LAST
} thread_mode_t;

// See ibv_transport_type for general verbs transport types
typedef enum {
	VMA_TRANSPORT_UNKNOWN	= -1,
	VMA_TRANSPORT_IB	= 0,
	VMA_TRANSPORT_ETH
} transport_type_t;

typedef enum {
	MSS_FOLLOW_MTU = 0
} mss_mode_t;

struct mce_sys_var {
	char 		*app_name;
	char 		app_id[MAX_APP_ID_LENGHT];

	uint32_t 	mce_spec;
	uint32_t 	mce_spec_param1;
	uint32_t 	mce_spec_param2;

	uint32_t 	log_level;
	uint32_t	log_details;
	char 		log_filename[FILENAME_MAX];
	char		stats_filename[FILENAME_MAX];
	char 		conf_filename[FILENAME_MAX];
	bool		log_colors;
	bool 		handle_sigintr;
	bool		handle_segfault;
	uint32_t	stats_fd_num_max;

	ring_logic_t	ring_allocation_logic_tx;
	ring_logic_t	ring_allocation_logic_rx;
	int		ring_migration_ratio_tx;
	int		ring_migration_ratio_rx;
	int		ring_limit_per_interface;

	uint32_t 	tx_num_segs_tcp;
	uint32_t 	tx_num_bufs;
	uint32_t 	tx_num_wr;
	uint32_t 	tx_max_inline;
	tx_drop_mode_t	tx_drop_mode;
	bool 		tx_mc_loopback_default;
	bool		tx_nonblocked_eagains;
	uint32_t	tx_prefetch_bytes;
	int32_t         tx_backlog_max;

	uint32_t 	rx_num_bufs;
	uint32_t 	rx_num_wr;
	uint32_t	rx_num_wr_to_post_recv;
	int32_t		rx_poll_num;
	int32_t		rx_poll_num_init;
	uint32_t 	rx_udp_poll_os_ratio;
	uint32_t 	rx_poll_yield_loops;
	uint32_t 	rx_skip_os_fd_check;
	uint32_t 	rx_ready_byte_min_limit;
	uint32_t 	rx_prefetch_bytes;
	uint32_t 	rx_prefetch_bytes_before_poll;
	uint32_t	rx_cq_drain_rate_nsec;	// If enabled this will cause the Rx to drain all wce in CQ before returning to user, 
						// Else (Default: Disbaled) it will return when first ready packet is in socket queue
	uint32_t	rx_delta_tsc_between_cq_polls;

	uint32_t	gro_streams_max;

	bool		tcp_3t_rules;
	bool		eth_mc_l2_only_rules;

	int32_t		select_poll_num;
	bool		select_poll_os_force;
	uint32_t	select_poll_os_ratio;
	uint32_t 	select_skip_os_fd_check;
	uint32_t 	select_poll_yield_loops;
	bool		select_arm_cq;
	bool            select_handle_cpu_usage_stats;

	bool		cq_moderation_enable;
	uint32_t	cq_moderation_count;
	uint32_t	cq_moderation_period_usec;
	uint32_t	cq_aim_max_count;
	uint32_t	cq_aim_max_period_usec;
	uint32_t	cq_aim_interval_msec;
	uint32_t	cq_aim_interrupts_rate_per_sec;


	uint32_t	cq_poll_batch_max;
	uint32_t	progress_engine_interval_msec;
	uint32_t	progress_engine_wce_max;
	bool		cq_keep_qp_full;
	uint32_t	qp_compensation_level;

	bool		offloaded_sockets;
	uint32_t	timer_resolution_msec;
	uint32_t	tcp_timer_resolution_msec;
	uint32_t	wait_after_join_msec;
	uint32_t	wait_after_rereg_msec;
	in_port_t	block_udp_port;
	thread_mode_t	thread_mode;
	alloc_mode_t	mem_alloc_type;
	bool		handle_fork;
	bool		close_on_dup2;
	uint32_t 	mtu;
	uint32_t	lwip_cc_algo_mod;
	uint32_t 	lwip_mss;
	int32_t 	window_scaling;
	char		internal_thread_cpuset[FILENAME_MAX];
	char		internal_thread_affinity_str[CPU_SETSIZE/4];
	cpu_set_t	internal_thread_affinity;
	bool		internal_thread_arm_cq_enabled;
	bool 		handle_bf;

	bool 		enable_ipoib;
	uint32_t	timer_netlink_update_msec;

	//Neigh parameters
	uint32_t 	neigh_uc_arp_quata;
	uint32_t	neigh_wait_till_send_arp_msec;
	uint32_t	neigh_num_err_retries;

	bool 		suppress_igmp_warning;

	uint32_t 	vma_time_measure_num_samples;
	char 		vma_time_measure_filename[FILENAME_MAX];
};


#define SYS_VAR_LOG_LEVEL				"VMA_TRACELEVEL"
#define SYS_VAR_LOG_DETAILS				"VMA_LOG_DETAILS"
#define SYS_VAR_LOG_FILENAME				"VMA_LOG_FILE"
#define SYS_VAR_STATS_FILENAME				"VMA_STATS_FILE"
#define SYS_VAR_CONF_FILENAME				"VMA_CONFIG_FILE"
#define SYS_VAR_LOG_COLORS				"VMA_LOG_COLORS"
#define SYS_VAR_APPLICATION_ID				"VMA_APPLICATION_ID"
#define SYS_VAR_HANDLE_SIGINTR				"VMA_HANDLE_SIGINTR"
#define SYS_VAR_HANDLE_SIGSEGV				"VMA_HANDLE_SIGSEGV"
#define SYS_VAR_STATS_FD_NUM				"VMA_STATS_FD_NUM"

#define SYS_VAR_RING_ALLOCATION_LOGIC_TX                "VMA_RING_ALLOCATION_LOGIC_TX"
#define SYS_VAR_RING_ALLOCATION_LOGIC_RX                "VMA_RING_ALLOCATION_LOGIC_RX"
#define SYS_VAR_RING_MIGRATION_RATIO_TX                 "VMA_RING_MIGRATION_RATIO_TX"
#define SYS_VAR_RING_MIGRATION_RATIO_RX                 "VMA_RING_MIGRATION_RATIO_RX"
#define SYS_VAR_RING_LIMIT_PER_INTERFACE                "VMA_RING_LIMIT_PER_INTERFACE"

#define SYS_VAR_TX_NUM_SEGS_TCP				"VMA_TX_SEGS_TCP"
#define SYS_VAR_TX_NUM_BUFS				"VMA_TX_BUFS"
#define SYS_VAR_TX_NUM_WRE				"VMA_TX_WRE"
#define SYS_VAR_TX_MAX_INLINE				"VMA_TX_MAX_INLINE"
#define SYS_VAR_TX_DROP					"VMA_TX_DROP_MODE"
#define SYS_VAR_TX_MC_LOOPBACK				"VMA_TX_MC_LOOPBACK"
#define SYS_VAR_TX_NONBLOCKED_EAGAINS			"VMA_TX_NONBLOCKED_EAGAINS"
#define SYS_VAR_TX_PREFETCH_BYTES			"VMA_TX_PREFETCH_BYTES"
#define SYS_VAR_TX_BACKLOG_MAX                          "VMA_TX_BACKLOG_MAX"

#define SYS_VAR_RX_NUM_BUFS				"VMA_RX_BUFS"
#define SYS_VAR_RX_NUM_WRE				"VMA_RX_WRE"
#define SYS_VAR_RX_NUM_WRE_TO_POST_RECV			"VMA_RX_WRE_BATCHING"
#define SYS_VAR_RX_NUM_POLLS				"VMA_RX_POLL"
#define SYS_VAR_RX_NUM_POLLS_INIT			"VMA_RX_POLL_INIT"
#define SYS_VAR_RX_UDP_POLL_OS_RATIO			"VMA_RX_UDP_POLL_OS_RATIO"
// The following 2 params were replaced by VMA_RX_UDP_POLL_OS_RATIO
#define SYS_VAR_RX_POLL_OS_RATIO                       "VMA_RX_POLL_OS_RATIO"
#define SYS_VAR_RX_SKIP_OS                             "VMA_RX_SKIP_OS"
#define SYS_VAR_RX_POLL_YIELD				"VMA_RX_POLL_YIELD"
#define SYS_VAR_RX_BYTE_MIN_LIMIT			"VMA_RX_BYTES_MIN"
#define SYS_VAR_RX_PREFETCH_BYTES			"VMA_RX_PREFETCH_BYTES"
#define SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL		"VMA_RX_PREFETCH_BYTES_BEFORE_POLL"
#define SYS_VAR_RX_CQ_DRAIN_RATE_NSEC			"VMA_RX_CQ_DRAIN_RATE_NSEC"
#define SYS_VAR_GRO_STREAMS_MAX				"VMA_GRO_STREAMS_MAX"
#define SYS_VAR_TCP_3T_RULES				"VMA_TCP_3T_RULES"
#define SYS_VAR_ETH_MC_L2_ONLY_RULES			"VMA_ETH_MC_L2_ONLY_RULES"

#define SYS_VAR_SELECT_CPU_USAGE_STATS			"VMA_CPU_USAGE_STATS"
#define SYS_VAR_SELECT_NUM_POLLS			"VMA_SELECT_POLL"
#define SYS_VAR_SELECT_POLL_OS_FORCE			"VMA_SELECT_POLL_OS_FORCE"
#define SYS_VAR_SELECT_POLL_OS_RATIO			"VMA_SELECT_POLL_OS_RATIO"
#define SYS_VAR_SELECT_POLL_YIELD			"VMA_SELECT_POLL_YIELD"
#define SYS_VAR_SELECT_SKIP_OS				"VMA_SELECT_SKIP_OS"
#define SYS_VAR_SELECT_CQ_IRQ				"VMA_SELECT_CQ_IRQ"

#define SYS_VAR_CQ_MODERATION_ENABLE			"VMA_CQ_MODERATION_ENABLE"
#define SYS_VAR_CQ_MODERATION_COUNT			"VMA_CQ_MODERATION_COUNT"
#define SYS_VAR_CQ_MODERATION_PERIOD_USEC		"VMA_CQ_MODERATION_PERIOD_USEC"
#define SYS_VAR_CQ_AIM_MAX_COUNT			"VMA_CQ_AIM_MAX_COUNT"
#define SYS_VAR_CQ_AIM_MAX_PERIOD_USEC			"VMA_CQ_AIM_MAX_PERIOD_USEC"
#define SYS_VAR_CQ_AIM_INTERVAL_MSEC			"VMA_CQ_AIM_INTERVAL_MSEC"
#define SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC		"VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC"

#define SYS_VAR_CQ_POLL_BATCH_MAX			"VMA_CQ_POLL_BATCH_MAX"
#define SYS_VAR_PROGRESS_ENGINE_INTERVAL		"VMA_PROGRESS_ENGINE_INTERVAL"
#define SYS_VAR_PROGRESS_ENGINE_WCE_MAX			"VMA_PROGRESS_ENGINE_WCE_MAX"
#define SYS_VAR_CQ_KEEP_QP_FULL				"VMA_CQ_KEEP_QP_FULL"
#define SYS_VAR_QP_COMPENSATION_LEVEL			"VMA_QP_COMPENSATION_LEVEL"
#define SYS_VAR_OFFLOADED_SOCKETS			"VMA_OFFLOADED_SOCKETS"
#define SYS_VAR_TIMER_RESOLUTION_MSEC			"VMA_TIMER_RESOLUTION_MSEC"
#define SYS_VAR_TCP_TIMER_RESOLUTION_MSEC		"VMA_TCP_TIMER_RESOLUTION_MSEC"
#define SYS_VAR_WAIT_AFTER_JOIN_MSEC			"VMA_WAIT_AFTER_JOIN_MSEC"
#define SYS_VAR_WAIT_AFTER_REREG_MSEC			"VMA_WAIT_AFTER_REREG_MSEC"
#define SYS_VAR_THREAD_MODE				"VMA_THREAD_MODE"
#define SYS_VAR_HUGETBL					"VMA_HUGETBL"
#define SYS_VAR_MEM_ALLOC_TYPE				"VMA_MEM_ALLOC_TYPE"
#define SYS_VAR_FORK					"VMA_FORK"
#define SYS_VAR_BF					"VMA_BF"
#define SYS_VAR_CLOSE_ON_DUP2				"VMA_CLOSE_ON_DUP2"
#define SYS_VAR_MTU					"VMA_MTU"
#define SYS_VAR_MSS					"VMA_MSS"
#define SYS_VAR_TCP_CC_ALGO					"VMA_TCP_CC_ALGO"
#define SYS_VAR_WINDOW_SCALING				"VMA_WINDOW_SCALING"
#define SYS_VAR_SPEC					"VMA_SPEC"
#define SYS_VAR_SPEC_PARAM1				"VMA_SPEC_PARAM1"
#define SYS_VAR_SPEC_PARAM2				"VMA_SPEC_PARAM2"

#define SYS_VAR_IPOIB					"VMA_IPOIB"

#define SYS_VAR_INTERNAL_THREAD_AFFINITY		"VMA_INTERNAL_THREAD_AFFINITY"
#define SYS_VAR_INTERNAL_THREAD_CPUSET			"VMA_INTERNAL_THREAD_CPUSET"
#define SYS_VAR_INTERNAL_THREAD_ARM_CQ			"VMA_INTERNAL_THREAD_ARM_CQ"

#define SYS_VAR_NETLINK_TIMER_MSEC			"VMA_NETLINK_TIMER"

#define SYS_VAR_NEIGH_UC_ARP_QUATA			"VMA_NEIGH_UC_ARP_QUATA"
#define SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC			"VMA_NEIGH_UC_ARP_DELAY_MSEC"
#define SYS_VAR_NEIGH_NUM_ERR_RETRIES			"VMA_NEIGH_NUM_ERR_RETRIES"

#define SYS_VAR_SUPPRESS_IGMP_WARNING			"VMA_SUPPRESS_IGMP_WARNING"

#define SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES		"VMA_TIME_MEASURE_NUM_SAMPLES"
#define SYS_VAR_VMA_TIME_MEASURE_DUMP_FILE		"VMA_TIME_MEASURE_DUMP_FILE"


#define MCE_DEFAULT_LOG_FILE				("")
#define MCE_DEFAULT_CONF_FILE				("/etc/libvma.conf")
#define MCE_DEFAULT_STATS_FILE				("")
#define MCE_DEFAULT_LOG_DETAILS				(0)
#define MCE_DEFAULT_LOG_COLORS				(true)
#define MCE_DEFAULT_APP_ID				("VMA_DEFAULT_APPLICATION_ID")
#define MCE_DEFAULT_HANDLE_SIGINTR			(false)
#define MCE_DEFAULT_HANDLE_SIGFAULT			(false)
#define MCE_DEFAULT_STATS_FD_NUM			100
#define MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX            (RING_LOGIC_PER_INTERFACE)
#define MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX            (RING_LOGIC_PER_INTERFACE)
#define MCE_DEFAULT_RING_MIGRATION_RATIO_TX             (100)
#define MCE_DEFAULT_RING_MIGRATION_RATIO_RX             (100)
#define MCE_DEFAULT_RING_LIMIT_PER_INTERFACE            (0)
#define MCE_DEFAULT_TX_NUM_SEGS_TCP			(1000000)
#define MCE_DEFAULT_TX_NUM_BUFS				(200000)
#define MCE_DEFAULT_TX_NUM_WRE				(16000)
#define MCE_DEFAULT_TX_MAX_INLINE			(220) //224
#define MCE_DEFAULT_TX_BUILD_IP_CHKSUM			(true)
#define MCE_DEFAULT_TX_MC_LOOPBACK			(true)
#define MCE_DEFAULT_TX_NONBLOCKED_EAGAINS		(false)
#define MCE_DEFAULT_TX_PREFETCH_BYTES			(256)
#define MCE_DEFAULT_TX_BACKLOG_MAX                      (100)
#define MCE_DEFAULT_RX_NUM_BUFS				(200000)
#define MCE_DEFAULT_RX_NUM_WRE				(16000)
#define MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV		(64)
#define MCE_DEFAULT_RX_NUM_SGE				(1)
#define MCE_DEFAULT_RX_NUM_POLLS			(100000)
#define MCE_DEFAULT_RX_NUM_POLLS_INIT			(0)
#define MCE_DEFAULT_RX_UDP_POLL_OS_RATIO		(100)
#define MCE_DEFAULT_RX_POLL_YIELD			(0)
#define MCE_DEFAULT_RX_BYTE_MIN_LIMIT			(65536)
#define MCE_DEFAULT_RX_PREFETCH_BYTES			(256)
#define MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL	(0)
#define MCE_DEFAULT_RX_CQ_DRAIN_RATE			(MCE_RX_CQ_DRAIN_RATE_DISABLED)
#define MCE_DEFAULT_GRO_STREAMS_MAX			(32)
#define MCE_DEFAULT_TCP_3T_RULES			(false)
#define MCE_DEFAULT_ETH_MC_L2_ONLY_RULES		(false)
#define MCE_DEFAULT_SELECT_NUM_POLLS			(100000)
#define MCE_DEFAULT_SELECT_POLL_OS_FORCE		(0)
#define MCE_DEFAULT_SELECT_POLL_OS_RATIO		(10)
#define MCE_DEFAULT_SELECT_POLL_YIELD			(0)
#define MCE_DEFAULT_SELECT_SKIP_OS			(4)
#define MCE_DEFAULT_SELECT_ARM_CQ			(true)
#define MCE_DEFAULT_SELECT_CPU_USAGE_STATS		(false)
#define MCE_DEFAULT_CQ_MODERATION_ENABLE		(true)
#define MCE_DEFAULT_CQ_MODERATION_COUNT			(48)
#define MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC		(50)
#define MCE_DEFAULT_CQ_AIM_MAX_COUNT			(560)
#define MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC		(250)
#define MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC		(250)
#define MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC	(5000)
#define MCE_DEFAULT_CQ_POLL_BATCH			(16)
#define MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC	(10)
#define MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX		(10000)
#define MCE_DEFAULT_CQ_KEEP_QP_FULL			(true)
#define MCE_DEFAULT_QP_COMPENSATION_LEVEL		(256)
#define MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED	(false)
#define MCE_DEFAULT_QP_FORCE_MC_ATTACH			(false)
#define MCE_DEFAULT_OFFLOADED_SOCKETS			(true)
#define MCE_DEFAULT_TIMER_RESOLUTION_MSEC		(10)
#define MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC		(100)
#define MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC		(0)
#define MCE_DEFAULT_WAIT_AFTER_REREG_MSEC		(500)
#define MCE_DEFAULT_THREAD_MODE				(THREAD_MODE_MULTI)
#ifndef VMA_IBV_ACCESS_ALLOCATE_MR
#define MCE_DEFAULT_MEM_ALLOC_TYPE			(ALLOC_TYPE_HUGEPAGES)
#else
#define MCE_DEFAULT_MEM_ALLOC_TYPE			(ALLOC_TYPE_CONTIG)
#endif
#define MCE_DEFAULT_FORK_SUPPORT			(true)
#define MCE_DEFAULT_BF_FLAG				(true)
#define MCE_DEFAULT_CLOSE_ON_DUP2			(true)
#define MCE_DEFAULT_MTU					(1500)
#define MCE_DEFAULT_MSS					(0)
#define MCE_DEFAULT_LWIP_CC_ALGO_MOD			(0)
#define MCE_DEFAULT_WINDOW_SCALING			(3)
#define MCE_DEFAULT_QP_LOGIC				(QP_ALLOC_LOGIC__SINGLE_QP_PER_PORT_PER_LOCAL_IP)
#define MCE_DEFAULT_CQ_LOGIC				(CQ_ALLOC_LOGIC__CQ_PER_HCA)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY		(0)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR	("0")
#define MCE_DEFAULT_INTERNAL_THREAD_CPUSET		("")
#define MCE_DEFAULT_NETLINK_TIMER_MSEC			(10000)

#define MCE_DEFAULT_NEIGH_UC_ARP_QUATA			3
#define MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC	10000
#define MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES		1

#define MCE_DEFAULT_SUPPRESS_IGMP_WARNING		0

#define MCE_DEFAULT_TIME_MEASURE_NUM_SAMPLES		(10000)
#define MCE_DEFAULT_TIME_MEASURE_DUMP_FILE		"/tmp/VMA_inst.dump"

#define MCE_MIN_NUM_SGE					(1)
#define MCE_MAX_NUM_SGE					(32)
#define MCE_MIN_RX_NUM_POLLS				(-1)
#define MCE_MAX_RX_NUM_POLLS				(100000000)
#define MCE_MIN_RX_PREFETCH_BYTES			(32) /* Just enough for headers (IPoIB+IP+UDP)*/
#define MCE_MAX_RX_PREFETCH_BYTES			(2044)
#define MCE_RX_CQ_DRAIN_RATE_DISABLED			(0)
#define MCE_CQ_DRAIN_INTERVAL_DISABLED			(0)
#define MCE_CQ_ADAPTIVE_MODERATION_DISABLED		(0)
#define MCE_MIN_CQ_POLL_BATCH				(1)
#define MCE_MAX_CQ_POLL_BATCH				(128)
#define MCE_DEFAULT_IPOIB_FLAG				(1)

#define MCE_ALIGNMENT					((unsigned long)63)
#define RX_BUF_SIZE(mtu)				(mtu + IPOIB_HDR_LEN + GRH_HDR_LEN) // RX buffers are larger in IB
#define TX_BUF_SIZE(mtu)				(mtu + ETH_HDR_LEN) // Tx buffers are larger in Ethernet (they include L2 for RAW QP)
#define NUM_TX_POST_SEND_NOTIFY				64
#define NUM_RX_WRE_TO_POST_RECV_MAX			1024
#define DEFAULT_MC_TTL					64
#define MAX_FREG_MEM_BUF				(MCE_DEFAULT_RX_NUM_BUFS/100)
#define IBVERBS_ABI_VER_PARAM_FILE			"/sys/class/infiniband_verbs/abi_version"
#define IFTYPE_PARAM_FILE				"/sys/class/net/%s/type"
#define IFADDR_LEN_PARAM_FILE				"/sys/class/net/%s/addr_len"
#define IFADDR_MTU_PARAM_FILE				"/sys/class/net/%s/mtu"
#define UMCAST_PARAM_FILE				"/sys/class/net/%s/umcast"
#define IPOIB_MODE_PARAM_FILE				"/sys/class/net/%s/mode"
#define VERBS_DEVICE_ID_PARAM_FILE			"/sys/class/net/%s/dev_id"
#define VERBS_DEVICE_RESOURCE_PARAM_FILE		"/sys/class/net/%s/device/resource"
#define BONDING_MODE_PARAM_FILE				"/sys/class/net/%s/bonding/mode"
#define BONDING_SLAVES_PARAM_FILE			"/sys/class/net/%s/bonding/slaves"
#define BONDING_ACTIVE_SLAVE_PARAM_FILE			"/sys/class/net/%s/bonding/active_slave"
#define BONDING_FAILOVER_MAC_PARAM_FILE			"/sys/class/net/%s/bonding/fail_over_mac"
#define L2_ADDR_FILE					"/sys/class/net/%s/address"
#define L2_BR_ADDR_FILE					"/sys/class/net/%s/broadcast"
#define IGMP_FORCE_PARAM_FILE				"/proc/sys/net/ipv4/conf/%s/force_igmp_version"
#define IGMP_MAX_MEMBERSHIP_FILE			"/proc/sys/net/ipv4/igmp_max_memberships"
#define TCP_SCALING_WINDOW_MAX_RECV_MEM_FILE		"/proc/sys/net/core/rmem_max"
#define TCP_SCALING_WINDOW_FILE				"/proc/sys/net/ipv4/tcp_window_scaling"
#define ARP_TABLE_FILE					"/proc/net/arp"
#define RAW_QP_PRIVLIGES_PARAM_FILE			"/sys/module/ib_uverbs/parameters/disable_raw_qp_enforcement"
#define FLOW_STEERING_PARAM_FILE			"/sys/module/mlx4_core/parameters/flow_steering"
#define FLOW_STEERING_HASH_PARAM_FILE			"/sys/module/mlx4_core/parameters/flow_steering_hash"
#define FLOW_STEERING_MGM_ENTRY_SIZE_PARAM_FILE		"/sys/module/mlx4_core/parameters/log_num_mgm_entry_size"

#define MAX_STATS_FD_NUM				1024
#define UNSENT_QUEUEU_SIZE				1024
#define TCP_LINGER_TIME_MSEC				2000
#define DISABLE_WINDOW_SCALING				(-1)
#define USE_OS_WINDOW_SCALING				(-2)
#define MAX_WINDOW_SCALING				14

/**
 * Macros for single/multi thread support
 */
#define MULTI_THREAD_ONLY(x) 	{ if (mce_sys.thread_mode > THREAD_MODE_SINGLE) x; }


extern struct mce_sys_var mce_sys;
extern bool g_b_exit;
extern bool g_is_forked_child;
extern bool g_init_global_ctors_done;

#endif
