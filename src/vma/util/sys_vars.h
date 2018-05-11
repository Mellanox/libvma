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


#ifndef SYS_VARS_H
#define SYS_VARS_H

#include <stdio.h>
#include <sched.h>
#include <string>
#include <netinet/in.h>

#include "vtypes.h"
#include "config.h"
#include "verbs_extra.h"
#include "vma/util/sysctl_reader.h"
#include "vma/vma_extra.h"

typedef enum {
	MCE_SPEC_NONE = 0,
	MCE_SPEC_SOCKPERF_ULTRA_LATENCY_10,
	MCE_SPEC_SOCKPERF_LATENCY_15,
	MCE_SPEC_29WEST_LBM_29,
	MCE_SPEC_WOMBAT_FH_LBM_554,
	MCE_SPEC_MCD_623,
	MCE_SPEC_MCD_IRQ_624,
	MCE_SPEC_RTI_784,
	MCE_SPEC_LL_7750,
	MCE_SPEC_LL_MULTI_RING,

	MCE_VMA__ALL /* last element */
} vma_spec_t;

typedef enum {
	ALLOC_TYPE_ANON = 0,
	ALLOC_TYPE_CONTIG,
	ALLOC_TYPE_HUGEPAGES,
	ALLOC_TYPE_LAST,
} alloc_mode_t;

typedef enum {
	TS_CONVERSION_MODE_DISABLE = 0, // TS_CONVERSION_MODE_DISABLE must be the first enum
	TS_CONVERSION_MODE_RAW,
	TS_CONVERSION_MODE_BEST_POSSIBLE,
	TS_CONVERSION_MODE_SYNC,
	TS_CONVERSION_MODE_PTP,
	TS_CONVERSION_MODE_LAST
} ts_conversion_mode_t;

static inline bool is_ring_logic_valid(ring_logic_t logic)
{
	switch (logic) {
	case RING_LOGIC_PER_INTERFACE:
	case RING_LOGIC_PER_SOCKET:
	case RING_LOGIC_PER_THREAD:
	case RING_LOGIC_PER_CORE:
	case RING_LOGIC_PER_CORE_ATTACH_THREADS:
	case RING_LOGIC_PER_IP:
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
	case RING_LOGIC_PER_IP:		return "(Ring per ip)";
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

typedef enum {
	BUFFER_BATCHING_NONE = 0,
	BUFFER_BATCHING_WITH_RECLAIM,
	BUFFER_BATCHING_NO_RECLAIM,
	BUFFER_BATCHING_LAST,
} buffer_batching_mode_t;

// See ibv_transport_type for general verbs transport types
typedef enum {
	VMA_TRANSPORT_UNKNOWN	= -1,
	VMA_TRANSPORT_IB	= 0,
	VMA_TRANSPORT_ETH
} transport_type_t;

static inline const char* priv_vma_transport_type_str(transport_type_t transport_type)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	switch (transport_type) {
	case VMA_TRANSPORT_IB: 			return "IB";
	case VMA_TRANSPORT_ETH: 		return "ETH";
	case VMA_TRANSPORT_UNKNOWN:
	default:				break;
	}
	return "UNKNOWN";
	BULLSEYE_EXCLUDE_BLOCK_END
}

typedef enum {
	MSS_FOLLOW_MTU = 0
} mss_mode_t;

typedef enum {
	MTU_FOLLOW_INTERFACE = 0
} mtu_mode_t;

typedef enum {
	CTL_THREAD_DISABLE = 0,
	CTL_THREAD_WITH_WAKEUP,
	CTL_THREAD_NO_WAKEUP,
	CTL_THREAD_LAST
} tcp_ctl_thread_t;

typedef enum {
	TCP_TS_OPTION_DISABLE = 0, // TCP_TS_OPTION_DISABLE must be the first enum
	TCP_TS_OPTION_ENABLE,
	TCP_TS_OPTION_FOLLOW_OS,
	TCP_TS_OPTION_LAST
} tcp_ts_opt_t;

static inline const char* ctl_thread_str(tcp_ctl_thread_t logic)
{
	switch (logic) {
	case CTL_THREAD_DISABLE:		return "(Disabled)";
	case CTL_THREAD_WITH_WAKEUP:		return "(Enabled - with wakeup)";
	case CTL_THREAD_NO_WAKEUP:		return "(Enabled - no wakeup)";
	default:				break;
	}
	return "unsupported";
}

typedef enum {
	INTERNAL_THREAD_TCP_TIMER_HANDLING_DEFERRED = 0,
	INTERNAL_THREAD_TCP_TIMER_HANDLING_IMMEDIATE
} internal_thread_tcp_timer_handling_t;

static inline const char* internal_thread_tcp_timer_handling_str(internal_thread_tcp_timer_handling_t handling)
{
	switch (handling) { 
	case INTERNAL_THREAD_TCP_TIMER_HANDLING_DEFERRED: return "(deferred)";
	case INTERNAL_THREAD_TCP_TIMER_HANDLING_IMMEDIATE: return "(immediate)";
	default:					break;
	}
	return "unsupported";
}

namespace vma_spec {
	// convert str to vVMA_spec_t; upon error - returns the given 'def_value'
	vma_spec_t from_str(const char* str, vma_spec_t def_value = MCE_SPEC_NONE);

	// convert int to vVMA_spec_t; upon error - returns the given 'def_value'
	vma_spec_t from_int(const int int_spec, vma_spec_t def_value = MCE_SPEC_NONE);

	const char * to_str(vma_spec_t level);
}

////////////////////////////////////////////////////////////////////////////////
class vma_exception_handling
{
public:

	static const char *getName() {
		return "Exception handling mode";
	}

	static const char *getSysVar() {
		return "VMA_EXCEPTION_HANDLING";
	}

	typedef enum {
		MODE_FIRST = -3,
		MODE_EXIT = -2,
		MODE_DEBUG = -1,
		MODE_UNOFFLOAD = 0,
		MODE_LOG_ERROR,
		MODE_RETURN_ERROR,
		MODE_ABORT,
		MODE_LAST,

		MODE_DEFAULT = MODE_DEBUG
	} mode;

	const char* to_str()
	{
		switch (m_mode) {
		case MODE_EXIT:         return "(exit on failed startup)";
		case MODE_DEBUG:        return "(just log debug message)";
		case MODE_UNOFFLOAD:    return "(log debug and un-offload)";
		case MODE_LOG_ERROR:    return "(log error and un-offload)";
		case MODE_RETURN_ERROR: return "(Log Error and return error)";
		case MODE_ABORT:        return "(Log error and Abort!)";
		default:				break;
		}
		return "unsupported";
	}

	bool is_suit_un_offloading() {
		return m_mode ==  MODE_UNOFFLOAD || m_mode == MODE_LOG_ERROR;
	}

	vlog_levels_t get_log_severity() {
		switch (m_mode) {
		case MODE_EXIT:
		case MODE_DEBUG:
		case MODE_UNOFFLOAD:
			return VLOG_DEBUG;
		case MODE_LOG_ERROR:
		case MODE_RETURN_ERROR:
		case MODE_ABORT:
		default:
			return VLOG_ERROR;
		}
	}

	//
	// cast constructors and cast operators
	//

	vma_exception_handling(mode _mode = MODE_DEFAULT) : m_mode(_mode) {
		if (m_mode >= MODE_LAST || m_mode <= MODE_FIRST)
			m_mode = MODE_DEFAULT;
	}

	explicit vma_exception_handling(int _mode) : m_mode((mode)_mode) {
		if (m_mode >= MODE_LAST || m_mode <= MODE_FIRST)
			m_mode = MODE_DEFAULT;
	}

	operator mode() const {
		return m_mode;
	}

private:
	mode m_mode;
};

////////////////////////////////////////////////////////////////////////////////
struct mce_sys_var {
	static mce_sys_var & instance() {
		static mce_sys_var the_instance; //singelton
		return the_instance;
	}

	void		get_env_params();

	char 		*app_name;
	char 		app_id[MAX_APP_ID_LENGHT];

	uint32_t 	mce_spec;
	uint32_t 	mce_spec_param1;
	uint32_t 	mce_spec_param2;

	vlog_levels_t 	log_level;
	uint32_t	log_details;
	char 		log_filename[PATH_MAX];
	char		stats_filename[PATH_MAX];
	char		stats_shmem_dirname[PATH_MAX];
	char 		conf_filename[PATH_MAX];
	bool		log_colors;
	bool 		handle_sigintr;
	bool		handle_segfault;
	uint32_t	stats_fd_num_max;

	ring_logic_t	ring_allocation_logic_tx;
	ring_logic_t	ring_allocation_logic_rx;
	int		ring_migration_ratio_tx;
	int		ring_migration_ratio_rx;
	int		ring_limit_per_interface;
	int		ring_dev_mem_tx;
	int		tcp_max_syn_rate;

	uint32_t 	tx_num_segs_tcp;
	uint32_t 	tx_num_bufs;
	uint32_t 	tx_num_wr;
	uint32_t	tx_num_wr_to_signal;
	uint32_t 	tx_max_inline;
	bool 		tx_mc_loopback_default;
	bool		tx_nonblocked_eagains;
	uint32_t	tx_prefetch_bytes;
	uint32_t        tx_bufs_batch_udp;
	uint32_t        tx_bufs_batch_tcp;

	uint32_t 	rx_num_bufs;
	uint32_t        rx_bufs_batch;
	uint32_t 	rx_num_wr;
	uint32_t	rx_num_wr_to_post_recv;
	int32_t		rx_poll_num;
	int32_t		rx_poll_num_init;
	uint32_t 	rx_udp_poll_os_ratio;
	ts_conversion_mode_t	hw_ts_conversion_mode;
	bool 		rx_sw_csum;
	uint32_t 	rx_poll_yield_loops;
	uint32_t 	rx_ready_byte_min_limit;
	uint32_t 	rx_prefetch_bytes;
	uint32_t 	rx_prefetch_bytes_before_poll;
	uint32_t	rx_cq_drain_rate_nsec;	// If enabled this will cause the Rx to drain all wce in CQ before returning to user, 
						// Else (Default: Disbaled) it will return when first ready packet is in socket queue
	uint32_t	rx_delta_tsc_between_cq_polls;

	uint32_t	gro_streams_max;

	bool		tcp_3t_rules;
	bool		eth_mc_l2_only_rules;
	bool		mc_force_flowtag;

	int32_t		select_poll_num;
	bool		select_poll_os_force;
	uint32_t	select_poll_os_ratio;
	uint32_t 	select_skip_os_fd_check;
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
	tcp_ctl_thread_t tcp_ctl_thread;
	tcp_ts_opt_t	tcp_ts_opt;
	bool		tcp_nodelay;
	bool		tcp_quickack;
	vma_exception_handling exception_handling;
	bool		avoid_sys_calls_on_tcp_fd;
	bool		allow_privileged_sock_opt;
	uint32_t	wait_after_join_msec;
	thread_mode_t	thread_mode;
	buffer_batching_mode_t buffer_batching_mode;
	alloc_mode_t	mem_alloc_type;
	bool		handle_fork;
	bool		close_on_dup2;
	uint32_t 	mtu;     /* effective MTU. If mtu==0 then auto calculate the MTU */
	uint32_t	lwip_cc_algo_mod;
	uint32_t 	lwip_mss;
	char		internal_thread_cpuset[FILENAME_MAX];
	char		internal_thread_affinity_str[FILENAME_MAX];
	cpu_set_t	internal_thread_affinity;
	bool		internal_thread_arm_cq_enabled;
	internal_thread_tcp_timer_handling_t internal_thread_tcp_timer_handling;	
	bool 		handle_bf;

	bool 		enable_ipoib;
	uint32_t	timer_netlink_update_msec;

	//Neigh parameters
	uint32_t 	neigh_uc_arp_quata;
	uint32_t	neigh_wait_till_send_arp_msec;
	uint32_t	neigh_num_err_retries;

	uint32_t 	vma_time_measure_num_samples;
	char 		vma_time_measure_filename[PATH_MAX];
	sysctl_reader_t & sysctl_reader;
	bool		rx_poll_on_tx_tcp;
	bool		is_hypervisor;
	bool		trigger_dummy_send_getsockname;

	bool cpuid_hv();

private:
	void print_vma_load_failure_msg();
	int list_to_cpuset(char *cpulist, cpu_set_t *cpu_set);
	int hex_to_cpuset(char *start, cpu_set_t *cpu_set);
	int env_to_cpuset(char *orig_start, cpu_set_t *cpu_set);
	void read_env_variable_with_pid(char* mce_sys_name, size_t mce_sys_max_size, char* env_ptr);
	bool check_cpuinfo_flag(const char* flag);
	const char* cpuid_hv_vendor();

	// prevent unautothrized creation of objects
	mce_sys_var () : sysctl_reader(sysctl_reader_t::instance()){
		// coverity[uninit_member]
		get_env_params();
	}
	mce_sys_var (const mce_sys_var &);
	mce_sys_var & operator= (const mce_sys_var &);


};
 
extern mce_sys_var & safe_mce_sys();

#define SYS_VAR_LOG_LEVEL				"VMA_TRACELEVEL"
#define SYS_VAR_LOG_DETAILS				"VMA_LOG_DETAILS"
#define SYS_VAR_LOG_FILENAME				"VMA_LOG_FILE"
#define SYS_VAR_STATS_FILENAME				"VMA_STATS_FILE"
#define SYS_VAR_STATS_SHMEM_DIRNAME			"VMA_STATS_SHMEM_DIR"
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
#define SYS_VAR_RING_DEV_MEM_TX                         "VMA_RING_DEV_MEM_TX"

#define SYS_VAR_TX_NUM_SEGS_TCP				"VMA_TX_SEGS_TCP"
#define SYS_VAR_TX_NUM_BUFS				"VMA_TX_BUFS"
#define SYS_VAR_TX_NUM_WRE				"VMA_TX_WRE"
#define SYS_VAR_TX_NUM_WRE_TO_SIGNAL			"VMA_TX_WRE_BATCHING"
#define SYS_VAR_TX_MAX_INLINE				"VMA_TX_MAX_INLINE"
#define SYS_VAR_TX_MC_LOOPBACK				"VMA_TX_MC_LOOPBACK"
#define SYS_VAR_TX_NONBLOCKED_EAGAINS			"VMA_TX_NONBLOCKED_EAGAINS"
#define SYS_VAR_TX_PREFETCH_BYTES			"VMA_TX_PREFETCH_BYTES"

#define SYS_VAR_RX_NUM_BUFS				"VMA_RX_BUFS"
#define SYS_VAR_RX_NUM_WRE				"VMA_RX_WRE"
#define SYS_VAR_RX_NUM_WRE_TO_POST_RECV			"VMA_RX_WRE_BATCHING"
#define SYS_VAR_RX_NUM_POLLS				"VMA_RX_POLL"
#define SYS_VAR_RX_NUM_POLLS_INIT			"VMA_RX_POLL_INIT"
#define SYS_VAR_RX_UDP_POLL_OS_RATIO			"VMA_RX_UDP_POLL_OS_RATIO"
#define SYS_VAR_RX_SW_CSUM				"VMA_RX_SW_CSUM"
#define SYS_VAR_HW_TS_CONVERSION_MODE			"VMA_HW_TS_CONVERSION"
// The following 2 params were replaced by VMA_RX_UDP_POLL_OS_RATIO
#define SYS_VAR_RX_POLL_OS_RATIO			"VMA_RX_POLL_OS_RATIO"
#define SYS_VAR_RX_SKIP_OS				"VMA_RX_SKIP_OS"
#define SYS_VAR_RX_POLL_YIELD				"VMA_RX_POLL_YIELD"
#define SYS_VAR_RX_BYTE_MIN_LIMIT			"VMA_RX_BYTES_MIN"
#define SYS_VAR_RX_PREFETCH_BYTES			"VMA_RX_PREFETCH_BYTES"
#define SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL		"VMA_RX_PREFETCH_BYTES_BEFORE_POLL"
#define SYS_VAR_RX_CQ_DRAIN_RATE_NSEC			"VMA_RX_CQ_DRAIN_RATE_NSEC"
#define SYS_VAR_GRO_STREAMS_MAX				"VMA_GRO_STREAMS_MAX"
#define SYS_VAR_TCP_3T_RULES				"VMA_TCP_3T_RULES"
#define SYS_VAR_ETH_MC_L2_ONLY_RULES			"VMA_ETH_MC_L2_ONLY_RULES"
#define SYS_VAR_MC_FORCE_FLOWTAG			"VMA_MC_FORCE_FLOWTAG"

#define SYS_VAR_SELECT_CPU_USAGE_STATS			"VMA_CPU_USAGE_STATS"
#define SYS_VAR_SELECT_NUM_POLLS			"VMA_SELECT_POLL"
#define SYS_VAR_SELECT_POLL_OS_FORCE			"VMA_SELECT_POLL_OS_FORCE"
#define SYS_VAR_SELECT_POLL_OS_RATIO			"VMA_SELECT_POLL_OS_RATIO"
#define SYS_VAR_SELECT_SKIP_OS				"VMA_SELECT_SKIP_OS"

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
#define SYS_VAR_TCP_CTL_THREAD				"VMA_TCP_CTL_THREAD"
#define SYS_VAR_TCP_TIMESTAMP_OPTION			"VMA_TCP_TIMESTAMP_OPTION"
#define SYS_VAR_TCP_NODELAY				"VMA_TCP_NODELAY"
#define SYS_VAR_TCP_QUICKACK				"VMA_TCP_QUICKACK"
#define SYS_VAR_VMA_EXCEPTION_HANDLING			(vma_exception_handling::getSysVar())
#define SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD		"VMA_AVOID_SYS_CALLS_ON_TCP_FD"
#define SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT		"VMA_ALLOW_PRIVILEGED_SOCK_OPT"
#define SYS_VAR_WAIT_AFTER_JOIN_MSEC			"VMA_WAIT_AFTER_JOIN_MSEC"
#define SYS_VAR_THREAD_MODE				"VMA_THREAD_MODE"
#define SYS_VAR_BUFFER_BATCHING_MODE			"VMA_BUFFER_BATCHING_MODE"
#define SYS_VAR_HUGETBL					"VMA_HUGETBL"
#define SYS_VAR_MEM_ALLOC_TYPE				"VMA_MEM_ALLOC_TYPE"
#define SYS_VAR_FORK					"VMA_FORK"
#define SYS_VAR_BF					"VMA_BF"
#define SYS_VAR_CLOSE_ON_DUP2				"VMA_CLOSE_ON_DUP2"
#define SYS_VAR_MTU					"VMA_MTU"
#define SYS_VAR_TCP_MAX_SYN_RATE			"VMA_TCP_MAX_SYN_RATE"
#define SYS_VAR_MSS					"VMA_MSS"
#define SYS_VAR_TCP_CC_ALGO				"VMA_TCP_CC_ALGO"
#define SYS_VAR_SPEC					"VMA_SPEC"
#define SYS_VAR_SPEC_PARAM1				"VMA_SPEC_PARAM1"
#define SYS_VAR_SPEC_PARAM2				"VMA_SPEC_PARAM2"

#define SYS_VAR_IPOIB					"VMA_IPOIB"

#define SYS_VAR_INTERNAL_THREAD_AFFINITY		"VMA_INTERNAL_THREAD_AFFINITY"
#define SYS_VAR_INTERNAL_THREAD_CPUSET			"VMA_INTERNAL_THREAD_CPUSET"
#define SYS_VAR_INTERNAL_THREAD_ARM_CQ			"VMA_INTERNAL_THREAD_ARM_CQ"
#define SYS_VAR_INTERNAL_THREAD_TCP_TIMER_HANDLING	"VMA_INTERNAL_THREAD_TCP_TIMER_HANDLING"

#define SYS_VAR_NETLINK_TIMER_MSEC			"VMA_NETLINK_TIMER"

#define SYS_VAR_NEIGH_UC_ARP_QUATA			"VMA_NEIGH_UC_ARP_QUATA"
#define SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC			"VMA_NEIGH_UC_ARP_DELAY_MSEC"
#define SYS_VAR_NEIGH_NUM_ERR_RETRIES			"VMA_NEIGH_NUM_ERR_RETRIES"

#define SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES		"VMA_TIME_MEASURE_NUM_SAMPLES"
#define SYS_VAR_VMA_TIME_MEASURE_DUMP_FILE		"VMA_TIME_MEASURE_DUMP_FILE"
#define SYS_VAR_VMA_RX_POLL_ON_TX_TCP			"VMA_RX_POLL_ON_TX_TCP"
#define SYS_VAR_VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME	"VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME"

#define MCE_DEFAULT_LOG_FILE				("")
#define MCE_DEFAULT_CONF_FILE				("/etc/libvma.conf")
#define MCE_DEFAULT_STATS_FILE				("")
#define MCE_DEFAULT_STATS_SHMEM_DIR			("/tmp/")
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
#define MCE_DEFAULT_RING_DEV_MEM_TX                     (0)
#define MCE_DEFAULT_TCP_MAX_SYN_RATE                	(0)
#define MCE_DEFAULT_TX_NUM_SEGS_TCP			(1000000)
#define MCE_DEFAULT_TX_NUM_BUFS				(200000)
#define MCE_DEFAULT_TX_NUM_WRE				(2048)
#define MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL		(64)
#define MCE_DEFAULT_TX_MAX_INLINE			(204) //+18(always inline ETH header) = 222
#define MCE_DEFAULT_TX_BUILD_IP_CHKSUM			(true)
#define MCE_DEFAULT_TX_MC_LOOPBACK			(true)
#define MCE_DEFAULT_TX_NONBLOCKED_EAGAINS		(false)
#define MCE_DEFAULT_TX_PREFETCH_BYTES			(256)
#define MCE_DEFAULT_TX_BUFS_BATCH_UDP			(8)
#define MCE_DEFAULT_TX_BUFS_BATCH_TCP			(16)
#define MCE_DEFAULT_TX_NUM_SGE				(2)
#define MCE_DEFAULT_RX_NUM_BUFS				(200000)
#define MCE_DEFAULT_RX_BUFS_BATCH			(64)
#ifdef DEFINED_SOCKETXTREME
#define MCE_DEFAULT_RX_NUM_WRE				(1024)
#else
#define MCE_DEFAULT_RX_NUM_WRE				(16000)
#endif // DEFINED_SOCKETXTREME
#define MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV		(64)
#define MCE_DEFAULT_RX_NUM_SGE				(1)
#define MCE_DEFAULT_RX_NUM_POLLS			(100000)
#define MCE_DEFAULT_RX_NUM_POLLS_INIT			(0)
#define MCE_DEFAULT_RX_UDP_POLL_OS_RATIO		(100)
#define MCE_DEFAULT_HW_TS_CONVERSION_MODE		(TS_CONVERSION_MODE_SYNC)
#define MCE_DEFUALT_RX_SW_CSUM				(true)
#define MCE_DEFAULT_RX_POLL_YIELD			(0)
#define MCE_DEFAULT_RX_BYTE_MIN_LIMIT			(65536)
#define MCE_DEFAULT_RX_PREFETCH_BYTES			(256)
#define MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL	(0)
#define MCE_DEFAULT_RX_CQ_DRAIN_RATE			(MCE_RX_CQ_DRAIN_RATE_DISABLED)
#ifdef DEFINED_SOCKETXTREME
#define MCE_DEFAULT_GRO_STREAMS_MAX			(0)
#else
#define MCE_DEFAULT_GRO_STREAMS_MAX			(32)
#endif // DEFINED_SOCKETXTREME
#define MCE_DEFAULT_TCP_3T_RULES			(false)
#define MCE_DEFAULT_ETH_MC_L2_ONLY_RULES		(false)
#define MCE_DEFAULT_MC_FORCE_FLOWTAG			(false)
#define MCE_DEFAULT_SELECT_NUM_POLLS			(100000)
#define MCE_DEFAULT_SELECT_POLL_OS_FORCE		(0)
#define MCE_DEFAULT_SELECT_POLL_OS_RATIO		(10)
#define MCE_DEFAULT_SELECT_SKIP_OS			(4)
#define MCE_DEFAULT_SELECT_CPU_USAGE_STATS		(false)

#ifdef DEFINED_IBV_EXP_CQ_MODERATION
#define MCE_DEFAULT_CQ_MODERATION_ENABLE               (true)
#else
#define MCE_DEFAULT_CQ_MODERATION_ENABLE               (false)
#endif
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
#define MCE_DEFAULT_TCP_CTL_THREAD			(CTL_THREAD_DISABLE)
#define MCE_DEFAULT_TCP_TIMESTAMP_OPTION		(TCP_TS_OPTION_DISABLE)
#define MCE_DEFAULT_TCP_NODELAY 			(false)
#define MCE_DEFAULT_TCP_QUICKACK			(false)
#define MCE_DEFAULT_VMA_EXCEPTION_HANDLING	(vma_exception_handling::MODE_DEFAULT)
#define MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD		(false)
#define MCE_DEFAULT_ALLOW_PRIVILEGED_SOCK_OPT		(true)
#define MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC		(0)
#define MCE_DEFAULT_THREAD_MODE				(THREAD_MODE_MULTI)
#define MCE_DEFAULT_BUFFER_BATCHING_MODE		(BUFFER_BATCHING_WITH_RECLAIM)
#ifndef VMA_IBV_ACCESS_ALLOCATE_MR
#define MCE_DEFAULT_MEM_ALLOC_TYPE			(ALLOC_TYPE_HUGEPAGES)
#else
#define MCE_DEFAULT_MEM_ALLOC_TYPE			(ALLOC_TYPE_CONTIG)
#endif
#define MCE_DEFAULT_FORK_SUPPORT			(true)
#define MCE_DEFAULT_BF_FLAG				(true)
#define MCE_DEFAULT_CLOSE_ON_DUP2			(true)
#define MCE_DEFAULT_MTU					(0)
#define MCE_DEFAULT_MSS					(0)
#define MCE_DEFAULT_LWIP_CC_ALGO_MOD			(0)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY		(-1)
#define MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR	("-1")
#define MCE_DEFAULT_INTERNAL_THREAD_CPUSET		("")
#define MCE_DEFAULT_INTERNAL_THREAD_TCP_TIMER_HANDLING	(INTERNAL_THREAD_TCP_TIMER_HANDLING_DEFERRED)
#define MCE_DEFAULT_NETLINK_TIMER_MSEC			(10000)

#define MCE_DEFAULT_NEIGH_UC_ARP_QUATA			3
#define MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC		10000
#define MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES		1

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
#define MCE_DEFAULT_RX_POLL_ON_TX_TCP			(false)
#define MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME	(false)

#define MCE_ALIGNMENT					((unsigned long)63)
#define RX_BUF_SIZE(mtu)				(mtu + IPOIB_HDR_LEN + GRH_HDR_LEN) // RX buffers are larger in IB
#define TX_BUF_SIZE(mtu)				(mtu + ETH_HDR_LEN) // Tx buffers are larger in Ethernet (they include L2 for RAW QP)
#define NUM_TX_WRE_TO_SIGNAL_MAX			64
#define NUM_RX_WRE_TO_POST_RECV_MAX			1024
#define TCP_MAX_SYN_RATE_TOP_LIMIT			100000
#define DEFAULT_MC_TTL					64
#define IFTYPE_PARAM_FILE				"/sys/class/net/%s/type"
#define IFADDR_MTU_PARAM_FILE				"/sys/class/net/%s/mtu"
#define UMCAST_PARAM_FILE				"/sys/class/net/%s/umcast"
#define IPOIB_MODE_PARAM_FILE				"/sys/class/net/%s/mode"
#define VERBS_DEVICE_PORT_PARAM_FILE			"/sys/class/net/%s/dev_port"
#define VERBS_DEVICE_ID_PARAM_FILE			"/sys/class/net/%s/dev_id"
#define BONDING_MODE_PARAM_FILE				"/sys/class/net/%s/bonding/mode"
#define BONDING_SLAVES_PARAM_FILE			"/sys/class/net/%s/bonding/slaves"
#define BONDING_ACTIVE_SLAVE_PARAM_FILE			"/sys/class/net/%s/bonding/active_slave"
#define BONDING_FAILOVER_MAC_PARAM_FILE			"/sys/class/net/%s/bonding/fail_over_mac"
#define BONDING_XMIT_HASH_POLICY_PARAM_FILE		"/sys/class/net/%s/bonding/xmit_hash_policy"
/* BONDING_SLAVE_STATE_PARAM_FILE is for kernel  > 3.14 or RH7.2 and higher */
#define BONDING_SLAVE_STATE_PARAM_FILE			"/sys/class/net/%s/bonding_slave/state"
#define L2_ADDR_FILE_FMT                                "/sys/class/net/%.*s/address"
#define L2_BR_ADDR_FILE_FMT                                   "/sys/class/net/%.*s/broadcast"
#define OPER_STATE_PARAM_FILE				"/sys/class/net/%s/operstate"
#define RAW_QP_PRIVLIGES_PARAM_FILE			"/sys/module/ib_uverbs/parameters/disable_raw_qp_enforcement"
#define FLOW_STEERING_MGM_ENTRY_SIZE_PARAM_FILE		"/sys/module/mlx4_core/parameters/log_num_mgm_entry_size"
#define VIRTUAL_DEVICE_FOLDER			"/sys/devices/virtual/net/%s/"
#define BOND_DEVICE_FILE				"/proc/net/bonding/%s"


#define NETVSC_DEVICE_CLASS_FILE		"/sys/class/net/%s/device/class_id"
#define NETVSC_DEVICE_LOWER_FILE		"/sys/class/net/%s/lower_%s/ifindex"
#define NETVSC_DEVICE_UPPER_FILE		"/sys/class/net/%s/upper_%s/ifindex"
#define NETVSC_ID               		"{f8615163-df3e-46c5-913f-f2d2f965ed0e}\n"

#define MAX_STATS_FD_NUM				1024
#define MAX_WINDOW_SCALING				14

#define VIRTUALIZATION_FLAG				"hypervisor"

extern bool g_b_exit;
extern bool g_is_forked_child;
extern bool g_init_global_ctors_done;

#endif
