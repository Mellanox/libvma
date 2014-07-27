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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <mcheck.h>
#include <execinfo.h>
#include <libgen.h>
#include <linux/igmp.h>

#include "vlogger/vlogger.h"
#include "vma/util/rdtsc.h"
#include "vma/util/verbs_extra.h"
#include "vma/util/vma_stats.h"
#include "vma/util/utils.h"
#include "vma/event/event_handler_manager.h"
#include "vma/event/vlogger_timer_handler.h"
#include "vma/dev/buffer_pool.h"
#include "vma/dev/ib_ctx_handler_collection.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/proto/ip_frag.h"
#include "vma/proto/vma_lwip.h"
#include "vma/proto/route_table_mgr.h"
#include "vma/proto/rule_table_mgr.h"
#include "vma/proto/igmp_mgr.h"

#include "vma/proto/neighbour_table_mgr.h"
#include "vma/netlink/netlink_wrapper.h"
#include "vma/event/command.h"

#include "vma/sock/sock-redirect.h"
#include "vma/sock/fd_collection.h"
#include "vma/sock/sockinfo_tcp.h"
#include "vma/sock/sockinfo_udp.h"
#include "vma/iomux/io_mux_call.h"

#include "vma/util/instrumentation.h"

void check_netperf_flags();


// Start of vma_version_str - used in "$ strings libvma.so | grep VMA_VERSION"
#define STR_EXPAND(x) #x
#define STR(x) STR_EXPAND(x)
const char *vma_version_str = "VMA_VERSION: " PACKAGE_VERSION "-" STR(VMA_LIBRARY_RELEASE)

#if _BullseyeCoverage
			      " Bullseye"
#endif
#ifdef VMA_SVN_REVISION
			      " Release"
#else
			      " Development Snapshot"
#endif

			      " built on "
#ifdef VMA_DATE_TIME
			      VMA_DATE_TIME
#else
			      __DATE__ " " __TIME__
#endif

#ifdef _DEBUG
			      " -*- DEBUG -*-"
#endif
			      ;	// End of vma_version_str - used in "$ strings libvma.so | grep VMA_VERSION"


struct mce_sys_var mce_sys;
bool g_handle_iperf = false;
bool g_b_exit = false;
bool g_init_ibv_fork_done = false;
bool g_is_forked_child = false;
bool g_init_global_ctors_done = true;

#define MAX_BACKTRACE		25
#define MAX_VERSION_STR_LEN	128
#define MAX_CMD_LINE		2048

static void handle_segfault(int)
{
	vlog_printf(VLOG_ERROR, "Segmentation Fault\n");
	printf_backtrace();

	kill(getpid(), SIGKILL);
}

int list_to_cpuset(char *cpulist, cpu_set_t *cpu_set)
{
	char comma[] = ",";
	char dash[] = "-";
	char *comma_saveptr, *dash_saveptr;

	char *token, *subtoken, *endptr;
	int range_start, range_end;
	int i;

	CPU_ZERO(cpu_set);
	
	/*
	 * When passed a CPU list, we expect comma(',') delimited values.
	 */
	token = strtok_r(cpulist, comma, &comma_saveptr);
	if (!token) {
		return -1;
	}

	/*
	 * For each comma delimited value we need to parse the token based 
	 * on a dash('-') to see if we are dealing with a single cpu digit 
	 * or a range.
	 */
	while (token) {

		subtoken = strtok_r(token, dash, &dash_saveptr);
		if (!subtoken) {
			return -1;
		}

		while (subtoken) {

			errno = 0;
			range_start = strtol(subtoken, &endptr, 10);
			if ( (!range_start && *endptr) || errno) {
				return -1;
			}

			/*
			 * Here we assume that if we get a second subtoken
			 * then we must be processing a range.
			 */
			subtoken = strtok_r(NULL, dash, &dash_saveptr);
			if (subtoken) {
				errno = 0;
				range_end = strtol(subtoken, &endptr, 10);
				if ( (!range_end && *endptr) || errno) {
					return -1;
				}
				subtoken = NULL; 
			} else {
				range_end = range_start;
			}

			for (i = range_start; i <= range_end; i++) {
				if (i > (CPU_SETSIZE-1)) {
					return -1;
				} else {
					CPU_SET(i,cpu_set);
				}
			}
		}

		token = strtok_r(NULL, comma, &comma_saveptr);
	}

        return 0;

}

int hex_to_cpuset(char *start, cpu_set_t *cpu_set)
{
	const char *end;
	char hexc[2];
	int i, length, digit;
	int bit = 0, set_one = 0;

	/*
	 * The least significant bits are at the end of the
	 * string, so we need to start our processing at the
	 * last character and work our way back to the start.
	 */
        length = strlen(start);
        end = start + (length - 1);

        CPU_ZERO(cpu_set);
        while (length) {

		*hexc = *end;
		*(hexc+1) = 0; // NULL terminate the string or strtol can be buggy.
		if (!isxdigit(*hexc)) {
                        return -1;
		}

		digit = strtol(hexc, NULL, 16);

		/*
		 * Each hex digit is 4 bits. For each bit set per
		 * in the hex value set the corresponding CPU number
		 * in the cpu_set.  
		 * 
		 * Since we are working on a single hex digit in a string
		 * of unknown length we need to keep a running bit counter
		 * so we don't lose track of our progress.
		 */
		for (i = 0; i < 4; i++)
		{
			if (digit & (1 << i)) {
				if (bit > (CPU_SETSIZE-1)) {
					return -1;
				} else {
					CPU_SET(bit,cpu_set);
					set_one++;
				}
			}
			
			bit++;
		}

		/* move the end pointer back a character */
		end--;

		/* one less character to process */
                length--;
        }

	/*
	 * passing all 0's is not legal.  if no bits were set
	 * and we make it to the end of the function then return
	 * failure.
	 */
	if (!set_one) {
		return -1;
	} else {
        	return 0;
	}

}

int env_to_cpuset(char *orig_start, cpu_set_t *cpu_set)
{
	int ret;
        char* start = strdup(orig_start); // save the caller string from strtok destruction.

	/*
	 * We expect a hex number or comma delimited cpulist.  Check for 
	 * starting characters of "0x" or "0X" and if present then parse
	 * the string as a hexidecimal value, otherwise treat it as a 
	 * cpulist.
	 */
	if ((start[0] == '0') &&
		((start[1] == 'x') || (start[1] == 'X'))) {
		ret = hex_to_cpuset(start+2, cpu_set);
	}
	else {
		ret = list_to_cpuset(start, cpu_set);
	}

	free(start);
	return ret;
}

void check_locked_mem()
{
	struct rlimit rlim;
	if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 && rlim.rlim_max != RLIM_INFINITY) {
		vlog_printf(VLOG_WARNING, "************************************************************************\n");
		vlog_printf(VLOG_WARNING, "Your current max locked memory is: %ld. Please change it to unlimited.\n", rlim.rlim_max);
		vlog_printf(VLOG_WARNING, "Set this user's default to `ulimit -l unlimited`.\n");
		vlog_printf(VLOG_WARNING, "Read more about this topic in the VMA's User Manual.\n");
		vlog_printf(VLOG_WARNING, "************************************************************************\n");
	}
}

void check_debug()
{
	if (mce_sys.log_level >= VLOG_DEBUG) {
		vlog_printf(VLOG_WARNING, "*************************************************************\n");
		vlog_printf(VLOG_WARNING, "* VMA is currently configured with high log level           *\n");
		vlog_printf(VLOG_WARNING, "* Application performance will decrease in this log level!  *\n");
		vlog_printf(VLOG_WARNING, "* This log level is recommended for debugging purposes only *\n");
		vlog_printf(VLOG_WARNING, "*************************************************************\n");
	}
}

void check_flow_steering_log_num_mgm_entry_size()
{
	char flow_steering_val[2] = {0};
	if (priv_read_file((const char*)FLOW_STEERING_MGM_ENTRY_SIZE_PARAM_FILE, flow_steering_val, 2) == -1) {
		vlog_printf(VLOG_DEBUG, "Flow steering option does not exist in current OFED version");
	}
	else if (flow_steering_val[0] != '-' || flow_steering_val[1] != '1') {
		vlog_printf(VLOG_WARNING, "***************************************************************************************\n");
		vlog_printf(VLOG_WARNING, "* VMA will not operate properly while flow steering option is disabled!               *\n");
		vlog_printf(VLOG_WARNING, "* Please restart your VMA applications after running the following:                   *\n");
		vlog_printf(VLOG_WARNING, "* WARNING: the following steps will restart your network interface!                   *\n");
		vlog_printf(VLOG_WARNING, "* 1. \"echo options mlx4_core log_num_mgm_entry_size=-1 > /etc/modprobe.d/mlnx.conf\" *\n");
		vlog_printf(VLOG_WARNING, "* 2. \"/etc/init.d/openibd restart\"                                                  *\n");
		vlog_printf(VLOG_WARNING, "* Read more about the Flow Steering support in the VMA's User Manual                  *\n");
		vlog_printf(VLOG_WARNING, "***************************************************************************************\n");
	}
}

const char* thread_mode_str(thread_mode_t thread_mode)
{
	switch (thread_mode) {
	case THREAD_MODE_SINGLE:		return "Single";
	case THREAD_MODE_MULTI:			return "Multi spin lock";
	case THREAD_MODE_MUTEX:			return "Multi mutex lock";
	case THREAD_MODE_PLENTY:		return "Multi more threads than cores";
	default:				break;
	}
	return "";
}

#define FORMAT_NUMBER		"%-30s %-26d [%s]\n"
#define FORMAT_STRING		"%-30s %-26s [%s]\n"
#define FORMAT_NUMSTR		"%-30s %-2d%-24s [%s]\n"


#define VLOG_STR_PARAM_DETAILS(param_val, param_def_val, args...)						\
	do {	                                 								\
		if (param_val && strcmp(param_val, param_def_val))	{							\
			vlog_printf(VLOG_INFO, ##args);								\
		}												\
		else {												\
			vlog_printf(VLOG_DEBUG, ##args);							\
		}												\
	} while (0);

#define VLOG_NUM_PARAM_DETAILS(param_val, param_def_val, args...)							\
	do {	                                 								\
		if (param_val != param_def_val)	{								\
			vlog_printf(VLOG_INFO, ##args);								\
		}												\
		else {												\
			vlog_printf(VLOG_DEBUG, ##args);							\
		}												\
	} while (0);

#define VLOG_STR_PARAM_STRING(param_desc, param_val, param_def_val, param_name, val_desc_str)			\
	VLOG_STR_PARAM_DETAILS (param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str, param_name)  \

#define VLOG_PARAM_NUMBER(param_desc, param_val, param_def_val, param_name)					\
	VLOG_NUM_PARAM_DETAILS (param_val, param_def_val, FORMAT_NUMBER, param_desc, param_val, param_name)

#define VLOG_PARAM_STRING(param_desc, param_val, param_def_val, param_name, val_desc_str)			\
	VLOG_NUM_PARAM_DETAILS (param_val, param_def_val, FORMAT_STRING, param_desc, val_desc_str, param_name)

#define VLOG_PARAM_NUMSTR(param_desc, param_val, param_def_val, param_name, val_desc_str)			\
	VLOG_NUM_PARAM_DETAILS (param_val, param_def_val, FORMAT_NUMSTR, param_desc, param_val, val_desc_str, param_name)

int get_ofed_version_info(char* ofed_version_str, int len)
{
	return run_and_retreive_system_command("ofed_info -s 2>/dev/null | grep OFED | head -1", ofed_version_str, len);
}


void print_vma_global_settings()
{
	struct utsname sys_info;
	time_t clock = time(NULL);
	char ofed_version_info[MAX_VERSION_STR_LEN];
	
	vlog_printf(VLOG_INFO,"---------------------------------------------------------------------------\n");
	vlog_printf(VLOG_INFO,"%s\n", vma_version_str);
	vlog_printf(VLOG_INFO,"Cmd Line: %s\n", mce_sys.app_name);

	// Use DEBUG level logging with more details in RPM release builds
	vlog_levels_t log_level = VLOG_DEBUG;
#ifndef VMA_SVN_REVISION
	// If non RPM (development builds) use more verbosity
	log_level = VLOG_INFO;
#endif
	vlog_printf(log_level,"Current Time: %s", ctime(&clock));
	vlog_printf(log_level,"Pid: %5u\n", getpid());

	if (!get_ofed_version_info(ofed_version_info, MAX_VERSION_STR_LEN))
		vlog_printf(VLOG_INFO,"OFED Version: %s", ofed_version_info);

	if (!uname(&sys_info)) {
		vlog_printf(VLOG_DEBUG,"System: %s\n", sys_info.release);
		vlog_printf(log_level,"Architecture: %s\n", sys_info.machine);
		vlog_printf(log_level,"Node: %s\n", sys_info.nodename);
	}

	vlog_printf(log_level,"---------------------------------------------------------------------------\n");

	switch (mce_sys.mce_spec) {
	case MCE_SPEC_29WEST_LBM_29:
		vlog_printf(VLOG_INFO, " 29West LBM Logic Spec\n");
		break;
	case MCE_SPEC_WOMBAT_FH_LBM_554:
		vlog_printf(VLOG_INFO, " Wombat FH LBM Logic Spec\n");
		break;
	case MCE_SPEC_RTI_784:
		vlog_printf(VLOG_INFO, " RTI Logic Spec\n");
		break;
	case MCE_SPEC_MCD_623:
		vlog_printf(VLOG_INFO, " Memcached Logic Spec\n");
		break;
	case MCE_SPEC_MCD_IRQ_624:
		vlog_printf(VLOG_INFO, " Memcached Interrupt Mode Logic Spec\n");
		break;
	default:
		break;
	}
	if (mce_sys.mce_spec != 0) {
		vlog_printf(VLOG_INFO, FORMAT_NUMBER, "Spec", mce_sys.mce_spec, SYS_VAR_SPEC);

		if (mce_sys.mce_spec == MCE_SPEC_29WEST_LBM_29 || mce_sys.mce_spec == MCE_SPEC_WOMBAT_FH_LBM_554) {
			vlog_printf(VLOG_INFO, FORMAT_NUMBER, "Param 1:", mce_sys.mce_spec_param1, SYS_VAR_SPEC_PARAM1);
			vlog_printf(VLOG_INFO, FORMAT_NUMBER, "Param 2:", mce_sys.mce_spec_param2, SYS_VAR_SPEC_PARAM2);
		}
		vlog_printf(VLOG_INFO,"---------------------------------------------------------------------------\n");
	}
	vlog_printf(VLOG_INFO, FORMAT_NUMBER, "Log Level", mce_sys.log_level, SYS_VAR_LOG_LEVEL);
	VLOG_PARAM_NUMBER("Log Details", mce_sys.log_details, MCE_DEFAULT_LOG_DETAILS, SYS_VAR_LOG_DETAILS);
	VLOG_PARAM_STRING("Log Colors", mce_sys.log_colors, MCE_DEFAULT_LOG_COLORS, SYS_VAR_LOG_COLORS, mce_sys.log_colors ? "Enabled " : "Disabled");
	VLOG_STR_PARAM_STRING("Log File", mce_sys.log_filename, MCE_DEFAULT_LOG_FILE, SYS_VAR_LOG_FILENAME, mce_sys.log_filename);
	VLOG_STR_PARAM_STRING("Stats File", mce_sys.stats_filename, MCE_DEFAULT_STATS_FILE, SYS_VAR_STATS_FILENAME, mce_sys.stats_filename);
	VLOG_PARAM_NUMBER("Stats FD Num (max)", mce_sys.stats_fd_num_max, MCE_DEFAULT_STATS_FD_NUM, SYS_VAR_STATS_FD_NUM);
	VLOG_STR_PARAM_STRING("Conf File", mce_sys.conf_filename, MCE_DEFAULT_CONF_FILE, SYS_VAR_CONF_FILENAME, mce_sys.conf_filename);
	VLOG_STR_PARAM_STRING("Application ID", mce_sys.app_id, MCE_DEFAULT_APP_ID, SYS_VAR_APPLICATION_ID, mce_sys.app_id);
	VLOG_PARAM_STRING("Polling CPU idle usage", mce_sys.select_handle_cpu_usage_stats, MCE_DEFAULT_SELECT_CPU_USAGE_STATS, SYS_VAR_SELECT_CPU_USAGE_STATS, mce_sys.select_handle_cpu_usage_stats ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("SigIntr Ctrl-C Handle", mce_sys.handle_sigintr, MCE_DEFAULT_HANDLE_SIGINTR, SYS_VAR_HANDLE_SIGINTR, mce_sys.handle_sigintr ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("SegFault Backtrace", mce_sys.handle_segfault, MCE_DEFAULT_HANDLE_SIGFAULT, SYS_VAR_HANDLE_SIGSEGV, mce_sys.handle_segfault ? "Enabled " : "Disabled");


	VLOG_PARAM_NUMSTR("Ring allocation logic TX", mce_sys.ring_allocation_logic_tx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX, SYS_VAR_RING_ALLOCATION_LOGIC_TX, ring_logic_str(mce_sys.ring_allocation_logic_tx));
	VLOG_PARAM_NUMSTR("Ring allocation logic RX", mce_sys.ring_allocation_logic_rx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX, SYS_VAR_RING_ALLOCATION_LOGIC_RX, ring_logic_str(mce_sys.ring_allocation_logic_rx));

	VLOG_PARAM_NUMBER("Ring migration ratio TX", mce_sys.ring_migration_ratio_tx, MCE_DEFAULT_RING_MIGRATION_RATIO_TX, SYS_VAR_RING_MIGRATION_RATIO_TX);
	VLOG_PARAM_NUMBER("Ring migration ratio RX", mce_sys.ring_migration_ratio_rx, MCE_DEFAULT_RING_MIGRATION_RATIO_RX, SYS_VAR_RING_MIGRATION_RATIO_RX);

	if (mce_sys.ring_limit_per_interface) {
		VLOG_PARAM_NUMBER("Ring limit per interface", mce_sys.ring_limit_per_interface, MCE_DEFAULT_RING_LIMIT_PER_INTERFACE, SYS_VAR_RING_LIMIT_PER_INTERFACE);
	}else {
		VLOG_PARAM_NUMSTR("Ring limit per interface", mce_sys.ring_limit_per_interface, MCE_DEFAULT_RING_LIMIT_PER_INTERFACE, SYS_VAR_RING_LIMIT_PER_INTERFACE, "(no limit)");
	}

	VLOG_PARAM_NUMBER("Tx Mem Segs TCP", mce_sys.tx_num_segs_tcp, MCE_DEFAULT_TX_NUM_SEGS_TCP, SYS_VAR_TX_NUM_SEGS_TCP);
	VLOG_PARAM_NUMBER("Tx Mem Bufs", mce_sys.tx_num_bufs, MCE_DEFAULT_TX_NUM_BUFS, SYS_VAR_TX_NUM_BUFS);
	VLOG_PARAM_NUMBER("Tx QP WRE", mce_sys.tx_num_wr, MCE_DEFAULT_TX_NUM_WRE, SYS_VAR_TX_NUM_WRE);
	VLOG_PARAM_NUMBER("Tx Max QP INLINE", mce_sys.tx_max_inline, MCE_DEFAULT_TX_MAX_INLINE, SYS_VAR_TX_MAX_INLINE);
	VLOG_PARAM_STRING("Tx MC Loopback", mce_sys.tx_mc_loopback_default, MCE_DEFAULT_TX_MC_LOOPBACK, SYS_VAR_TX_MC_LOOPBACK, mce_sys.tx_mc_loopback_default ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("Tx non-blocked eagains", mce_sys.tx_nonblocked_eagains, MCE_DEFAULT_TX_NONBLOCKED_EAGAINS, SYS_VAR_TX_NONBLOCKED_EAGAINS, mce_sys.tx_nonblocked_eagains ? "Enabled " : "Disabled");
	VLOG_PARAM_NUMBER("Tx Prefetch Bytes", mce_sys.tx_prefetch_bytes, MCE_DEFAULT_TX_PREFETCH_BYTES, SYS_VAR_TX_PREFETCH_BYTES);
	VLOG_PARAM_NUMBER("Tx backlog max", mce_sys.tx_backlog_max, MCE_DEFAULT_TX_BACKLOG_MAX, SYS_VAR_TX_BACKLOG_MAX);

	VLOG_PARAM_NUMBER("Rx Mem Bufs", mce_sys.rx_num_bufs, MCE_DEFAULT_RX_NUM_BUFS, SYS_VAR_RX_NUM_BUFS);
	VLOG_PARAM_NUMBER("Rx QP WRE", mce_sys.rx_num_wr, MCE_DEFAULT_RX_NUM_WRE, SYS_VAR_RX_NUM_WRE);
	VLOG_PARAM_NUMBER("Rx QP WRE BATCHING", mce_sys.rx_num_wr_to_post_recv, MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV, SYS_VAR_RX_NUM_WRE_TO_POST_RECV);
	VLOG_PARAM_NUMBER("Rx Byte Min Limit", mce_sys.rx_ready_byte_min_limit, MCE_DEFAULT_RX_BYTE_MIN_LIMIT, SYS_VAR_RX_BYTE_MIN_LIMIT);
	VLOG_PARAM_NUMBER("Rx Poll Loops", mce_sys.rx_poll_num, MCE_DEFAULT_RX_NUM_POLLS, SYS_VAR_RX_NUM_POLLS);
	VLOG_PARAM_NUMBER("Rx Poll Init Loops", mce_sys.rx_poll_num_init, MCE_DEFAULT_RX_NUM_POLLS_INIT, SYS_VAR_RX_NUM_POLLS_INIT);
	if (mce_sys.rx_udp_poll_os_ratio) {
		VLOG_PARAM_NUMBER("Rx UDP Poll OS Ratio", mce_sys.rx_udp_poll_os_ratio, MCE_DEFAULT_RX_UDP_POLL_OS_RATIO, SYS_VAR_RX_UDP_POLL_OS_RATIO);
	}
	else {
		VLOG_PARAM_STRING("Rx UDP Poll OS Ratio", mce_sys.rx_udp_poll_os_ratio, MCE_DEFAULT_RX_UDP_POLL_OS_RATIO, SYS_VAR_RX_UDP_POLL_OS_RATIO, "Disabled");
	}
	if (mce_sys.rx_poll_yield_loops) {
		VLOG_PARAM_NUMBER("Rx Poll Yield", mce_sys.rx_poll_yield_loops, MCE_DEFAULT_RX_POLL_YIELD, SYS_VAR_RX_POLL_YIELD);
	}
	else {
		VLOG_PARAM_STRING("Rx Poll Yield", mce_sys.rx_poll_yield_loops, MCE_DEFAULT_RX_POLL_YIELD, SYS_VAR_RX_POLL_YIELD, "Disabled");
	}
	VLOG_PARAM_NUMBER("Rx Prefetch Bytes", mce_sys.rx_prefetch_bytes, MCE_DEFAULT_RX_PREFETCH_BYTES, SYS_VAR_RX_PREFETCH_BYTES);

	VLOG_PARAM_NUMBER("Rx Prefetch Bytes Before Poll", mce_sys.rx_prefetch_bytes_before_poll, MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL, SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL);

	if (mce_sys.rx_cq_drain_rate_nsec == MCE_RX_CQ_DRAIN_RATE_DISABLED) {
		VLOG_PARAM_STRING("Rx CQ Drain Rate", mce_sys.rx_cq_drain_rate_nsec, MCE_DEFAULT_RX_CQ_DRAIN_RATE, SYS_VAR_RX_CQ_DRAIN_RATE_NSEC, "Disabled");
	}
	else {
		VLOG_PARAM_NUMBER("Rx CQ Drain Rate (nsec)", mce_sys.rx_cq_drain_rate_nsec, MCE_DEFAULT_RX_CQ_DRAIN_RATE, SYS_VAR_RX_CQ_DRAIN_RATE_NSEC);
	}

	VLOG_PARAM_NUMBER("GRO max streams", mce_sys.gro_streams_max, MCE_DEFAULT_GRO_STREAMS_MAX, SYS_VAR_GRO_STREAMS_MAX);

	VLOG_PARAM_STRING("TCP 3T rules", mce_sys.tcp_3t_rules, MCE_DEFAULT_TCP_3T_RULES, SYS_VAR_TCP_3T_RULES, mce_sys.tcp_3t_rules ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("ETH MC L2 only rules", mce_sys.eth_mc_l2_only_rules, MCE_DEFAULT_ETH_MC_L2_ONLY_RULES, SYS_VAR_ETH_MC_L2_ONLY_RULES, mce_sys.eth_mc_l2_only_rules ? "Enabled " : "Disabled");

	VLOG_PARAM_NUMBER("Select Poll (usec)", mce_sys.select_poll_num, MCE_DEFAULT_SELECT_NUM_POLLS, SYS_VAR_SELECT_NUM_POLLS);
	VLOG_PARAM_STRING("Select Poll OS Force", mce_sys.select_poll_os_force, MCE_DEFAULT_SELECT_POLL_OS_FORCE, SYS_VAR_SELECT_POLL_OS_FORCE, mce_sys.select_poll_os_force ? "Enabled " : "Disabled");

	if (mce_sys.select_poll_os_ratio) {
		VLOG_PARAM_NUMBER("Select Poll OS Ratio", mce_sys.select_poll_os_ratio, MCE_DEFAULT_SELECT_POLL_OS_RATIO, SYS_VAR_SELECT_POLL_OS_RATIO);
	}
	else {
		VLOG_PARAM_STRING("Select Poll OS Ratio", mce_sys.select_poll_os_ratio, MCE_DEFAULT_SELECT_POLL_OS_RATIO, SYS_VAR_SELECT_POLL_OS_RATIO, "Disabled");
	}
	if (mce_sys.select_poll_yield_loops) {
		VLOG_PARAM_NUMBER("Select Poll Yield", mce_sys.select_poll_yield_loops, MCE_DEFAULT_SELECT_POLL_YIELD, SYS_VAR_SELECT_POLL_YIELD);
	}
	else {
		VLOG_PARAM_STRING("Select Poll Yield", mce_sys.select_poll_yield_loops, MCE_DEFAULT_SELECT_POLL_YIELD, SYS_VAR_SELECT_POLL_YIELD, "Disabled");
	}
	if (mce_sys.select_skip_os_fd_check) {
		VLOG_PARAM_NUMBER("Select Skip OS", mce_sys.select_skip_os_fd_check, MCE_DEFAULT_SELECT_SKIP_OS, SYS_VAR_SELECT_SKIP_OS);
	}
	else {
		VLOG_PARAM_STRING("Select Skip OS", mce_sys.select_skip_os_fd_check, MCE_DEFAULT_SELECT_SKIP_OS, SYS_VAR_SELECT_SKIP_OS, "Disabled");
	}

	VLOG_PARAM_STRING("Select CQ Interrupts", mce_sys.select_arm_cq, MCE_DEFAULT_SELECT_ARM_CQ, SYS_VAR_SELECT_CQ_IRQ, mce_sys.select_arm_cq ? "Enabled " : "Disabled");

	if (mce_sys.progress_engine_interval_msec == MCE_CQ_DRAIN_INTERVAL_DISABLED || mce_sys.progress_engine_wce_max == 0) {
		vlog_printf(VLOG_INFO, FORMAT_STRING, "CQ Drain Thread", "Disabled", SYS_VAR_PROGRESS_ENGINE_INTERVAL);	
	}
	else {
		VLOG_PARAM_NUMBER("CQ Drain Interval (msec)", mce_sys.progress_engine_interval_msec, MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC, SYS_VAR_PROGRESS_ENGINE_INTERVAL);
		VLOG_PARAM_NUMBER("CQ Drain WCE (max)", mce_sys.progress_engine_wce_max, MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX, SYS_VAR_PROGRESS_ENGINE_WCE_MAX);
	}

	VLOG_PARAM_STRING("CQ Interrupts Moderation", mce_sys.cq_moderation_enable, MCE_DEFAULT_CQ_MODERATION_ENABLE, SYS_VAR_CQ_MODERATION_ENABLE, mce_sys.cq_moderation_enable ? "Enabled " : "Disabled");
	VLOG_PARAM_NUMBER("CQ Moderation Count", mce_sys.cq_moderation_count, MCE_DEFAULT_CQ_MODERATION_COUNT, SYS_VAR_CQ_MODERATION_COUNT);
	VLOG_PARAM_NUMBER("CQ Moderation Period (usec)", mce_sys.cq_moderation_period_usec, MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC, SYS_VAR_CQ_MODERATION_PERIOD_USEC);
	VLOG_PARAM_NUMBER("CQ AIM Max Count", mce_sys.cq_aim_max_count, MCE_DEFAULT_CQ_AIM_MAX_COUNT, SYS_VAR_CQ_AIM_MAX_COUNT);
	VLOG_PARAM_NUMBER("CQ AIM Max Period (usec)", mce_sys.cq_aim_max_period_usec, MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC, SYS_VAR_CQ_AIM_MAX_PERIOD_USEC);
	if (mce_sys.cq_aim_interval_msec == MCE_CQ_ADAPTIVE_MODERATION_DISABLED) {
		vlog_printf(VLOG_INFO, FORMAT_STRING, "CQ Adaptive Moderation", "Disabled", SYS_VAR_CQ_AIM_INTERVAL_MSEC);
	} else {
		VLOG_PARAM_NUMBER("CQ AIM Interval (msec)", mce_sys.cq_aim_interval_msec, MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC, SYS_VAR_CQ_AIM_INTERVAL_MSEC);
	}
	VLOG_PARAM_NUMBER("CQ AIM Interrupts Rate (per sec)", mce_sys.cq_aim_interrupts_rate_per_sec, MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC, SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC);

	VLOG_PARAM_NUMBER("CQ Poll Batch (max)", mce_sys.cq_poll_batch_max, MCE_DEFAULT_CQ_POLL_BATCH, SYS_VAR_CQ_POLL_BATCH_MAX);
	VLOG_PARAM_STRING("CQ Keeps QP Full", mce_sys.cq_keep_qp_full, MCE_DEFAULT_CQ_KEEP_QP_FULL, SYS_VAR_CQ_KEEP_QP_FULL, mce_sys.cq_keep_qp_full ? "Enabled" : "Disabled");
	VLOG_PARAM_NUMBER("QP Compensation Level", mce_sys.qp_compensation_level, MCE_DEFAULT_QP_COMPENSATION_LEVEL, SYS_VAR_QP_COMPENSATION_LEVEL);
	VLOG_PARAM_STRING("Offloaded Sockets", mce_sys.offloaded_sockets, MCE_DEFAULT_OFFLOADED_SOCKETS, SYS_VAR_OFFLOADED_SOCKETS, mce_sys.offloaded_sockets ? "Enabled" : "Disabled");
	VLOG_PARAM_NUMBER("Timer Resolution (msec)", mce_sys.timer_resolution_msec, MCE_DEFAULT_TIMER_RESOLUTION_MSEC, SYS_VAR_TIMER_RESOLUTION_MSEC);
	VLOG_PARAM_NUMBER("TCP Timer Resolution (msec)", mce_sys.tcp_timer_resolution_msec, MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC, SYS_VAR_TCP_TIMER_RESOLUTION_MSEC);
	VLOG_PARAM_NUMBER("Delay after join (msec)", mce_sys.wait_after_join_msec, MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC, SYS_VAR_WAIT_AFTER_JOIN_MSEC);
	VLOG_PARAM_NUMBER("Delay after rereg (msec)", mce_sys.wait_after_rereg_msec, MCE_DEFAULT_WAIT_AFTER_REREG_MSEC, SYS_VAR_WAIT_AFTER_REREG_MSEC);
	VLOG_STR_PARAM_STRING("Internal Thread Affinity", mce_sys.internal_thread_affinity_str, MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR, SYS_VAR_INTERNAL_THREAD_AFFINITY, mce_sys.internal_thread_affinity_str);
	VLOG_STR_PARAM_STRING("Internal Thread Cpuset", mce_sys.internal_thread_cpuset, MCE_DEFAULT_INTERNAL_THREAD_CPUSET, SYS_VAR_INTERNAL_THREAD_CPUSET, mce_sys.internal_thread_cpuset);
	VLOG_PARAM_STRING("Internal Thread Arm CQ", mce_sys.internal_thread_arm_cq_enabled, MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED, SYS_VAR_INTERNAL_THREAD_ARM_CQ, mce_sys.internal_thread_arm_cq_enabled ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("Thread mode", mce_sys.thread_mode, MCE_DEFAULT_THREAD_MODE, SYS_VAR_THREAD_MODE, thread_mode_str(mce_sys.thread_mode));
	switch (mce_sys.mem_alloc_type) {
	case ALLOC_TYPE_HUGEPAGES:
		VLOG_PARAM_NUMSTR("Mem Allocate type", mce_sys.mem_alloc_type, MCE_DEFAULT_MEM_ALLOC_TYPE, SYS_VAR_MEM_ALLOC_TYPE, "(Huge Pages)");     break;
	case ALLOC_TYPE_ANON:
		VLOG_PARAM_NUMSTR("Mem Allocate type", mce_sys.mem_alloc_type, MCE_DEFAULT_MEM_ALLOC_TYPE, SYS_VAR_MEM_ALLOC_TYPE, "(Malloc)");         break;
	case ALLOC_TYPE_CONTIG:
	default:
		VLOG_PARAM_NUMSTR("Mem Allocate type", mce_sys.mem_alloc_type, MCE_DEFAULT_MEM_ALLOC_TYPE, SYS_VAR_MEM_ALLOC_TYPE, "(Contig Pages)");   break;
	}

	VLOG_PARAM_NUMBER("Num of UC ARPs", mce_sys.neigh_uc_arp_quata, MCE_DEFAULT_NEIGH_UC_ARP_QUATA, SYS_VAR_NEIGH_UC_ARP_QUATA);
	VLOG_PARAM_NUMBER("UC ARP delay (msec)", mce_sys.neigh_wait_till_send_arp_msec, MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC, SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC);
	VLOG_PARAM_NUMBER("Num of neigh restart retries", mce_sys.neigh_num_err_retries, MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES, SYS_VAR_NEIGH_NUM_ERR_RETRIES );

	VLOG_PARAM_STRING("IPOIB support", mce_sys.enable_ipoib, MCE_DEFAULT_IPOIB_FLAG, SYS_VAR_IPOIB, mce_sys.enable_ipoib ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("BF (Blue Flame)", mce_sys.handle_bf, MCE_DEFAULT_BF_FLAG, SYS_VAR_BF, mce_sys.handle_bf ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("fork() support", mce_sys.handle_fork, MCE_DEFAULT_FORK_SUPPORT, SYS_VAR_FORK, mce_sys.handle_fork ? "Enabled " : "Disabled");
	VLOG_PARAM_STRING("close on dup2()", mce_sys.close_on_dup2, MCE_DEFAULT_CLOSE_ON_DUP2, SYS_VAR_CLOSE_ON_DUP2, mce_sys.close_on_dup2 ? "Enabled " : "Disabled");
	VLOG_PARAM_NUMBER("MTU", mce_sys.mtu, MCE_DEFAULT_MTU, SYS_VAR_MTU);
	switch (mce_sys.lwip_mss) {
	case MSS_FOLLOW_MTU:
		VLOG_PARAM_NUMSTR("MSS", mce_sys.lwip_mss, MCE_DEFAULT_MSS, SYS_VAR_MSS, "(follow VMA_MTU)");     break;
	default:
		VLOG_PARAM_NUMBER("MSS", mce_sys.lwip_mss, MCE_DEFAULT_MSS, SYS_VAR_MSS);	break;
	}
	VLOG_PARAM_NUMSTR("TCP CC Algorithm", mce_sys.lwip_cc_algo_mod, MCE_DEFAULT_LWIP_CC_ALGO_MOD, SYS_VAR_TCP_CC_ALGO, lwip_cc_algo_str(mce_sys.lwip_cc_algo_mod));
	VLOG_PARAM_NUMBER("TCP scaling window", mce_sys.window_scaling, MCE_DEFAULT_WINDOW_SCALING, SYS_VAR_WINDOW_SCALING);
	VLOG_PARAM_STRING("Suppress IGMP ver. warning", mce_sys.suppress_igmp_warning, MCE_DEFAULT_SUPPRESS_IGMP_WARNING, SYS_VAR_SUPPRESS_IGMP_WARNING, mce_sys.suppress_igmp_warning ? "Enabled " : "Disabled");

#ifdef VMA_TIME_MEASURE
	VLOG_PARAM_NUMBER("Time Measure Num Samples", mce_sys.vma_time_measure_num_samples, MCE_DEFAULT_TIME_MEASURE_NUM_SAMPLES, SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES);
	VLOG_STR_PARAM_STRING("Time Measure Dump File", mce_sys.vma_time_measure_filename, MCE_DEFAULT_TIME_MEASURE_DUMP_FILE, SYS_VAR_VMA_TIME_MEASURE_DUMP_FILE, mce_sys.vma_time_measure_filename);
#endif

	vlog_printf(VLOG_INFO,"---------------------------------------------------------------------------\n");
}

void get_env_params()
{
	int c = 0, len =0;
	char *env_ptr;
	FILE *fp = NULL;
	int app_name_size = MAX_CMD_LINE;
	// Large buffer size to avoid need for realloc

	fp = fopen("/proc/self/cmdline", "r");
	if (!fp) {
		vlog_printf(VLOG_ERROR,"***************************************************************************\n");
		vlog_printf(VLOG_ERROR,"* Failed loading VMA library! Try to execute the application without VMA. *\n");
		vlog_printf(VLOG_ERROR,"* 'unset LD_PRELOAD' environment variable and rerun the application.      *\n");
		vlog_printf(VLOG_ERROR,"***************************************************************************\n");
		exit(1);
	}

	mce_sys.app_name = (char *)malloc(app_name_size);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!mce_sys.app_name) {
		vlog_printf(VLOG_PANIC, "error while malloc\n");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	while ((c = fgetc(fp)) != EOF){
		mce_sys.app_name[len++] = (c==0?' ':c);
		if (len>=app_name_size) {
			app_name_size=app_name_size*2;
			mce_sys.app_name = (char*)realloc(mce_sys.app_name, app_name_size);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!mce_sys.app_name) {
				vlog_printf(VLOG_PANIC, "error while malloc\n");
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
	}

	mce_sys.app_name[len-1] = '\0';
	fclose(fp);

	bzero(mce_sys.vma_time_measure_filename, sizeof(mce_sys.vma_time_measure_filename));
	strcpy(mce_sys.vma_time_measure_filename, MCE_DEFAULT_TIME_MEASURE_DUMP_FILE);
	bzero(mce_sys.log_filename, sizeof(mce_sys.log_filename));
	bzero(mce_sys.stats_filename, sizeof(mce_sys.stats_filename));
	strcpy(mce_sys.stats_filename, MCE_DEFAULT_STATS_FILE);
	strcpy(mce_sys.conf_filename, MCE_DEFAULT_CONF_FILE);
	strcpy(mce_sys.app_id, MCE_DEFAULT_APP_ID);
	strcpy(mce_sys.internal_thread_cpuset, MCE_DEFAULT_INTERNAL_THREAD_CPUSET);
	strcpy(mce_sys.internal_thread_affinity_str, MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR);

	mce_sys.log_level               = VLOG_INFO;
	mce_sys.log_details             = MCE_DEFAULT_LOG_DETAILS;
	mce_sys.log_colors		= MCE_DEFAULT_LOG_COLORS;
	mce_sys.handle_sigintr 		= MCE_DEFAULT_HANDLE_SIGINTR;
	mce_sys.handle_segfault		= MCE_DEFAULT_HANDLE_SIGFAULT;
	mce_sys.stats_fd_num_max	= MCE_DEFAULT_STATS_FD_NUM;

	mce_sys.ring_allocation_logic_tx= MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
	mce_sys.ring_allocation_logic_rx= MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
	mce_sys.ring_migration_ratio_tx = MCE_DEFAULT_RING_MIGRATION_RATIO_TX;
	mce_sys.ring_migration_ratio_rx = MCE_DEFAULT_RING_MIGRATION_RATIO_RX;
	mce_sys.ring_limit_per_interface= MCE_DEFAULT_RING_LIMIT_PER_INTERFACE;

	mce_sys.tx_num_segs_tcp         = MCE_DEFAULT_TX_NUM_SEGS_TCP;
	mce_sys.tx_num_bufs             = MCE_DEFAULT_TX_NUM_BUFS;
	mce_sys.tx_num_wr               = MCE_DEFAULT_TX_NUM_WRE;
	mce_sys.tx_max_inline		= MCE_DEFAULT_TX_MAX_INLINE;
	mce_sys.tx_drop_mode            = TX_DROP_NOTHING;
	mce_sys.tx_mc_loopback_default  = MCE_DEFAULT_TX_MC_LOOPBACK;
	mce_sys.tx_nonblocked_eagains   = MCE_DEFAULT_TX_NONBLOCKED_EAGAINS;
	mce_sys.tx_prefetch_bytes 	= MCE_DEFAULT_TX_PREFETCH_BYTES;
	mce_sys.tx_backlog_max          = MCE_DEFAULT_TX_BACKLOG_MAX;

	mce_sys.rx_num_bufs             = MCE_DEFAULT_RX_NUM_BUFS;
	mce_sys.rx_num_wr               = MCE_DEFAULT_RX_NUM_WRE;
	mce_sys.rx_num_wr_to_post_recv  = MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV;
	mce_sys.rx_poll_num             = MCE_DEFAULT_RX_NUM_POLLS;
	mce_sys.rx_poll_num_init        = MCE_DEFAULT_RX_NUM_POLLS_INIT;
	mce_sys.rx_udp_poll_os_ratio    = MCE_DEFAULT_RX_UDP_POLL_OS_RATIO;
	mce_sys.rx_poll_yield_loops     = MCE_DEFAULT_RX_POLL_YIELD;
	mce_sys.select_handle_cpu_usage_stats   = MCE_DEFAULT_SELECT_CPU_USAGE_STATS;
	mce_sys.rx_ready_byte_min_limit = MCE_DEFAULT_RX_BYTE_MIN_LIMIT;
	mce_sys.rx_prefetch_bytes	= MCE_DEFAULT_RX_PREFETCH_BYTES;
	mce_sys.rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
	mce_sys.rx_cq_drain_rate_nsec 	= MCE_DEFAULT_RX_CQ_DRAIN_RATE;
	mce_sys.rx_delta_tsc_between_cq_polls = 0;

	mce_sys.gro_streams_max		= MCE_DEFAULT_GRO_STREAMS_MAX;

	mce_sys.tcp_3t_rules		= MCE_DEFAULT_TCP_3T_RULES;
	mce_sys.eth_mc_l2_only_rules	= MCE_DEFAULT_ETH_MC_L2_ONLY_RULES;

	mce_sys.select_poll_num		= MCE_DEFAULT_SELECT_NUM_POLLS;
	mce_sys.select_poll_os_force	= MCE_DEFAULT_SELECT_POLL_OS_FORCE;
	mce_sys.select_poll_os_ratio	= MCE_DEFAULT_SELECT_POLL_OS_RATIO;
	mce_sys.select_poll_yield_loops	= MCE_DEFAULT_SELECT_POLL_YIELD;
	mce_sys.select_skip_os_fd_check	= MCE_DEFAULT_SELECT_SKIP_OS;
	mce_sys.select_arm_cq		= MCE_DEFAULT_SELECT_ARM_CQ;

	mce_sys.cq_moderation_enable	= MCE_DEFAULT_CQ_MODERATION_ENABLE;
	mce_sys.cq_moderation_count = MCE_DEFAULT_CQ_MODERATION_COUNT;
	mce_sys.cq_moderation_period_usec = MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC;
	mce_sys.cq_aim_max_count	= MCE_DEFAULT_CQ_AIM_MAX_COUNT;
	mce_sys.cq_aim_max_period_usec = MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC;
	mce_sys.cq_aim_interval_msec = MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC;
	mce_sys.cq_aim_interrupts_rate_per_sec = MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC;

	mce_sys.cq_poll_batch_max	= MCE_DEFAULT_CQ_POLL_BATCH;
	mce_sys.progress_engine_interval_msec	= MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC;
	mce_sys.progress_engine_wce_max	= MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX;
	mce_sys.cq_keep_qp_full		= MCE_DEFAULT_CQ_KEEP_QP_FULL;
	mce_sys.qp_compensation_level	= MCE_DEFAULT_QP_COMPENSATION_LEVEL;
	mce_sys.internal_thread_arm_cq_enabled	= MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED;

	mce_sys.offloaded_sockets	= MCE_DEFAULT_OFFLOADED_SOCKETS;
	mce_sys.timer_resolution_msec	= MCE_DEFAULT_TIMER_RESOLUTION_MSEC;
	mce_sys.tcp_timer_resolution_msec	= MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC;
	mce_sys.wait_after_join_msec	= MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC;
	mce_sys.wait_after_rereg_msec 	= MCE_DEFAULT_WAIT_AFTER_REREG_MSEC;
	mce_sys.thread_mode		= MCE_DEFAULT_THREAD_MODE;
	mce_sys.mem_alloc_type          = MCE_DEFAULT_MEM_ALLOC_TYPE;
	mce_sys.enable_ipoib		= MCE_DEFAULT_IPOIB_FLAG;
	mce_sys.handle_fork		= MCE_DEFAULT_FORK_SUPPORT;
	mce_sys.handle_bf		= MCE_DEFAULT_BF_FLAG;
	mce_sys.close_on_dup2		= MCE_DEFAULT_CLOSE_ON_DUP2;
	mce_sys.mtu			= MCE_DEFAULT_MTU;
	mce_sys.lwip_mss		= MCE_DEFAULT_MSS;
	mce_sys.lwip_cc_algo_mod	= MCE_DEFAULT_LWIP_CC_ALGO_MOD;
	mce_sys.window_scaling		= MCE_DEFAULT_WINDOW_SCALING;
	mce_sys.mce_spec		= 0;
	mce_sys.mce_spec_param1		= 1;
	mce_sys.mce_spec_param2		= 1;
	
	mce_sys.neigh_num_err_retries	= MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES;
	mce_sys.neigh_uc_arp_quata	= MCE_DEFAULT_NEIGH_UC_ARP_QUATA;
	mce_sys.neigh_wait_till_send_arp_msec = MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC;

	mce_sys.timer_netlink_update_msec = MCE_DEFAULT_NETLINK_TIMER_MSEC;

	mce_sys.suppress_igmp_warning	= MCE_DEFAULT_SUPPRESS_IGMP_WARNING;

#ifdef VMA_TIME_MEASURE
	mce_sys.vma_time_measure_num_samples = MCE_DEFAULT_TIME_MEASURE_NUM_SAMPLES;
#endif

	if ((env_ptr = getenv(SYS_VAR_SPEC)) != NULL)
		mce_sys.mce_spec = (uint32_t)atoi(env_ptr);

	switch (mce_sys.mce_spec) {

	case MCE_SPEC_29WEST_LBM_29:
		mce_sys.mce_spec_param1         = 5000;	// [u-sec] Time out to send next pipe_write
		mce_sys.mce_spec_param2         = 50;	// Num of max sequential pipe_write to drop
		mce_sys.rx_poll_num             = 0;
		mce_sys.rx_udp_poll_os_ratio    = 100;
		mce_sys.select_poll_num         = 100000;
		mce_sys.select_poll_os_ratio    = 100;
		mce_sys.select_skip_os_fd_check = 50;
		break;

	case MCE_SPEC_WOMBAT_FH_LBM_554:
		mce_sys.mce_spec_param1         = 5000;	// [u-sec] Time out to send next pipe_write
		mce_sys.mce_spec_param2         = 50;	// Num of max sequential pipe_write to drop
		mce_sys.rx_poll_num             = 0;
		mce_sys.rx_udp_poll_os_ratio    = 100;
		mce_sys.select_poll_num         = 0;
		mce_sys.select_skip_os_fd_check = 20;
		mce_sys.select_arm_cq           = false;
		break;

	case MCE_SPEC_RTI_784:
		mce_sys.rx_poll_num             = -1;
// TODO - Need to replace old QP/CQ allocation logic here
//		mce_sys.qp_allocation_logic 	= QP_ALLOC_LOGIC__QP_PER_PEER_IP_PER_LOCAL_IP;
//		mce_sys.cq_allocation_logic	= CQ_ALLOC_LOGIC__CQ_PER_QP;
		break;

	case MCE_SPEC_MCD_623:
		mce_sys.ring_allocation_logic_rx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		mce_sys.ring_allocation_logic_tx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		break;

	case MCE_SPEC_MCD_IRQ_624:
		mce_sys.ring_allocation_logic_rx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		mce_sys.ring_allocation_logic_tx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		mce_sys.select_poll_num = 0;
		mce_sys.rx_poll_num = 0;
		mce_sys.cq_moderation_enable = false;
		break;

	case 0:
	default:
		break;
	}

       if ((env_ptr = getenv(SYS_VAR_SPEC_PARAM1)) != NULL)
		mce_sys.mce_spec_param1 = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SPEC_PARAM2)) != NULL)
		mce_sys.mce_spec_param2 = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_LOG_FILENAME)) != NULL){
        	// 'snprintf & getpid' will allow the use of a '%d' in the file name that will be replaced with the PID value
		snprintf(mce_sys.log_filename, sizeof(mce_sys.log_filename), env_ptr, getpid());
	}

	if ((env_ptr = getenv(SYS_VAR_STATS_FILENAME)) != NULL){
		snprintf(mce_sys.stats_filename, sizeof(mce_sys.stats_filename), env_ptr, getpid());
	}

	if ((env_ptr = getenv(SYS_VAR_CONF_FILENAME)) != NULL){
		snprintf(mce_sys.conf_filename, sizeof(mce_sys.conf_filename), env_ptr, getpid());
	}

	if ((env_ptr = getenv(SYS_VAR_LOG_LEVEL)) != NULL)
		mce_sys.log_level = (uint32_t)atoi(env_ptr);

	if (mce_sys.log_level >= VLOG_DEBUG)
		mce_sys.log_details = 2;

	if ((env_ptr = getenv(SYS_VAR_LOG_DETAILS)) != NULL)
		mce_sys.log_details = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_LOG_COLORS)) != NULL)
		mce_sys.log_colors = atoi(env_ptr) ? true : false;
	
	if ((env_ptr = getenv(SYS_VAR_APPLICATION_ID)) != NULL){
		// 'snprintf & getpid' will allow the use of a '%d' in the file name that will be replaced with the PID value
		snprintf(mce_sys.app_id, sizeof(mce_sys.app_id), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGINTR)) != NULL)
		mce_sys.handle_sigintr = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGSEGV)) != NULL)
		mce_sys.handle_segfault = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_STATS_FD_NUM)) != NULL) {
		mce_sys.stats_fd_num_max = (uint32_t)atoi(env_ptr);
		if (mce_sys.stats_fd_num_max > MAX_STATS_FD_NUM) {
			vlog_printf(VLOG_WARNING," Can only monitor maximum %d sockets in statistics \n", MAX_STATS_FD_NUM);
			mce_sys.stats_fd_num_max = MAX_STATS_FD_NUM;
		}
	}


	if ((env_ptr = getenv(SYS_VAR_TX_NUM_SEGS_TCP)) != NULL)
		mce_sys.tx_num_segs_tcp = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_NUM_BUFS)) != NULL)
		mce_sys.tx_num_bufs = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE)) != NULL)
		mce_sys.tx_num_wr = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_MAX_INLINE)) != NULL)
			mce_sys.tx_max_inline = (uint32_t)atoi(env_ptr);
	if(mce_sys.tx_max_inline > MAX_SUPPORTED_IB_INLINE_SIZE){
		vlog_printf(VLOG_WARNING,"MAX_INLINE  must be smaller or equal to 884 [%d]\n", mce_sys.tx_max_inline);
		mce_sys.tx_max_inline = MAX_SUPPORTED_IB_INLINE_SIZE;
	}

	if ((env_ptr = getenv(SYS_VAR_TX_DROP)) != NULL)
		mce_sys.tx_drop_mode = (tx_drop_mode_t)atoi(env_ptr);
	if (mce_sys.tx_drop_mode >= TX_DROP_LAST)
		mce_sys.tx_drop_mode = TX_DROP_NOTHING;

	if ((env_ptr = getenv(SYS_VAR_TX_MC_LOOPBACK)) != NULL)
		mce_sys.tx_mc_loopback_default = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_SUPPRESS_IGMP_WARNING)) != NULL)
				mce_sys.suppress_igmp_warning = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_TX_NONBLOCKED_EAGAINS)) != NULL)
		mce_sys.tx_nonblocked_eagains = atoi(env_ptr)? true : false;

	if ((env_ptr = getenv(SYS_VAR_TX_PREFETCH_BYTES)) != NULL)
		mce_sys.tx_prefetch_bytes = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_BACKLOG_MAX)) != NULL)
		mce_sys.tx_backlog_max = atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_TX)) != NULL) {
		mce_sys.ring_allocation_logic_tx = (ring_logic_t)atoi(env_ptr);
		if (!is_ring_logic_valid(mce_sys.ring_allocation_logic_tx)) {
			vlog_printf(VLOG_WARNING,"%s = %d is not valid, setting logic to default = %d\n",
					SYS_VAR_RING_ALLOCATION_LOGIC_TX, mce_sys.ring_allocation_logic_tx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX);
			mce_sys.ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_RX)) != NULL) {
		mce_sys.ring_allocation_logic_rx = (ring_logic_t)atoi(env_ptr);
		if (!is_ring_logic_valid(mce_sys.ring_allocation_logic_rx)) {
			vlog_printf(VLOG_WARNING,"%s = %d is not valid, setting logic to default = %d\n",
					SYS_VAR_RING_ALLOCATION_LOGIC_RX, mce_sys.ring_allocation_logic_rx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX);
			mce_sys.ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_TX)) != NULL)
		mce_sys.ring_migration_ratio_tx = (int32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_RX)) != NULL)
		mce_sys.ring_migration_ratio_rx = (int32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_LIMIT_PER_INTERFACE)) != NULL)
		mce_sys.ring_limit_per_interface = MAX(0, (int32_t)atoi(env_ptr));

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_BUFS)) != NULL)
		mce_sys.rx_num_bufs = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE_TO_POST_RECV)) != NULL)
		mce_sys.rx_num_wr_to_post_recv = MIN(NUM_RX_WRE_TO_POST_RECV_MAX, MAX(1, (uint32_t)atoi(env_ptr)));

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE)) != NULL)
		mce_sys.rx_num_wr = (uint32_t)atoi(env_ptr);
	if (mce_sys.rx_num_wr <= (mce_sys.rx_num_wr_to_post_recv * 2))
		mce_sys.rx_num_wr = mce_sys.rx_num_wr_to_post_recv * 2;

	if ((env_ptr = getenv(SYS_VAR_TX_MAX_INLINE)) != NULL)
		mce_sys.tx_max_inline = (uint32_t)atoi(env_ptr);
	if(mce_sys.tx_max_inline > MAX_SUPPORTED_IB_INLINE_SIZE){
		vlog_printf(VLOG_WARNING,"MAX INLINE  must be smaller or equal to %d [%d]\n",
				MAX_SUPPORTED_IB_INLINE_SIZE, mce_sys.tx_max_inline);
		mce_sys.tx_max_inline = MAX_SUPPORTED_IB_INLINE_SIZE;
	}

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS)) != NULL) {
		mce_sys.rx_poll_num = atoi(env_ptr);
	}
	if (mce_sys.rx_poll_num < MCE_MIN_RX_NUM_POLLS || mce_sys.rx_poll_num >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Rx Poll loops should be between %d and %d [%d]\n", MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, mce_sys.rx_poll_num);
		mce_sys.rx_poll_num = MCE_DEFAULT_RX_NUM_POLLS;
	}
	if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS_INIT)) != NULL)
		mce_sys.rx_poll_num_init = atoi(env_ptr);
	if (mce_sys.rx_poll_num_init < MCE_MIN_RX_NUM_POLLS || mce_sys.rx_poll_num_init >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Rx Poll loops should be between %d and %d [%d]\n", MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, mce_sys.rx_poll_num_init);
		mce_sys.rx_poll_num_init = MCE_DEFAULT_RX_NUM_POLLS_INIT;
	}
	if (mce_sys.rx_poll_num == 0)
		mce_sys.rx_poll_num = 1; // Force at least one good polling loop

	if ((env_ptr = getenv(SYS_VAR_RX_UDP_POLL_OS_RATIO)) != NULL)
		mce_sys.rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);

	//The following 2 params were replaced by SYS_VAR_RX_UDP_POLL_OS_RATIO
	if ((env_ptr = getenv(SYS_VAR_RX_POLL_OS_RATIO)) != NULL) {
		mce_sys.rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
		vlog_printf(VLOG_WARNING,"The parameter VMA_RX_POLL_OS_RATIO is no longer in use. Parameter VMA_RX_UDP_POLL_OS_RATIO was set to %d instead\n", mce_sys.rx_udp_poll_os_ratio);
	}
	if ((env_ptr = getenv(SYS_VAR_RX_SKIP_OS)) != NULL) {
		mce_sys.rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
		vlog_printf(VLOG_WARNING,"The parameter VMA_RX_SKIP_OS is no longer in use. Parameter VMA_RX_UDP_POLL_OS_RATIO was set to %d instead\n", mce_sys.rx_udp_poll_os_ratio);
	}

	if ((env_ptr = getenv(SYS_VAR_RX_POLL_YIELD)) != NULL)
		mce_sys.rx_poll_yield_loops = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_CPU_USAGE_STATS)) != NULL)
		mce_sys.select_handle_cpu_usage_stats = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_RX_BYTE_MIN_LIMIT)) != NULL)
		mce_sys.rx_ready_byte_min_limit = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES)) != NULL)
		mce_sys.rx_prefetch_bytes = (uint32_t)atoi(env_ptr);
	if (mce_sys.rx_prefetch_bytes < MCE_MIN_RX_PREFETCH_BYTES || mce_sys.rx_prefetch_bytes >  MCE_MAX_RX_PREFETCH_BYTES) {
		vlog_printf(VLOG_WARNING," Rx prefetch bytes size out of range [%d] (min=%d, max=%d)\n", mce_sys.rx_prefetch_bytes, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
		mce_sys.rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
	}

	if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL)) != NULL)
		mce_sys.rx_prefetch_bytes_before_poll = (uint32_t)atoi(env_ptr);
	if (mce_sys.rx_prefetch_bytes_before_poll != 0 && (mce_sys.rx_prefetch_bytes_before_poll < MCE_MIN_RX_PREFETCH_BYTES || mce_sys.rx_prefetch_bytes_before_poll >  MCE_MAX_RX_PREFETCH_BYTES)) {
		vlog_printf(VLOG_WARNING," Rx prefetch bytes size out of range [%d] (min=%d, max=%d, disabled=0)\n", mce_sys.rx_prefetch_bytes_before_poll, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
		mce_sys.rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
	}

	if ((env_ptr = getenv(SYS_VAR_RX_CQ_DRAIN_RATE_NSEC)) != NULL)
		mce_sys.rx_cq_drain_rate_nsec = atoi(env_ptr);
	// Update the rx cq polling rate for draining logic
	tscval_t tsc_per_second = get_tsc_rate_per_second();
	mce_sys.rx_delta_tsc_between_cq_polls = tsc_per_second * mce_sys.rx_cq_drain_rate_nsec / NSEC_PER_SEC;

	if ((env_ptr = getenv(SYS_VAR_GRO_STREAMS_MAX)) != NULL)
		mce_sys.gro_streams_max = MAX(atoi(env_ptr), 0);

	if ((env_ptr = getenv(SYS_VAR_TCP_3T_RULES)) != NULL)
		mce_sys.tcp_3t_rules = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_ETH_MC_L2_ONLY_RULES)) != NULL)
		mce_sys.eth_mc_l2_only_rules = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_SELECT_NUM_POLLS)) != NULL)
		mce_sys.select_poll_num = atoi(env_ptr);
	if (mce_sys.select_poll_num < MCE_MIN_RX_NUM_POLLS || mce_sys.select_poll_num >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Select Poll loops can not be below zero [%d]\n", mce_sys.select_poll_num);
		mce_sys.select_poll_num = MCE_DEFAULT_SELECT_NUM_POLLS;
	}

	if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_FORCE)) != NULL)
		mce_sys.select_poll_os_force = (uint32_t)atoi(env_ptr);

	if (mce_sys.select_poll_os_force) {
		mce_sys.select_poll_os_ratio = 1;
		mce_sys.select_skip_os_fd_check = 1;
	}

	if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_RATIO)) != NULL)
		mce_sys.select_poll_os_ratio = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_YIELD)) != NULL)
		mce_sys.select_poll_yield_loops = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_SKIP_OS)) != NULL)
		mce_sys.select_skip_os_fd_check = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_CQ_IRQ)) != NULL)
		mce_sys.select_arm_cq = atoi(env_ptr) ? true : false;



	if (mce_sys.rx_poll_num < 0 ||  mce_sys.select_poll_num < 0) {
		mce_sys.cq_moderation_enable = false;
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE)) != NULL)
		mce_sys.cq_moderation_enable = atoi(env_ptr) ? true : false;
#ifndef DEFINED_IBV_EXP_CQ_MODERATION
	mce_sys.cq_moderation_enable = false;
#endif

	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT)) != NULL)
		mce_sys.cq_moderation_count = (uint32_t)atoi(env_ptr);
	if (mce_sys.cq_moderation_count > mce_sys.rx_num_wr / 2) {
		mce_sys.cq_moderation_count = mce_sys.rx_num_wr / 2;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC)) != NULL)
		mce_sys.cq_moderation_period_usec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT)) != NULL)
		mce_sys.cq_aim_max_count = (uint32_t)atoi(env_ptr);
	if (mce_sys.cq_aim_max_count > mce_sys.rx_num_wr / 2){
		mce_sys.cq_aim_max_count = mce_sys.rx_num_wr / 2;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC)) != NULL)
		mce_sys.cq_aim_max_period_usec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC)) != NULL)
		mce_sys.cq_aim_interval_msec = (uint32_t)atoi(env_ptr);

	if (!mce_sys.cq_moderation_enable) {
		mce_sys.cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC)) != NULL)
		mce_sys.cq_aim_interrupts_rate_per_sec = (uint32_t)atoi(env_ptr);



	if ((env_ptr = getenv(SYS_VAR_CQ_POLL_BATCH_MAX)) != NULL)
		mce_sys.cq_poll_batch_max = (uint32_t)atoi(env_ptr);
	if (mce_sys.cq_poll_batch_max < MCE_MIN_CQ_POLL_BATCH || mce_sys.cq_poll_batch_max >  MCE_MAX_CQ_POLL_BATCH) {
		vlog_printf(VLOG_WARNING," Rx number of cq poll batchs should be between %d and %d [%d]\n", MCE_MIN_CQ_POLL_BATCH, MCE_MAX_CQ_POLL_BATCH, mce_sys.cq_poll_batch_max);
		mce_sys.cq_poll_batch_max = MCE_DEFAULT_CQ_POLL_BATCH;
	}

	if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL)) != NULL)
		mce_sys.progress_engine_interval_msec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_WCE_MAX)) != NULL)
		mce_sys.progress_engine_wce_max = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_KEEP_QP_FULL)) != NULL)
		mce_sys.cq_keep_qp_full = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_QP_COMPENSATION_LEVEL)) != NULL)
		mce_sys.qp_compensation_level = (uint32_t)atoi(env_ptr);
	if (mce_sys.qp_compensation_level < mce_sys.rx_num_wr_to_post_recv)
		mce_sys.qp_compensation_level = mce_sys.rx_num_wr_to_post_recv;

	if ((env_ptr = getenv(SYS_VAR_OFFLOADED_SOCKETS)) != NULL)
		mce_sys.offloaded_sockets = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_TIMER_RESOLUTION_MSEC)) != NULL)
			mce_sys.timer_resolution_msec = atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TCP_TIMER_RESOLUTION_MSEC)) != NULL) {
			mce_sys.tcp_timer_resolution_msec = atoi(env_ptr);
	}
	if(mce_sys.tcp_timer_resolution_msec < mce_sys.timer_resolution_msec){
		vlog_printf(VLOG_WARNING," TCP timer resolution [%s=%d] cannot be smaller than timer resolution [%s=%d]. Setting TCP timer resolution to %d msec.\n", SYS_VAR_TCP_TIMER_RESOLUTION_MSEC, mce_sys.tcp_timer_resolution_msec, SYS_VAR_TIMER_RESOLUTION_MSEC, mce_sys.timer_resolution_msec, mce_sys.timer_resolution_msec);
		mce_sys.tcp_timer_resolution_msec = mce_sys.timer_resolution_msec;
	}

	if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_ARM_CQ)) != NULL)
		mce_sys.internal_thread_arm_cq_enabled = atoi(env_ptr) ? true : false;

        if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_CPUSET)) != NULL) {
        	strcpy(mce_sys.internal_thread_cpuset, env_ptr);
        }

	// handle internal thread affinity - default is CPU-0
	if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_AFFINITY)) != NULL) {
		strcpy(mce_sys.internal_thread_affinity_str, env_ptr);
	}
	if (env_to_cpuset(mce_sys.internal_thread_affinity_str, &mce_sys.internal_thread_affinity)) {
		vlog_printf(VLOG_WARNING," Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
		            mce_sys.internal_thread_affinity_str);
	}

	if ((env_ptr = getenv(SYS_VAR_WAIT_AFTER_JOIN_MSEC)) != NULL)
		mce_sys.wait_after_join_msec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_WAIT_AFTER_REREG_MSEC)) != NULL)
		mce_sys.wait_after_rereg_msec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_THREAD_MODE)) != NULL) {
		mce_sys.thread_mode = (thread_mode_t)atoi(env_ptr);
		if (mce_sys.thread_mode < 0 || mce_sys.thread_mode >= THREAD_MODE_LAST)
			mce_sys.thread_mode = MCE_DEFAULT_THREAD_MODE;
	}

	if ((env_ptr = getenv(SYS_VAR_NETLINK_TIMER_MSEC)) != NULL)
		mce_sys.timer_netlink_update_msec = (uint32_t)atoi(env_ptr);


	if((env_ptr = getenv(SYS_VAR_NEIGH_NUM_ERR_RETRIES))!= NULL)  {
		mce_sys.neigh_num_err_retries = (uint32_t)atoi(env_ptr);
	}
	if((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC)) != NULL){
		mce_sys.neigh_wait_till_send_arp_msec = (uint32_t)atoi(env_ptr);
	}
	if((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_QUATA)) != NULL){
		mce_sys.neigh_uc_arp_quata = (uint32_t)atoi(env_ptr);
	}

	if ((getenv(SYS_VAR_HUGETBL)) != NULL)
	{
		vlog_printf(VLOG_WARNING, "**********************************************************************************************************************\n");
		vlog_printf(VLOG_WARNING, "The '%s' paramaeter is no longer supported, please refer to '%s' in README.txt for more info\n", SYS_VAR_HUGETBL, SYS_VAR_MEM_ALLOC_TYPE);
		vlog_printf(VLOG_WARNING, "**********************************************************************************************************************\n");
	}

	int tempVal = MCE_DEFAULT_MEM_ALLOC_TYPE;
	if ((env_ptr = getenv(SYS_VAR_MEM_ALLOC_TYPE)) != NULL)
		tempVal = atoi(env_ptr);
	if (tempVal < 0 || tempVal >= ALLOC_TYPE_LAST)
		tempVal = MCE_DEFAULT_MEM_ALLOC_TYPE;

	mce_sys.mem_alloc_type = (alloc_mode_t)tempVal;

	if ((env_ptr = getenv(SYS_VAR_BF)) != NULL)
		mce_sys.handle_bf = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_FORK)) != NULL)
		mce_sys.handle_fork = atoi(env_ptr) ? true : false;

	if((env_ptr = getenv(SYS_VAR_IPOIB )) != NULL)
		mce_sys.enable_ipoib = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_CLOSE_ON_DUP2)) != NULL)
		mce_sys.close_on_dup2 = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_MTU)) != NULL)
		mce_sys.mtu = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_MSS)) != NULL)
		mce_sys.lwip_mss = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TCP_CC_ALGO)) != NULL)
		mce_sys.lwip_cc_algo_mod = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_WINDOW_SCALING)) != NULL) {
		mce_sys.window_scaling = (int32_t)atoi(env_ptr);
		if(mce_sys.window_scaling > MAX_WINDOW_SCALING){
			mce_sys.window_scaling = MAX_WINDOW_SCALING;
			vlog_printf(VLOG_WARNING, "Window scaling is limited to %d. The value of '%s' is set to %d.\n", MAX_WINDOW_SCALING, SYS_VAR_WINDOW_SCALING, MAX_WINDOW_SCALING);
		}
	}

#ifdef VMA_TIME_MEASURE
	if ((env_ptr = getenv(SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES)) != NULL) {
		mce_sys.vma_time_measure_num_samples = (uint32_t)atoi(env_ptr);
		if(mce_sys.vma_time_measure_num_samples > INST_SIZE){
			vlog_printf(VLOG_WARNING, "The value of '%s' is bigger than %d. Time samples over %d will be dropped.\n", SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES, INST_SIZE, INST_SIZE);
		}
	}

	if ((env_ptr = getenv(SYS_VAR_VMA_TIME_MEASURE_DUMP_FILE)) != NULL){
		snprintf(mce_sys.vma_time_measure_filename, sizeof(mce_sys.vma_time_measure_filename), env_ptr, getpid());
	}
#endif

}

void set_env_params()
{
	// Need to call setenv() only after getenv() is done, because /bin/sh has
	// a custom setenv() which overrides original environment.

	//setenv("MLX4_SINGLE_THREADED", "1", 0);

	if(mce_sys.handle_bf){
                setenv("MLX4_POST_SEND_PREFER_BF", "1", 1);
        } else {
                setenv("MLX4_POST_SEND_PREFER_BF", "0", 1);
        }

        switch (mce_sys.mem_alloc_type) {
        case ALLOC_TYPE_ANON:
                setenv("MLX_QP_ALLOC_TYPE", "ANON", 0);
                setenv("MLX_CQ_ALLOC_TYPE", "ANON", 0);
                break;
        case ALLOC_TYPE_HUGEPAGES:
                setenv("RDMAV_HUGEPAGES_SAFE", "1", 0);
                setenv("MLX_QP_ALLOC_TYPE", "ALL", 0);
                setenv("MLX_CQ_ALLOC_TYPE", "ALL", 0);
                break;
        case ALLOC_TYPE_CONTIG:
        default:
                setenv("MLX_QP_ALLOC_TYPE", "PREFER_CONTIG", 0);
                setenv("MLX_CQ_ALLOC_TYPE", "PREFER_CONTIG", 0);
                break;
        }
}

void prepare_fork()
{
	if (mce_sys.handle_fork && !g_init_ibv_fork_done) {
                IF_VERBS_FAILURE(ibv_fork_init()) {
                        vlog_printf(VLOG_DEBUG,"ibv_fork_init failed (errno=%d %m)\n", errno);
                        vlog_printf(VLOG_ERROR, "************************************************************************\n");
                        vlog_printf(VLOG_ERROR, "ibv_fork_init() failed! The effect of the application calling 'fork()' is undefined!\n");
                        vlog_printf(VLOG_ERROR, "Read the fork section in the VMA's User Manual for more information\n");
                        vlog_printf(VLOG_ERROR, "************************************************************************\n");
                }
                else {
                        g_init_ibv_fork_done = true;
                        vlog_printf(VLOG_DEBUG,"ibv_fork_init() succeeded, fork() may be used safely!!\n");
                } ENDIF_VERBS_FAILURE;
        }
}

void register_handler_segv()
{
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = handle_segfault;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGSEGV, &act, NULL);
	vlog_printf(VLOG_INFO, "Registered a SIGSEGV handler\n");
}

extern "C" void sock_redirect_main(void)
{
	vlog_printf(VLOG_DEBUG, "%s()\n", __FUNCTION__);
//	int ret = atexit(sock_redirect_exit);
//	if (ret)
//		vlog_printf(VLOG_ERROR, "%s() ERROR at atexit() (ret=%d %m)\n", __FUNCTION__, ret);

	tv_clear(&g_last_zero_polling_time);

	if (mce_sys.handle_segfault) {
		register_handler_segv();
	}

#ifdef VMA_TIME_MEASURE
	init_instrumentation();
#endif
}

extern "C" void sock_redirect_exit(void)
{
#ifdef VMA_TIME_MEASURE
	finit_instrumentation(mce_sys.vma_time_measure_filename);
#endif
	vlog_printf(VLOG_DEBUG, "%s()\n", __FUNCTION__);
	vma_shmem_stats_close();
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void vma_mcheck_abort_cb(enum mcheck_status status)
{
	printf("mcheck abort! Got %d\n", status);
	printf("Press ENTER to continue...\n");
	getchar();
	handle_segfault(0);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

/*
void neigh_test()
{
		const cache_observer ob1;
		const cache_observer ob2;

		ip_address add1((in_addr_t)inet_addr("1.1.1.12"));
		ip_address add2((in_addr_t)inet_addr("225.5.5.5"));

		cache_entry_subject<ip_address, neigh_val*>  * cache_entry1;
		cache_entry_subject<ip_address, neigh_val*>  * cache_entry2;

		//neigh_entry * my_neigh;


//		g_p_neigh_table_mgr->register_observer(inet_addr("225.5.5.5"), &ob1, &cache_entry1);
//		g_p_neigh_table_mgr->register_observer(inet_addr("225.1.1.1"), &ob1, &cache_entry2);

		g_p_neigh_table_mgr->register_observer(add1, &ob1, &cache_entry1);
		g_p_neigh_table_mgr->register_observer(add2, &ob1, &cache_entry2);

		//my_neigh = (neigh_entry*)cache_entry;
		neigh_val *val1;
		while(!cache_entry1->get_val(val1))
			usleep(1);

		printf("Got val1\n");

		neigh_val *val2;

		for(int i=0; i<5; i++)
		{
			if(!(cache_entry2->get_val(val2)))
				sleep(1);
			else
				break;
		}

		sleep (5);
}
*/

/*
void igmp_test()
{
	// Simulating in igmp query/report  packet for igmp manager to process

	#define  IGMP_QUERY	IGMP_HOST_MEMBERSHIP_QUERY
	#define	 IGMP_REPORT	IGMPV2_HOST_MEMBERSHIP_REPORT

	ip_igmp_tx_hdr_template_t igmp_pkt;
	ip_igmp_tx_hdr_template_t *p_pkt = &igmp_pkt;

	p_pkt->m_ip_hdr.ihl = IPV4_IGMP_HDR_LEN_WORDS;
	p_pkt->m_ip_hdr.protocol = IPPROTO_IGMP;
	p_pkt->m_ip_hdr.tos = 0xc0;
	p_pkt->m_ip_hdr.ttl = 1;
	p_pkt->m_ip_hdr.tot_len = htons(IPV4_IGMP_HDR_LEN + sizeof(igmphdr));
	p_pkt->m_ip_hdr_ext = htonl(IGMP_IP_HEADER_EXT);
	p_pkt->m_ip_hdr.check = 0;
	p_pkt->m_ip_hdr.check = csum((unsigned short*)&p_pkt->m_ip_hdr, (IPV4_IGMP_HDR_LEN_WORDS) * 2);

	// Create the IGMP header
	p_pkt->m_igmp_hdr.type = IGMP_QUERY;
	p_pkt->m_igmp_hdr.code = 1; // igmp_code (1-255)
	p_pkt->m_igmp_hdr.group = (in_addr_t)inet_addr("224.4.4.4");

	p_pkt->m_igmp_hdr.csum = 0;
	p_pkt->m_igmp_hdr.csum = csum((unsigned short*)&p_pkt->m_igmp_hdr, IGMP_HDR_LEN_WORDS * 2);

	g_p_igmp_mgr->process_igmp_packet(&p_pkt->m_ip_hdr, (in_addr_t)inet_addr("2.2.2.16"));
}
*/

void do_global_ctors()
{
	static lock_spin_recursive g_globals_lock;
	auto_unlocker lock(g_globals_lock);

	if (g_init_global_ctors_done) {
		return;
	}
	g_init_global_ctors_done = true;

	set_env_params();
	prepare_fork();
	
	if (g_is_forked_child == true)
		g_is_forked_child = false;

	// Create all global managment objects
	if (!g_p_event_handler_manager)
		g_p_event_handler_manager = new event_handler_manager();

	  //Create new netlink listener
	if (!g_p_netlink_handler) {
		g_p_netlink_handler = new netlink_wrapper();
	}

        if (!g_p_ib_ctx_handler_collection) {
                g_p_ib_ctx_handler_collection = new ib_ctx_handler_collection();
        }
        g_p_ib_ctx_handler_collection->map_ib_devices();


	if(g_p_neigh_table_mgr == NULL) {
        	g_p_neigh_table_mgr = new neigh_table_mgr();
        	BULLSEYE_EXCLUDE_BLOCK_START
                if (g_p_neigh_table_mgr == NULL) {
                	vlog_printf(VLOG_PANIC, "Failed allocate neigh_table_mgr");
                }
        	BULLSEYE_EXCLUDE_BLOCK_END
        }

	// net_device should be initialized after event_handler and before buffer pool and g_p_neigh_table_mgr.
	if (!g_p_net_device_table_mgr) {
		g_p_net_device_table_mgr = new net_device_table_mgr();
		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_p_net_device_table_mgr == NULL) {
			vlog_printf(VLOG_PANIC, "Failed allocate net_device_table_mgr");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	if (!g_p_route_table_mgr) {
		g_p_route_table_mgr = new route_table_mgr();

		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_p_route_table_mgr == NULL) {
			vlog_printf(VLOG_PANIC, "Failed allocate route_table_mgr");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	if (!g_p_rule_table_mgr) {
		g_p_rule_table_mgr = new rule_table_mgr();
		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_p_rule_table_mgr == NULL) {
			vlog_printf(VLOG_PANIC, "Failed allocate rule_table_mgr");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	if(g_p_igmp_mgr == NULL) {
		g_p_igmp_mgr = new igmp_mgr();
		BULLSEYE_EXCLUDE_BLOCK_START
                if (g_p_igmp_mgr == NULL) {
                	vlog_printf(VLOG_PANIC, "Failed allocate igmp_mgr");
                }
		BULLSEYE_EXCLUDE_BLOCK_END
        }

 	if (!g_buffer_pool_rx)
		g_buffer_pool_rx = new buffer_pool(mce_sys.rx_num_bufs, RX_BUF_SIZE(mce_sys.mtu), NULL, NULL, buffer_pool::free_rx_lwip_pbuf_custom);

 	if (!g_buffer_pool_tx)
 		g_buffer_pool_tx = new buffer_pool(mce_sys.tx_num_bufs, get_lwip_tcp_mss(mce_sys.mtu, mce_sys.lwip_mss) + 92, NULL, NULL, buffer_pool::free_tx_lwip_pbuf_custom);

 	if (!g_tcp_seg_pool)
 		g_tcp_seg_pool = new tcp_seg_pool(mce_sys.tx_num_segs_tcp);

 	if (!g_tcp_timers_collection)
 		g_tcp_timers_collection = new tcp_timers_collection(mce_sys.tcp_timer_resolution_msec, mce_sys.timer_resolution_msec);

	if (!g_p_vlogger_timer_handler)
		g_p_vlogger_timer_handler = new vlogger_timer_handler();

	if (!g_p_ip_frag_manager) {
		g_p_ip_frag_manager = new ip_frag_manager();
	}

	if (!g_p_fd_collection)
		g_p_fd_collection = new fd_collection();

	if (check_if_regular_file (mce_sys.conf_filename))
	{
		vlog_printf(VLOG_WARNING,"FAILED to read VMA configuration file. %s is not a regular file.\n",
				mce_sys.conf_filename);
		if (strcmp (MCE_DEFAULT_CONF_FILE, mce_sys.conf_filename))
			vlog_printf(VLOG_INFO,"Please see README.txt section regarding VMA_CONFIG_FILE\n");
	}
	else if (__vma_parse_config_file(mce_sys.conf_filename))
		vlog_printf(VLOG_WARNING,"FAILED to read VMA configuration file: %s\n", mce_sys.conf_filename);


	// initialize LWIP tcp/ip stack
	if (!g_p_lwip)
		g_p_lwip = new vma_lwip();
        
	vma_shmem_stats_open(&g_p_vlogger_level, &g_p_vlogger_details);
	*g_p_vlogger_level = g_vlogger_level;
	*g_p_vlogger_details = g_vlogger_details;

	if (g_p_netlink_handler) {
		// Open netlink socket
		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_p_netlink_handler->open_channel()) {
			vlog_printf(VLOG_PANIC, "Failed in netlink open_channel()\n");
			exit (1);
		}

		int fd = g_p_netlink_handler->get_channel();
		if(fd == -1) {
			vlog_printf(VLOG_PANIC, "Netlink fd == -1\n");
			exit(1);
		}

		// Register netlink fd to the event_manager
		command_netlink * cmd_nl = NULL;
		cmd_nl = new command_netlink(g_p_netlink_handler);
		if (cmd_nl == NULL) {
			vlog_printf(VLOG_PANIC,"Failed allocating command_netlink\n");
			exit(1);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		g_p_event_handler_manager->register_command_event(fd, cmd_nl);
		g_p_event_handler_manager->register_timer_event(
				mce_sys.timer_netlink_update_msec,
				cmd_nl,
				PERIODIC_TIMER,
				NULL);

	}

	g_n_os_igmp_max_membership = get_igmp_max_membership();
	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_n_os_igmp_max_membership < 0) {
		vlog_printf(VLOG_WARNING,"failed to read igmp_max_membership value");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

// 	neigh_test();
//	igmp_test();
}

// checks that netserver runs with flags: -D, -f. Otherwise, warn user for wrong usage
// this test is performed since vma does not support fork, and these flags make sure the netserver application will not use fork.
void check_netperf_flags()
{
        char cmd_line[FILENAME_MAX];
        char *pch, *command;
        bool b_D_flag = false, b_f_flag = false;
        char add_flags[4];

        strcpy(cmd_line, mce_sys.app_name);
        pch = strtok(cmd_line, " ");

        command = basename(pch); //extract only "netserver" from full path
        if (strcmp(command, "netserver")) {
                return;
        }
        pch = strtok(NULL, " ");

        while (pch != NULL) {
                if (*pch == '-') {
                        if (strchr(pch, 'D'))
                                b_D_flag = true;
                        if (strchr(pch, 'f'))
                                b_f_flag = true;
                }
                if (b_f_flag && b_D_flag)
                        break;
                pch = strtok(NULL, " ");
        }
        if (!b_D_flag || !b_f_flag) {
                vlog_printf(VLOG_WARNING,
                                "Running netserver without flags: -D, -f can cause failure\n");
                add_flags[0] = '-'; // check which flags need to be added to the command
                if (!b_D_flag)
                        add_flags[1] = 'D';
                if (!b_f_flag)
                        add_flags[1] == 0 ? add_flags[1] = 'f' : add_flags[2] = 'f';
                vlog_printf(VLOG_WARNING, "Recommended command line: %s %s\n",
                                mce_sys.app_name, add_flags);
        }
}

//-----------------------------------------------------------------------------
//  library init function
//-----------------------------------------------------------------------------
// __attribute__((constructor)) causes the function to be called when
// library is firsrt loaded
//extern "C" int __attribute__((constructor)) sock_redirect_lib_load_constructor(void)
extern "C" int main_init(void)
{

#ifndef VMA_SVN_REVISION
	// Force GCC's malloc() to check the consistency of dynamic memory in development build (Non Release)
	//mcheck(vma_mcheck_abort_cb);
#endif

	get_env_params();

	g_init_global_ctors_done = false;

	vlog_start("VMA", mce_sys.log_level, mce_sys.log_filename, mce_sys.log_details, mce_sys.log_colors);

	print_vma_global_settings();
	get_orig_funcs();

	check_locked_mem();
	check_debug();
	check_flow_steering_log_num_mgm_entry_size();
	check_netperf_flags();

	if (*mce_sys.stats_filename) {
		if (check_if_regular_file (mce_sys.stats_filename))
			vlog_printf(VLOG_WARNING,"FAILED to create VMA statistics file. %s is not a regular file.\n", mce_sys.stats_filename);
		else if (!(g_stats_file = fopen(mce_sys.stats_filename, "w")))
				vlog_printf(VLOG_WARNING," Couldn't open statistics file: %s\n", mce_sys.stats_filename);
	}

	sock_redirect_main();

	return 0;
}
//extern "C" int __attribute__((destructor)) sock_redirect_lib_load_destructor(void)
extern "C" int main_destroy(void)
{
	vlog_printf(VLOG_DEBUG, "%s: Closing libvma resources\n", __FUNCTION__);

	//Triggers connection close, relevant for TCP which may need some time to terminate the connection.
	if (g_p_fd_collection) {
		g_p_fd_collection->prepare_to_close();
	}
	g_b_exit = true;

	usleep(50000);

	//Handle pending received data, this is critical for proper TCP connection termination
	if (g_p_net_device_table_mgr) {
		g_p_net_device_table_mgr->global_ring_drain_and_procces();
	}

	if(g_p_igmp_mgr) {
		igmp_mgr* g_p_igmp_mgr_tmp = g_p_igmp_mgr;
		g_p_igmp_mgr = NULL;
		delete g_p_igmp_mgr_tmp;
		usleep(50000);
	}

	if (g_tcp_timers_collection) g_tcp_timers_collection->clean_obj();
	g_tcp_timers_collection = NULL;

	if (g_p_event_handler_manager)
		g_p_event_handler_manager->stop_thread();
	// Block all sock-redicrt API calls into our offloading core
	fd_collection* g_p_fd_collection_temp = g_p_fd_collection;
	g_p_fd_collection = NULL;
	if (g_p_fd_collection_temp) delete g_p_fd_collection_temp;

	usleep(50000);

	if (g_p_rule_table_mgr) delete g_p_rule_table_mgr;
	g_p_rule_table_mgr = NULL;

	if (g_p_route_table_mgr) delete g_p_route_table_mgr;
	g_p_route_table_mgr = NULL;

	//if(g_p_net_device_table_mgr) delete g_p_net_device_table_mgr;
	//g_p_net_device_table_mgr = NULL;

	/*TODO: Need to handle this as part of  clean exit and destruction of all VMA data structures
	 * 	if (g_p_lwip) delete g_p_lwip;
	 *	g_p_lwip = NULL;
	 */

// XXX YossiE later- unite all stats to mux_stats
#if 0
	// Print select() related stat counters (only if we got some calls to select)
	if (g_p_socket_select_stats != NULL) {
		if (g_p_socket_select_stats->n_select_os_rx_ready || g_p_socket_select_stats->n_select_rx_ready)
			vlog_printf(VLOG_DEBUG, "select() Rx fds ready: %d / %d [os/offload]\n", g_p_socket_select_stats->n_select_os_rx_ready, g_p_socket_select_stats->n_select_rx_ready);
		if (g_p_socket_select_stats->n_select_timeouts || g_p_socket_select_stats->n_select_errors)
			vlog_printf(VLOG_DEBUG, "select() : %d / %d [timeouts/errors]\n", g_p_socket_select_stats->n_select_timeouts, g_p_socket_select_stats->n_select_errors);
		if (g_p_socket_select_stats->n_select_poll_miss + g_p_socket_select_stats->n_select_poll_hit) {
			float select_poll_hit_percentage = (float)(g_p_socket_select_stats->n_select_poll_hit * 100) / (float)(g_p_socket_select_stats->n_select_poll_miss + g_p_socket_select_stats->n_select_poll_hit);
			vlog_printf(VLOG_DEBUG, "select() poll: %d / %d (%2.2f%%) [miss/hit]\n", g_p_socket_select_stats->n_select_poll_miss, g_p_socket_select_stats->n_select_poll_hit, select_poll_hit_percentage);
		}
	}

	// Print epoll() related stat counters (only if we got some calls to epoll)
	if (g_p_socket_epoll_stats != NULL) {
		if (g_p_socket_epoll_stats->n_select_os_rx_ready || g_p_socket_epoll_stats->n_select_rx_ready)
			vlog_printf(VLOG_DEBUG, "epoll() Rx fds ready: %d / %d [os/offload]\n", g_p_socket_epoll_stats->n_select_os_rx_ready, g_p_socket_epoll_stats->n_select_rx_ready);
		if (g_p_socket_epoll_stats->n_select_timeouts || g_p_socket_epoll_stats->n_select_errors)
			vlog_printf(VLOG_DEBUG, "epoll() : %d / %d [timeouts/errors]\n", g_p_socket_epoll_stats->n_select_timeouts, g_p_socket_epoll_stats->n_select_errors);
		if (g_p_socket_epoll_stats->n_select_poll_miss + g_p_socket_epoll_stats->n_select_poll_hit) {
			float epoll_poll_hit_percentage = (float)(g_p_socket_epoll_stats->n_select_poll_hit * 100) / (float)(g_p_socket_epoll_stats->n_select_poll_miss + g_p_socket_epoll_stats->n_select_poll_hit);
			vlog_printf(VLOG_DEBUG, "epoll() poll: %d / %d (%2.2f%%) [miss/hit]\n", g_p_socket_epoll_stats->n_select_poll_miss, g_p_socket_epoll_stats->n_select_poll_hit, epoll_poll_hit_percentage);
		}
	}
#endif

	ip_frag_manager* g_p_ip_frag_manager_temp = g_p_ip_frag_manager;
	g_p_ip_frag_manager = NULL;
	if (g_p_ip_frag_manager_temp) delete g_p_ip_frag_manager_temp;
	
	if (g_tcp_seg_pool) delete g_tcp_seg_pool;
	g_tcp_seg_pool = NULL;

	if (g_buffer_pool_tx) delete g_buffer_pool_tx;
	g_buffer_pool_tx = NULL;

	if (g_buffer_pool_rx) delete g_buffer_pool_rx;
	g_buffer_pool_rx = NULL;

	if (g_p_vlogger_timer_handler) delete g_p_vlogger_timer_handler;
	g_p_vlogger_timer_handler = NULL;
	
	if (g_p_event_handler_manager) delete g_p_event_handler_manager;
	g_p_event_handler_manager = NULL;

	vlog_printf(VLOG_DEBUG, "Stopping logger module\n");

	sock_redirect_exit();

	vlog_stop();

	if (g_stats_file) {
		//cosmetics - remove when adding iomux block
		fprintf(g_stats_file, "======================================================\n");
		fclose (g_stats_file);
	}

	return 0;
}
