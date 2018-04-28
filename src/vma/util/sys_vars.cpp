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
#include "utils/rdtsc.h"
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

// Do not rely on global variable initialization in code that might be called from library constructor (main_init)
mce_sys_var & safe_mce_sys() {return mce_sys_var::instance();}

#define MAX_BACKTRACE		25
#define MAX_VERSION_STR_LEN	128
#define MAX_CMD_LINE		2048

void mce_sys_var::print_vma_load_failure_msg()
{
	vlog_printf(VLOG_ERROR,"***************************************************************************\n");
	vlog_printf(VLOG_ERROR,"* Failed loading VMA library! Try executing the application without VMA.  *\n");
	vlog_printf(VLOG_ERROR,"* 'unset LD_PRELOAD' environment variable and rerun the application.      *\n");
	vlog_printf(VLOG_ERROR,"***************************************************************************\n");
}



namespace vma_spec {
	typedef struct {
		vma_spec_t level;
		const char *  output_name;
		const char ** input_names;
	} vma_spec_names;

	static const char *names_none[]    	   = {"none", "0",NULL};
	static const char *spec_names_ulatency[]  = {"ultra-latency", "10", NULL};
	static const char *spec_names_latency[]   = {"latency", "15", NULL};
	static const char *spec_names_29west[]    = {"29west", "29", NULL};
	static const char *spec_names_wombat_fh[] = {"wombat_fh", "554", NULL};
	static const char *spec_names_mcd[]       = {"mcd", "623", NULL};
	static const char *spec_names_mcd_irq[]   = {"mcd-irq", "624", NULL};
	static const char *spec_names_rti[]       = {"rti", "784", NULL};
	static const char *spec_names_7750[]      = {"7750", NULL};
	static const char *spec_names_multi_ring[]      = {"multi_ring_latency", NULL};

	// must be by order because "to_str" relies on that!
	static const vma_spec_names specs[] = {
		{MCE_SPEC_NONE, 		  	"NONE",     			(const char ** )names_none},
		{MCE_SPEC_SOCKPERF_ULTRA_LATENCY_10, 	"Ultra Latency", 		(const char ** )spec_names_ulatency},
		{MCE_SPEC_SOCKPERF_LATENCY_15,    	"Latency",   			(const char ** )spec_names_latency},
		{MCE_SPEC_29WEST_LBM_29,    	  	"29West LBM Logic",    		(const char ** )spec_names_29west},
		{MCE_SPEC_WOMBAT_FH_LBM_554,      	"Wombat FH LBM Logic",    	(const char ** )spec_names_wombat_fh},
		{MCE_SPEC_MCD_623,    		  	"Memcached Logic",    		(const char ** )spec_names_mcd},
		{MCE_SPEC_MCD_IRQ_624,    	  	"Memcached Interrupt Mode",	(const char ** )spec_names_mcd_irq},
		{MCE_SPEC_RTI_784,    		  	"RTI Logic",    		(const char ** )spec_names_rti},
		{MCE_SPEC_LL_7750,    		  	"7750 Low Latency Profile", 	(const char ** )spec_names_7750},
		{MCE_SPEC_LL_MULTI_RING,    	"Multi Ring Latency Profile",	 	(const char ** )spec_names_multi_ring},
	};

	// convert str to vVMA_spec_t; upon error - returns the given 'def_value'
	vma_spec_t from_str(const char* str, vma_spec_t def_value)
	{
		size_t num_levels = sizeof(specs) / sizeof(specs[0]);
		for (size_t i = 0; i < num_levels; ++i) {
			const char ** input_name = specs[i].input_names;
			while (*input_name) {
				if (strcasecmp(str, *input_name) == 0)
					return specs[i].level;
				input_name++;
			}
		}

		return def_value; // not found. use given def_value
	}

	// convert int to vVMA_spec_t; upon error - returns the given 'def_value'
	vma_spec_t from_int(const int int_spec, vma_spec_t def_value)
	{
		if (int_spec >= MCE_SPEC_NONE && int_spec <= MCE_VMA__ALL) {
			return static_cast<vma_spec_t>(int_spec);
		}
		return def_value; // not found. use given def_value
	}

	const char * to_str(vma_spec_t level)
	{
		static int base = MCE_SPEC_NONE;
		return specs[level - base].output_name;
	}

}

int mce_sys_var::list_to_cpuset(char *cpulist, cpu_set_t *cpu_set)
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

int mce_sys_var::hex_to_cpuset(char *start, cpu_set_t *cpu_set)
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

int mce_sys_var::env_to_cpuset(char *orig_start, cpu_set_t *cpu_set)
{
	int ret;
	char* start = strdup(orig_start); // save the caller string from strtok destruction.

	/*
	 * We expect a hex number or comma delimited cpulist.  Check for 
	 * starting characters of "0x" or "0X" and if present then parse
	 * the string as a hexidecimal value, otherwise treat it as a 
	 * cpulist.
	 */
	if ((strlen(start) > 2) &&
		(start[0] == '0') &&
		((start[1] == 'x') || (start[1] == 'X'))) {
		ret = hex_to_cpuset(start + 2, cpu_set);
	} else {
		ret = list_to_cpuset(start, cpu_set);
	}

	free(start);
	return ret;
}

void mce_sys_var::read_env_variable_with_pid(char* mce_sys_name, size_t mce_sys_max_size, char* env_ptr)
{
	int n = -1;
	char* d_pos = NULL;

	if (NULL == env_ptr || NULL == mce_sys_name || mce_sys_max_size < 2) {
		return ;
	}

	d_pos = strstr(env_ptr, "%d");
	if (!d_pos) { // no %d in the string
		n = snprintf(mce_sys_name, mce_sys_max_size - 1, "%s", env_ptr);
		if (unlikely((((int)mce_sys_max_size - 1) < n) || (n < 0))) {
			mce_sys_name[0] = '\0';
		}
	} else { // has at least one occurrence of %d - replace the first one with the process PID
		size_t bytes_num = MIN((size_t)(d_pos - env_ptr), mce_sys_max_size - 1);
		strncpy(mce_sys_name, env_ptr, bytes_num);
		mce_sys_name[bytes_num] = '\0';
		n = snprintf(mce_sys_name + bytes_num, mce_sys_max_size - bytes_num - 1, "%d", getpid());
		if (likely((0 < n) && (n < ((int)mce_sys_max_size - (int)bytes_num - 1)))) {
			bytes_num += n;
			snprintf(mce_sys_name + bytes_num, mce_sys_max_size - bytes_num, "%s", d_pos + 2);
		}
	}
}

bool mce_sys_var::check_cpuinfo_flag(const char* flag)
{
	FILE *fp;
	char *line;
	bool ret = false;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp) {
		vlog_printf(VLOG_ERROR, "error while fopen\n");
		print_vma_load_failure_msg();
		return false;
	}
	line = (char*)malloc(MAX_CMD_LINE);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!line) {
		vlog_printf(VLOG_ERROR, "error while malloc\n");
		print_vma_load_failure_msg();
		goto exit;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	while (fgets(line, MAX_CMD_LINE, fp)) {
		if (strncmp(line, "flags\t", 5) == 0) {
			if (strstr(line, flag)) {
				ret = true;
				goto exit;
			}
		}
	}

exit:
	fclose(fp);
	free(line);
	return ret;
}

/*
 * Intel and AMD CPUs have reserved bit 31 of ECX of CPUID leaf 0x1 as the hypervisor present bit.
 * This bit allows hypervisors to indicate their presence to the guest operating system.
 * Hypervisors set this bit and physical CPUs (all existing and future CPUs) set this bit to zero.
 * Guest operating systems can test bit 31 to detect if they are running inside a virtual machine.
 */
bool mce_sys_var::cpuid_hv()
{
#if defined(__x86_64__)
	uint32_t _ecx;
	__asm__ __volatile__("cpuid" \
            : "=c"(_ecx) \
	        : "a"(0x01));
	usleep(0);
	return (bool)((_ecx >> 31) & 0x1);
#else
	return check_cpuinfo_flag(VIRTUALIZATION_FLAG);
#endif
}

/*
 * Intel and AMD have also reserved CPUID leaves 0x40000000 - 0x400000FF for software use.
 * Hypervisors can use these leaves to provide an interface to pass information from the
 * hypervisor to the guest operating system running inside a virtual machine.
 * The hypervisor bit indicates the presence of a hypervisor and that it is safe to test
 * these additional software leaves. VMware defines the 0x40000000 leaf as the hypervisor CPUID
 * information leaf. Code running on a VMware hypervisor can test the CPUID information leaf
 * for the hypervisor signature. VMware stores the string "VMwareVMware" in
 * EBX, ECX, EDX of CPUID leaf 0x40000000.
 */
const char* mce_sys_var::cpuid_hv_vendor()
{
#if defined(__x86_64__)
	static __thread char vendor[13];
	uint32_t _ebx = 0, _ecx = 0, _edx = 0;

    if (!cpuid_hv()) {
    	return NULL;
    }
	__asm__ __volatile__("cpuid" \
            : "=b"(_ebx), \
            "=c"(_ecx), \
            "=d"(_edx) \
            : "a"(0x40000000));
	sprintf(vendor,     "%c%c%c%c", _ebx, (_ebx >> 8), (_ebx >> 16), (_ebx >> 24));
	sprintf(vendor + 4, "%c%c%c%c", _ecx, (_ecx >> 8), (_ecx >> 16), (_ecx >> 24));
	sprintf(vendor + 8, "%c%c%c%c", _edx, (_edx >> 8), (_edx >> 16), (_edx >> 24));
	vendor[12] = 0x00;
	return vendor;
#else
	static __thread char vendor[13] = "n/a";
	return vendor;
#endif
}

void mce_sys_var::get_env_params()
{
	int c = 0, len =0;
	char *env_ptr;
	FILE *fp = NULL;
	int app_name_size = MAX_CMD_LINE;
	// Large buffer size to avoid need for realloc

	fp = fopen("/proc/self/cmdline", "r");
	if (!fp) {
		vlog_printf(VLOG_ERROR, "error while fopen\n");
		print_vma_load_failure_msg();
		exit(1);
	}

	app_name = (char *)malloc(app_name_size);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!app_name) {
		vlog_printf(VLOG_ERROR, "error while malloc\n");
		print_vma_load_failure_msg();
		exit(1);
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	while ((c = fgetc(fp)) != EOF){
		app_name[len++] = (c==0?' ':c);
		if (len>=app_name_size) {
			app_name_size=app_name_size*2;
			app_name = (char*)realloc(app_name, app_name_size);
			BULLSEYE_EXCLUDE_BLOCK_START
			if (!app_name) {
				vlog_printf(VLOG_ERROR, "error while malloc\n");
				print_vma_load_failure_msg();
				exit(1);
			}
			BULLSEYE_EXCLUDE_BLOCK_END
		}
	}

	app_name[len-1] = '\0';
	fclose(fp);

	bzero(vma_time_measure_filename, sizeof(vma_time_measure_filename));
	strcpy(vma_time_measure_filename, MCE_DEFAULT_TIME_MEASURE_DUMP_FILE);
	bzero(log_filename, sizeof(log_filename));
	bzero(stats_filename, sizeof(stats_filename));
	bzero(stats_shmem_dirname, sizeof(stats_shmem_dirname));
	strcpy(stats_filename, MCE_DEFAULT_STATS_FILE);
	strcpy(stats_shmem_dirname, MCE_DEFAULT_STATS_SHMEM_DIR);
	strcpy(conf_filename, MCE_DEFAULT_CONF_FILE);
	strcpy(app_id, MCE_DEFAULT_APP_ID);
	strcpy(internal_thread_cpuset, MCE_DEFAULT_INTERNAL_THREAD_CPUSET);
	strcpy(internal_thread_affinity_str, MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR);

	log_level               = VLOG_DEFAULT;
	log_details             = MCE_DEFAULT_LOG_DETAILS;
	log_colors		= MCE_DEFAULT_LOG_COLORS;
	handle_sigintr 		= MCE_DEFAULT_HANDLE_SIGINTR;
	handle_segfault		= MCE_DEFAULT_HANDLE_SIGFAULT;
	stats_fd_num_max	= MCE_DEFAULT_STATS_FD_NUM;

	ring_allocation_logic_tx= MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
	ring_allocation_logic_rx= MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
	ring_migration_ratio_tx = MCE_DEFAULT_RING_MIGRATION_RATIO_TX;
	ring_migration_ratio_rx = MCE_DEFAULT_RING_MIGRATION_RATIO_RX;
	ring_limit_per_interface= MCE_DEFAULT_RING_LIMIT_PER_INTERFACE;
	ring_dev_mem_tx         = MCE_DEFAULT_RING_DEV_MEM_TX;

	tcp_max_syn_rate	= MCE_DEFAULT_TCP_MAX_SYN_RATE;

	tx_num_segs_tcp         = MCE_DEFAULT_TX_NUM_SEGS_TCP;
	tx_num_bufs             = MCE_DEFAULT_TX_NUM_BUFS;
	tx_num_wr               = MCE_DEFAULT_TX_NUM_WRE;
	tx_num_wr_to_signal     = MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL;
	tx_max_inline		= MCE_DEFAULT_TX_MAX_INLINE;
	tx_mc_loopback_default  = MCE_DEFAULT_TX_MC_LOOPBACK;
	tx_nonblocked_eagains   = MCE_DEFAULT_TX_NONBLOCKED_EAGAINS;
	tx_prefetch_bytes 	= MCE_DEFAULT_TX_PREFETCH_BYTES;
	tx_bufs_batch_udp	= MCE_DEFAULT_TX_BUFS_BATCH_UDP;
	tx_bufs_batch_tcp	= MCE_DEFAULT_TX_BUFS_BATCH_TCP;

	rx_num_bufs             = MCE_DEFAULT_RX_NUM_BUFS;
	rx_bufs_batch           = MCE_DEFAULT_RX_BUFS_BATCH;
	rx_num_wr               = MCE_DEFAULT_RX_NUM_WRE;
	rx_num_wr_to_post_recv  = MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV;
	rx_poll_num             = MCE_DEFAULT_RX_NUM_POLLS;
	rx_poll_num_init        = MCE_DEFAULT_RX_NUM_POLLS_INIT;
	rx_udp_poll_os_ratio    = MCE_DEFAULT_RX_UDP_POLL_OS_RATIO;
	hw_ts_conversion_mode   = MCE_DEFAULT_HW_TS_CONVERSION_MODE;
	rx_sw_csum         	= MCE_DEFUALT_RX_SW_CSUM;
	rx_poll_yield_loops     = MCE_DEFAULT_RX_POLL_YIELD;
	select_handle_cpu_usage_stats   = MCE_DEFAULT_SELECT_CPU_USAGE_STATS;
	rx_ready_byte_min_limit = MCE_DEFAULT_RX_BYTE_MIN_LIMIT;
	rx_prefetch_bytes	= MCE_DEFAULT_RX_PREFETCH_BYTES;
	rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
	rx_cq_drain_rate_nsec 	= MCE_DEFAULT_RX_CQ_DRAIN_RATE;
	rx_delta_tsc_between_cq_polls = 0;

	gro_streams_max		= MCE_DEFAULT_GRO_STREAMS_MAX;

	tcp_3t_rules		= MCE_DEFAULT_TCP_3T_RULES;
	eth_mc_l2_only_rules	= MCE_DEFAULT_ETH_MC_L2_ONLY_RULES;
	mc_force_flowtag	= MCE_DEFAULT_MC_FORCE_FLOWTAG;

	select_poll_num		= MCE_DEFAULT_SELECT_NUM_POLLS;
	select_poll_os_force	= MCE_DEFAULT_SELECT_POLL_OS_FORCE;
	select_poll_os_ratio	= MCE_DEFAULT_SELECT_POLL_OS_RATIO;
	select_skip_os_fd_check	= MCE_DEFAULT_SELECT_SKIP_OS;

	cq_moderation_enable	= MCE_DEFAULT_CQ_MODERATION_ENABLE;
	cq_moderation_count = MCE_DEFAULT_CQ_MODERATION_COUNT;
	cq_moderation_period_usec = MCE_DEFAULT_CQ_MODERATION_PERIOD_USEC;
	cq_aim_max_count	= MCE_DEFAULT_CQ_AIM_MAX_COUNT;
	cq_aim_max_period_usec = MCE_DEFAULT_CQ_AIM_MAX_PERIOD_USEC;
	cq_aim_interval_msec = MCE_DEFAULT_CQ_AIM_INTERVAL_MSEC;
	cq_aim_interrupts_rate_per_sec = MCE_DEFAULT_CQ_AIM_INTERRUPTS_RATE_PER_SEC;

	cq_poll_batch_max	= MCE_DEFAULT_CQ_POLL_BATCH;
	progress_engine_interval_msec	= MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC;
	progress_engine_wce_max	= MCE_DEFAULT_PROGRESS_ENGINE_WCE_MAX;
	cq_keep_qp_full		= MCE_DEFAULT_CQ_KEEP_QP_FULL;
	qp_compensation_level	= MCE_DEFAULT_QP_COMPENSATION_LEVEL;
	internal_thread_arm_cq_enabled	= MCE_DEFAULT_INTERNAL_THREAD_ARM_CQ_ENABLED;

	offloaded_sockets	= MCE_DEFAULT_OFFLOADED_SOCKETS;
	timer_resolution_msec	= MCE_DEFAULT_TIMER_RESOLUTION_MSEC;
	tcp_timer_resolution_msec= MCE_DEFAULT_TCP_TIMER_RESOLUTION_MSEC;
	internal_thread_tcp_timer_handling = MCE_DEFAULT_INTERNAL_THREAD_TCP_TIMER_HANDLING;
	tcp_ctl_thread		= MCE_DEFAULT_TCP_CTL_THREAD;
	tcp_ts_opt		= MCE_DEFAULT_TCP_TIMESTAMP_OPTION;
	tcp_nodelay		= MCE_DEFAULT_TCP_NODELAY;
	tcp_quickack		= MCE_DEFAULT_TCP_QUICKACK;
//	exception_handling is handled by its CTOR
	avoid_sys_calls_on_tcp_fd = MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD;
	allow_privileged_sock_opt = MCE_DEFAULT_ALLOW_PRIVILEGED_SOCK_OPT;
	wait_after_join_msec	= MCE_DEFAULT_WAIT_AFTER_JOIN_MSEC;
	thread_mode		= MCE_DEFAULT_THREAD_MODE;
	buffer_batching_mode	= MCE_DEFAULT_BUFFER_BATCHING_MODE;
	mem_alloc_type          = MCE_DEFAULT_MEM_ALLOC_TYPE;
	enable_ipoib		= MCE_DEFAULT_IPOIB_FLAG;
	handle_fork		= MCE_DEFAULT_FORK_SUPPORT;
	handle_bf		= MCE_DEFAULT_BF_FLAG;
	close_on_dup2		= MCE_DEFAULT_CLOSE_ON_DUP2;
	mtu			= MCE_DEFAULT_MTU;
	lwip_mss		= MCE_DEFAULT_MSS;
	lwip_cc_algo_mod	= MCE_DEFAULT_LWIP_CC_ALGO_MOD;
	mce_spec		= MCE_SPEC_NONE;
	mce_spec_param1		= 1;
	mce_spec_param2		= 1;

	neigh_num_err_retries	= MCE_DEFAULT_NEIGH_NUM_ERR_RETRIES;
	neigh_uc_arp_quata	= MCE_DEFAULT_NEIGH_UC_ARP_QUATA;
	neigh_wait_till_send_arp_msec = MCE_DEFAULT_NEIGH_UC_ARP_DELAY_MSEC;
	timer_netlink_update_msec = MCE_DEFAULT_NETLINK_TIMER_MSEC;

	rx_poll_on_tx_tcp	= MCE_DEFAULT_RX_POLL_ON_TX_TCP;
	trigger_dummy_send_getsockname = MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME;

#ifdef VMA_TIME_MEASURE
	vma_time_measure_num_samples = MCE_DEFAULT_TIME_MEASURE_NUM_SAMPLES;
#endif

	is_hypervisor = cpuid_hv();

	if ((env_ptr = getenv(SYS_VAR_SPEC)) != NULL){
		mce_spec = (uint32_t)vma_spec::from_str(env_ptr, MCE_SPEC_NONE);
	}

	switch (mce_spec) {
	case MCE_SPEC_SOCKPERF_ULTRA_LATENCY_10:
		tx_num_segs_tcp         = 512; //MCE_DEFAULT_TX_NUM_SEGS_TCP (1000000)
		tx_num_bufs             = 512; //MCE_DEFAULT_TX_NUM_BUFS (200000)
		tx_num_wr               = 256; //MCE_DEFAULT_TX_NUM_WRE (3000)
		tx_num_wr_to_signal     = 4; //MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL (64)
		tx_prefetch_bytes 	= MCE_DEFAULT_TX_PREFETCH_BYTES; //(256)
		tx_bufs_batch_udp	= 1; //MCE_DEFAULT_TX_BUFS_BATCH_UDP (8)
		tx_bufs_batch_tcp	= 1; //MCE_DEFAULT_TX_BUFS_BATCH_TCP;
		rx_num_bufs             = 1024; //MCE_DEFAULT_RX_NUM_BUFS (200000)
		rx_bufs_batch           = 4; //MCE_DEFAULT_RX_BUFS_BATCH (64)
		rx_num_wr               = 256; //MCE_DEFAULT_RX_NUM_WRE (16000)
		rx_num_wr_to_post_recv  = 4; //MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV (64)
		rx_poll_num             = -1; //MCE_DEFAULT_RX_NUM_POLLS
		rx_udp_poll_os_ratio    = 0; //MCE_DEFAULT_RX_UDP_POLL_OS_RATIO
		rx_prefetch_bytes	= MCE_DEFAULT_RX_PREFETCH_BYTES; //(256)
		rx_prefetch_bytes_before_poll = 256; //MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL 0
		select_poll_num         = -1;
		select_poll_os_ratio    = 0;
		select_skip_os_fd_check = 0;
		avoid_sys_calls_on_tcp_fd = true; //MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD (false)
		gro_streams_max		= 0; //MCE_DEFAULT_GRO_STREAMS_MAX (32)
		progress_engine_interval_msec = 0;
		cq_keep_qp_full		= false; //MCE_DEFAULT_CQ_KEEP_QP_FULL(true)
		thread_mode		= THREAD_MODE_SINGLE;
		mem_alloc_type          = ALLOC_TYPE_HUGEPAGES;
		tcp_nodelay		= true; // MCE_DEFAULT_TCP_NODELAY (false)
		ring_dev_mem_tx         = 16384; // MCE_DEFAULT_RING_DEV_MEM_TX (0)
		strcpy(internal_thread_affinity_str, "0"); //MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR;
		break;

	case MCE_SPEC_SOCKPERF_LATENCY_15:
		tx_num_wr         	= 256; //MCE_DEFAULT_TX_NUM_WRE (3000)
		tx_num_wr_to_signal     = 4;   //MCE_DEFAULT_TX_NUM_WRE_TO_SIGNAL(64)
		tx_bufs_batch_udp	= 1;   //MCE_DEFAULT_TX_BUFS_BATCH_UDP (8)
		tx_bufs_batch_tcp	= 1;   //MCE_DEFAULT_TX_BUFS_BATCH_TCP (16)
		rx_bufs_batch           = 4;   //MCE_DEFAULT_RX_BUFS_BATCH (64)
		rx_num_wr               = 256; //MCE_DEFAULT_RX_NUM_WRE (16000)
		rx_num_wr_to_post_recv  = 4;   //MCE_DEFAULT_RX_NUM_WRE_TO_POST_RECV (64)
		rx_poll_num             = -1;  //MCE_DEFAULT_RX_NUM_POLLS (100000)
		rx_prefetch_bytes_before_poll = 256; //MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL (0)
		select_poll_num         = -1;  //MCE_DEFAULT_SELECT_NUM_POLLS (100000)
		avoid_sys_calls_on_tcp_fd = true; //MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD (false)
		gro_streams_max		= 0; //MCE_DEFAULT_GRO_STREAMS_MAX (32)
		cq_keep_qp_full		= false; //MCE_DEFAULT_CQ_KEEP_QP_FULL (true)
		thread_mode 		= THREAD_MODE_SINGLE; //MCE_DEFAULT_THREAD_MODE (THREAD_MODE_MULTI)
		mem_alloc_type 		= ALLOC_TYPE_HUGEPAGES; //MCE_DEFAULT_MEM_ALLOC_TYPE (ALLOC_TYPE_CONTIG)
		strcpy(internal_thread_affinity_str, "0"); //MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR ("-1")
		progress_engine_interval_msec = 100; //MCE_DEFAULT_PROGRESS_ENGINE_INTERVAL_MSEC (10)
		select_poll_os_ratio          = 100; //MCE_DEFAULT_SELECT_POLL_OS_RATIO (10)
		select_poll_os_force	      = 1;   //MCE_DEFAULT_SELECT_POLL_OS_FORCE (0)
		tcp_nodelay	      	      = true; // MCE_DEFAULT_TCP_NODELAY (falst)
		ring_dev_mem_tx          = 16384; // MCE_DEFAULT_RING_DEV_MEM_TX (0)
		break;

	case MCE_SPEC_29WEST_LBM_29:
		mce_spec_param1         = 5000;	// [u-sec] Time out to send next pipe_write
		mce_spec_param2         = 50;	// Num of max sequential pipe_write to drop
		rx_poll_num             = 0;
		rx_udp_poll_os_ratio    = 100;
		select_poll_num         = 100000;
		select_poll_os_ratio    = 100;
		select_skip_os_fd_check = 50;
		break;

	case MCE_SPEC_WOMBAT_FH_LBM_554:
		mce_spec_param1         = 5000;	// [u-sec] Time out to send next pipe_write
		mce_spec_param2         = 50;	// Num of max sequential pipe_write to drop
		rx_poll_num             = 0;
		rx_udp_poll_os_ratio    = 100;
		select_poll_num         = 0;
		select_skip_os_fd_check = 20;
		break;

	case MCE_SPEC_RTI_784:
		rx_poll_num             = -1;
// TODO - Need to replace old QP/CQ allocation logic here
//		qp_allocation_logic 	= QP_ALLOC_LOGIC__QP_PER_PEER_IP_PER_LOCAL_IP;
//		cq_allocation_logic	= CQ_ALLOC_LOGIC__CQ_PER_QP;
		break;

	case MCE_SPEC_MCD_623:
		ring_allocation_logic_rx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		ring_allocation_logic_tx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		break;

	case MCE_SPEC_MCD_IRQ_624:
		ring_allocation_logic_rx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		ring_allocation_logic_tx = RING_LOGIC_PER_CORE_ATTACH_THREADS;
		select_poll_num = 0;
		rx_poll_num = 0;
		cq_moderation_enable = false;
		break;

	case MCE_SPEC_LL_7750:
		tx_num_bufs               = 8192; // MCE_DEFAULT_TX_NUM_BUFS (200000), Global TX data buffers allocated
		rx_num_bufs               = 204800; // MCE_DEFAULT_RX_NUM_BUFS (200000), RX data buffers used on all QPs on all HCAs
		log_level                 = VLOG_WARNING; //VLOG_DEFAULT(VLOG_INFO) VMA_TRACELEVEL
		stats_fd_num_max          = 1024; //MCE_DEFAULT_STATS_FD_NUM(100), max. number of sockets monitored by VMA stats
		strcpy(internal_thread_affinity_str, "0x3"); // MCE_DEFAULT_INTERNAL_THREAD_AFFINITY_STR(-1), first 2 cores
		rx_poll_num               = -1; //MCE_DEFAULT_RX_NUM_POLLS(100000), Infinite RX poll for ready packets (during read/recv)
		select_poll_num           = -1;	//MCE_DEFAULT_SELECT_NUM_POLLS(100000), Infinite poll the hardware on RX (before sleeping in epoll/select, etc)
		select_poll_os_ratio      = 0;  //MCE_DEFAULT_SELECT_POLL_OS_RATIO(10), Disable polling OS fd's (re-enabled if bound on OS fd)
		tcp_3t_rules              = true; //MCE_DEFAULT_TCP_3T_RULES(false), Use only 3 tuple rules for TCP
		avoid_sys_calls_on_tcp_fd = 1; //MCE_DEFAULT_AVOID_SYS_CALLS_ON_TCP_FD (false), Disable handling control packets on a separate thread
		buffer_batching_mode      = BUFFER_BATCHING_NONE; //MCE_DEFAULT_BUFFER_BATCHING_MODE(BUFFER_BATCHING_WITH_RECLAIM), Disable handling control packets on a separate thread
		tcp_ctl_thread            = CTL_THREAD_NO_WAKEUP; //MCE_DEFAULT_TCP_CTL_THREAD (CTL_THREAD_DISABLE), wait for thread timer to expire
		break;

	case MCE_SPEC_LL_MULTI_RING:
		mem_alloc_type           = ALLOC_TYPE_HUGEPAGES; //MCE_DEFAULT_MEM_ALLOC_TYPE (ALLOC_TYPE_CONTIG) VMA_MEM_ALLOC_TYPE
		select_poll_num          = -1; //MCE_DEFAULT_SELECT_NUM_POLLS (100000) VMA_SELECT_POLL
		rx_poll_num              = -1; //MCE_DEFAULT_RX_NUM_POLLS(100000) VMA_RX_POLL
		ring_allocation_logic_tx = RING_LOGIC_PER_THREAD; //MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX(RING_LOGIC_PER_INTERFACE) VMA_RING_ALLOCATION_LOGIC_TX
		ring_allocation_logic_rx = RING_LOGIC_PER_THREAD; //MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX(RING_LOGIC_PER_INTERFACE) VMA_RING_ALLOCATION_LOGIC_RX
		select_poll_os_ratio     = 0; //MCE_DEFAULT_SELECT_POLL_OS_RATIO(10) VMA_SELECT_POLL_OS_RATIO
		select_skip_os_fd_check  = 0; //MCE_DEFAULT_SELECT_SKIP_OS(4) VMA_SELECT_SKIP_OS
		rx_poll_on_tx_tcp        = true; //MCE_DEFAULT_RX_POLL_ON_TX_TCP (false)
		trigger_dummy_send_getsockname = true; //MCE_DEFAULT_TRIGGER_DUMMY_SEND_GETSOCKNAME (false)
		break;

	case MCE_SPEC_NONE:
	default:
		break;
	}

	if ((env_ptr = getenv(SYS_VAR_SPEC_PARAM1)) != NULL)
		mce_spec_param1 = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SPEC_PARAM2)) != NULL)
		mce_spec_param2 = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_LOG_FILENAME)) != NULL){
		read_env_variable_with_pid(log_filename, sizeof(log_filename), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_STATS_FILENAME)) != NULL){
		read_env_variable_with_pid(stats_filename, sizeof(stats_filename), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_STATS_SHMEM_DIRNAME)) != NULL){
		read_env_variable_with_pid(stats_shmem_dirname, sizeof(stats_shmem_dirname), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_CONF_FILENAME)) != NULL){
		read_env_variable_with_pid(conf_filename, sizeof(conf_filename), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_LOG_LEVEL)) != NULL)
		log_level = log_level::from_str(env_ptr, VLOG_DEFAULT);

	if (log_level >= VLOG_DEBUG)
		log_details = 2;

	if ((env_ptr = getenv(SYS_VAR_LOG_DETAILS)) != NULL)
		log_details = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_LOG_COLORS)) != NULL)
		log_colors = atoi(env_ptr) ? true : false;
	
	if ((env_ptr = getenv(SYS_VAR_APPLICATION_ID)) != NULL){
		read_env_variable_with_pid(app_id, sizeof(app_id), env_ptr);
	}

	if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGINTR)) != NULL)
		handle_sigintr = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_HANDLE_SIGSEGV)) != NULL)
		handle_segfault = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_STATS_FD_NUM)) != NULL) {
		stats_fd_num_max = (uint32_t)atoi(env_ptr);
		if (stats_fd_num_max > MAX_STATS_FD_NUM) {
			vlog_printf(VLOG_WARNING," Can only monitor maximum %d sockets in statistics \n", MAX_STATS_FD_NUM);
			stats_fd_num_max = MAX_STATS_FD_NUM;
		}
	}


	if ((env_ptr = getenv(SYS_VAR_TX_NUM_SEGS_TCP)) != NULL)
		tx_num_segs_tcp = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_NUM_BUFS)) != NULL)
		tx_num_bufs = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE)) != NULL)
		tx_num_wr = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TX_NUM_WRE_TO_SIGNAL)) != NULL)
		tx_num_wr_to_signal = MIN(NUM_TX_WRE_TO_SIGNAL_MAX, MAX(1, (uint32_t)atoi(env_ptr)));
	if (tx_num_wr <= (tx_num_wr_to_signal * 2))
		tx_num_wr = tx_num_wr_to_signal * 2;

	if ((env_ptr = getenv(SYS_VAR_TX_MAX_INLINE)) != NULL)
		tx_max_inline = (uint32_t)atoi(env_ptr);
	if (tx_max_inline > MAX_SUPPORTED_IB_INLINE_SIZE) {
		vlog_printf(VLOG_WARNING,"VMA_TX_MAX_INLINE  must be smaller or equal to %d [%d]\n",
				MAX_SUPPORTED_IB_INLINE_SIZE, tx_max_inline);
		tx_max_inline = MAX_SUPPORTED_IB_INLINE_SIZE;
	}
	unsigned int cx4_max_tx_wre_for_inl = (16 * 1024 * 64) / (VMA_ALIGN(VMA_ALIGN(tx_max_inline - 12, 64) + 12, 64));
	if (tx_num_wr > cx4_max_tx_wre_for_inl) {
		vlog_printf(VLOG_WARNING,"For the given VMA_TX_MAX_INLINE [%d], VMA_TX_WRE [%d] must be smaller than %d\n",
				tx_max_inline, tx_num_wr, cx4_max_tx_wre_for_inl);
		tx_num_wr = cx4_max_tx_wre_for_inl;
	}

	if ((env_ptr = getenv(SYS_VAR_TX_MC_LOOPBACK)) != NULL)
		tx_mc_loopback_default = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_TX_NONBLOCKED_EAGAINS)) != NULL)
		tx_nonblocked_eagains = atoi(env_ptr)? true : false;

	if ((env_ptr = getenv(SYS_VAR_TX_PREFETCH_BYTES)) != NULL)
		tx_prefetch_bytes = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_TX)) != NULL) {
		ring_allocation_logic_tx = (ring_logic_t)atoi(env_ptr);
		if (!is_ring_logic_valid(ring_allocation_logic_tx)) {
			vlog_printf(VLOG_WARNING,"%s = %d is not valid, setting logic to default = %d\n",
					SYS_VAR_RING_ALLOCATION_LOGIC_TX, ring_allocation_logic_tx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX);
			ring_allocation_logic_tx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_TX;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_RING_ALLOCATION_LOGIC_RX)) != NULL) {
		ring_allocation_logic_rx = (ring_logic_t)atoi(env_ptr);
		if (!is_ring_logic_valid(ring_allocation_logic_rx)) {
			vlog_printf(VLOG_WARNING,"%s = %d is not valid, setting logic to default = %d\n",
					SYS_VAR_RING_ALLOCATION_LOGIC_RX, ring_allocation_logic_rx, MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX);
			ring_allocation_logic_rx = MCE_DEFAULT_RING_ALLOCATION_LOGIC_RX;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_TX)) != NULL)
		ring_migration_ratio_tx = (int32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_MIGRATION_RATIO_RX)) != NULL)
		ring_migration_ratio_rx = (int32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RING_LIMIT_PER_INTERFACE)) != NULL)
		ring_limit_per_interface = MAX(0, (int32_t)atoi(env_ptr));

	if ((env_ptr = getenv(SYS_VAR_RING_DEV_MEM_TX)) != NULL)
		ring_dev_mem_tx = MAX(0, (int32_t)atoi(env_ptr));

	if ((env_ptr = getenv(SYS_VAR_TCP_MAX_SYN_RATE)) != NULL)
		tcp_max_syn_rate = MIN(TCP_MAX_SYN_RATE_TOP_LIMIT, MAX(0, (int32_t)atoi(env_ptr)));

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_BUFS)) != NULL)
		rx_num_bufs = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE_TO_POST_RECV)) != NULL)
		rx_num_wr_to_post_recv = MIN(NUM_RX_WRE_TO_POST_RECV_MAX, MAX(1, (uint32_t)atoi(env_ptr)));

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_WRE)) != NULL)
		rx_num_wr = (uint32_t)atoi(env_ptr);
	if (rx_num_wr <= (rx_num_wr_to_post_recv * 2))
		rx_num_wr = rx_num_wr_to_post_recv * 2;

	if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS)) != NULL) {
		rx_poll_num = atoi(env_ptr);
	}
	if (rx_poll_num < MCE_MIN_RX_NUM_POLLS || rx_poll_num >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Rx Poll loops should be between %d and %d [%d]\n", MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num);
		rx_poll_num = MCE_DEFAULT_RX_NUM_POLLS;
	}
	if ((env_ptr = getenv(SYS_VAR_RX_NUM_POLLS_INIT)) != NULL)
		rx_poll_num_init = atoi(env_ptr);
	if (rx_poll_num_init < MCE_MIN_RX_NUM_POLLS || rx_poll_num_init >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Rx Poll loops should be between %d and %d [%d]\n", MCE_MIN_RX_NUM_POLLS, MCE_MAX_RX_NUM_POLLS, rx_poll_num_init);
		rx_poll_num_init = MCE_DEFAULT_RX_NUM_POLLS_INIT;
	}
	if (rx_poll_num == 0)
		rx_poll_num = 1; // Force at least one good polling loop

	if ((env_ptr = getenv(SYS_VAR_RX_UDP_POLL_OS_RATIO)) != NULL)
		rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_HW_TS_CONVERSION_MODE)) != NULL) {
		hw_ts_conversion_mode = (ts_conversion_mode_t)atoi(env_ptr);
		if ((uint32_t)hw_ts_conversion_mode >= TS_CONVERSION_MODE_LAST) {
			vlog_printf(VLOG_WARNING,"HW TS conversion size out of range [%d] (min=%d, max=%d). using default [%d]\n", hw_ts_conversion_mode, TS_CONVERSION_MODE_DISABLE , TS_CONVERSION_MODE_LAST - 1, MCE_DEFAULT_HW_TS_CONVERSION_MODE);
			hw_ts_conversion_mode = MCE_DEFAULT_HW_TS_CONVERSION_MODE;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_RX_SW_CSUM)) != NULL) {
		rx_sw_csum = atoi(env_ptr) ? true : false;
	}

	//The following 2 params were replaced by SYS_VAR_RX_UDP_POLL_OS_RATIO
	if ((env_ptr = getenv(SYS_VAR_RX_POLL_OS_RATIO)) != NULL) {
		rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
		vlog_printf(VLOG_WARNING,"The parameter VMA_RX_POLL_OS_RATIO is no longer in use. Parameter VMA_RX_UDP_POLL_OS_RATIO was set to %d instead\n", rx_udp_poll_os_ratio);
	}
	if ((env_ptr = getenv(SYS_VAR_RX_SKIP_OS)) != NULL) {
		rx_udp_poll_os_ratio = (uint32_t)atoi(env_ptr);
		vlog_printf(VLOG_WARNING,"The parameter VMA_RX_SKIP_OS is no longer in use. Parameter VMA_RX_UDP_POLL_OS_RATIO was set to %d instead\n", rx_udp_poll_os_ratio);
	}

	if ((env_ptr = getenv(SYS_VAR_RX_POLL_YIELD)) != NULL)
		rx_poll_yield_loops = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_CPU_USAGE_STATS)) != NULL)
		select_handle_cpu_usage_stats = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_RX_BYTE_MIN_LIMIT)) != NULL)
		rx_ready_byte_min_limit = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES)) != NULL)
		rx_prefetch_bytes = (uint32_t)atoi(env_ptr);
	if (rx_prefetch_bytes < MCE_MIN_RX_PREFETCH_BYTES || rx_prefetch_bytes >  MCE_MAX_RX_PREFETCH_BYTES) {
		vlog_printf(VLOG_WARNING," Rx prefetch bytes size out of range [%d] (min=%d, max=%d)\n", rx_prefetch_bytes, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
		rx_prefetch_bytes = MCE_DEFAULT_RX_PREFETCH_BYTES;
	}

	if ((env_ptr = getenv(SYS_VAR_RX_PREFETCH_BYTES_BEFORE_POLL)) != NULL)
		rx_prefetch_bytes_before_poll = (uint32_t)atoi(env_ptr);
	if (rx_prefetch_bytes_before_poll != 0 && (rx_prefetch_bytes_before_poll < MCE_MIN_RX_PREFETCH_BYTES || rx_prefetch_bytes_before_poll >  MCE_MAX_RX_PREFETCH_BYTES)) {
		vlog_printf(VLOG_WARNING," Rx prefetch bytes size out of range [%d] (min=%d, max=%d, disabled=0)\n", rx_prefetch_bytes_before_poll, MCE_MIN_RX_PREFETCH_BYTES, MCE_MAX_RX_PREFETCH_BYTES);
		rx_prefetch_bytes_before_poll = MCE_DEFAULT_RX_PREFETCH_BYTES_BEFORE_POLL;
	}

	if ((env_ptr = getenv(SYS_VAR_RX_CQ_DRAIN_RATE_NSEC)) != NULL)
		rx_cq_drain_rate_nsec = atoi(env_ptr);
	// Update the rx cq polling rate for draining logic
	tscval_t tsc_per_second = get_tsc_rate_per_second();
	rx_delta_tsc_between_cq_polls = tsc_per_second * rx_cq_drain_rate_nsec / NSEC_PER_SEC;

	if ((env_ptr = getenv(SYS_VAR_GRO_STREAMS_MAX)) != NULL)
		gro_streams_max = MAX(atoi(env_ptr), 0);

	if ((env_ptr = getenv(SYS_VAR_TCP_3T_RULES)) != NULL)
		tcp_3t_rules = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_ETH_MC_L2_ONLY_RULES)) != NULL)
		eth_mc_l2_only_rules = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_MC_FORCE_FLOWTAG)) != NULL)
		mc_force_flowtag = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_SELECT_NUM_POLLS)) != NULL)
		select_poll_num = atoi(env_ptr);

	if (select_poll_num < MCE_MIN_RX_NUM_POLLS || select_poll_num >  MCE_MAX_RX_NUM_POLLS) {
		vlog_printf(VLOG_WARNING," Select Poll loops can not be below zero [%d]\n", select_poll_num);
		select_poll_num = MCE_DEFAULT_SELECT_NUM_POLLS;
	}

	if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_FORCE)) != NULL)
		select_poll_os_force = (uint32_t)atoi(env_ptr);

	if (select_poll_os_force) {
		select_poll_os_ratio = 1;
		select_skip_os_fd_check = 1;
	}

	if ((env_ptr = getenv(SYS_VAR_SELECT_POLL_OS_RATIO)) != NULL)
		select_poll_os_ratio = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_SELECT_SKIP_OS)) != NULL)
		select_skip_os_fd_check = (uint32_t)atoi(env_ptr);

#ifdef DEFINED_IBV_EXP_CQ_MODERATION
	if (rx_poll_num < 0 ||  select_poll_num < 0) {
		cq_moderation_enable = false;
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE)) != NULL)
		cq_moderation_enable = atoi(env_ptr) ? true : false;
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT)) != NULL)
		cq_moderation_count = (uint32_t)atoi(env_ptr);
	if (cq_moderation_count > rx_num_wr / 2) {
		cq_moderation_count = rx_num_wr / 2;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC)) != NULL)
		cq_moderation_period_usec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT)) != NULL)
		cq_aim_max_count = (uint32_t)atoi(env_ptr);
	if (cq_aim_max_count > rx_num_wr / 2){
		cq_aim_max_count = rx_num_wr / 2;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC)) != NULL)
		cq_aim_max_period_usec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC)) != NULL)
		cq_aim_interval_msec = (uint32_t)atoi(env_ptr);

	if (!cq_moderation_enable) {
		cq_aim_interval_msec = MCE_CQ_ADAPTIVE_MODERATION_DISABLED;
	}

	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC)) != NULL)
		cq_aim_interrupts_rate_per_sec = (uint32_t)atoi(env_ptr);
#else
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_ENABLE)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_MODERATION_ENABLE);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_COUNT)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_MODERATION_COUNT);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_MODERATION_PERIOD_USEC)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_MODERATION_PERIOD_USEC);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_COUNT)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_AIM_MAX_COUNT);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_MAX_PERIOD_USEC)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_AIM_MAX_PERIOD_USEC);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERVAL_MSEC)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_AIM_INTERVAL_MSEC);
	}
	if ((env_ptr = getenv(SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC)) != NULL) {
		vlog_printf(VLOG_WARNING,"'%s' is not supported on this environment\n", SYS_VAR_CQ_AIM_INTERRUPTS_RATE_PER_SEC);
	}
#endif /*DEFINED_IBV_EXP_CQ_MODERATION*/

	if ((env_ptr = getenv(SYS_VAR_CQ_POLL_BATCH_MAX)) != NULL)
		cq_poll_batch_max = (uint32_t)atoi(env_ptr);
	if (cq_poll_batch_max < MCE_MIN_CQ_POLL_BATCH || cq_poll_batch_max >  MCE_MAX_CQ_POLL_BATCH) {
		vlog_printf(VLOG_WARNING," Rx number of cq poll batchs should be between %d and %d [%d]\n", MCE_MIN_CQ_POLL_BATCH, MCE_MAX_CQ_POLL_BATCH, cq_poll_batch_max);
		cq_poll_batch_max = MCE_DEFAULT_CQ_POLL_BATCH;
	}

	if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_INTERVAL)) != NULL)
		progress_engine_interval_msec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_PROGRESS_ENGINE_WCE_MAX)) != NULL)
		progress_engine_wce_max = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_CQ_KEEP_QP_FULL)) != NULL)
		cq_keep_qp_full = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_QP_COMPENSATION_LEVEL)) != NULL)
		qp_compensation_level = (uint32_t)atoi(env_ptr);
	if (qp_compensation_level < rx_num_wr_to_post_recv)
		qp_compensation_level = rx_num_wr_to_post_recv;

	if ((env_ptr = getenv(SYS_VAR_OFFLOADED_SOCKETS)) != NULL)
		offloaded_sockets = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_TIMER_RESOLUTION_MSEC)) != NULL)
		timer_resolution_msec = atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TCP_TIMER_RESOLUTION_MSEC)) != NULL)
		tcp_timer_resolution_msec = atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_TCP_TIMER_HANDLING)) != NULL) {
		internal_thread_tcp_timer_handling =
		atoi(env_ptr) == 1 ?  INTERNAL_THREAD_TCP_TIMER_HANDLING_IMMEDIATE : INTERNAL_THREAD_TCP_TIMER_HANDLING_DEFERRED;
	}

	if ((env_ptr = getenv(SYS_VAR_TCP_CTL_THREAD)) != NULL) {
		tcp_ctl_thread = (tcp_ctl_thread_t)atoi(env_ptr);
		if (tcp_ctl_thread >= CTL_THREAD_LAST || tcp_ctl_thread < 0)
			tcp_ctl_thread = MCE_DEFAULT_TCP_CTL_THREAD;
	}

	if ((env_ptr = getenv(SYS_VAR_TCP_TIMESTAMP_OPTION)) != NULL) {
		tcp_ts_opt = (tcp_ts_opt_t)atoi(env_ptr);
		if ((uint32_t) tcp_ts_opt >= TCP_TS_OPTION_LAST) {
			vlog_printf(VLOG_WARNING,"TCP timestamp option value is out of range [%d] (min=%d, max=%d). using default [%d]\n", tcp_ts_opt, TCP_TS_OPTION_DISABLE , TCP_TS_OPTION_LAST - 1, MCE_DEFAULT_TCP_TIMESTAMP_OPTION);
			tcp_ts_opt = MCE_DEFAULT_TCP_TIMESTAMP_OPTION;
		}
	}

	if ((env_ptr = getenv(SYS_VAR_TCP_NODELAY)) != NULL) {
		tcp_nodelay = atoi(env_ptr) ? true : false;
	}

	if ((env_ptr = getenv(SYS_VAR_TCP_QUICKACK)) != NULL) {
		tcp_quickack = atoi(env_ptr) ? true : false;
	}

	// TODO: this should be replaced by calling "exception_handling.init()" that will be called from init()
	if ((env_ptr = getenv(vma_exception_handling::getSysVar())) != NULL) {
		exception_handling = vma_exception_handling(strtol(env_ptr, NULL, 10)); // vma_exception_handling is responsible for its invariant
	}

	if ((env_ptr = getenv(SYS_VAR_AVOID_SYS_CALLS_ON_TCP_FD)) != NULL) {
		avoid_sys_calls_on_tcp_fd = atoi(env_ptr) ? true : false;
	}

	if ((env_ptr = getenv(SYS_VAR_ALLOW_PRIVILEGED_SOCK_OPT)) != NULL) {
		allow_privileged_sock_opt = atoi(env_ptr) ? true : false;
	}

	if(tcp_timer_resolution_msec < timer_resolution_msec){
		vlog_printf(VLOG_WARNING," TCP timer resolution [%s=%d] cannot be smaller than timer resolution [%s=%d]. Setting TCP timer resolution to %d msec.\n", SYS_VAR_TCP_TIMER_RESOLUTION_MSEC, tcp_timer_resolution_msec, SYS_VAR_TIMER_RESOLUTION_MSEC, timer_resolution_msec, timer_resolution_msec);
		tcp_timer_resolution_msec = timer_resolution_msec;
	}

	if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_ARM_CQ)) != NULL)
		internal_thread_arm_cq_enabled = atoi(env_ptr) ? true : false;

        if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_CPUSET)) != NULL) {
               snprintf(internal_thread_cpuset, FILENAME_MAX, "%s", env_ptr);
        }

	// handle internal thread affinity - default is CPU-0
	if ((env_ptr = getenv(SYS_VAR_INTERNAL_THREAD_AFFINITY)) != NULL) {
		int n = snprintf(internal_thread_affinity_str,
				sizeof(internal_thread_affinity_str), "%s", env_ptr);
		if (unlikely(((int)sizeof(internal_thread_affinity_str) < n) || (n < 0))) {
			vlog_printf(VLOG_WARNING,"Failed to process: %s.\n",
					SYS_VAR_INTERNAL_THREAD_AFFINITY);
		}
	}
	if (env_to_cpuset(internal_thread_affinity_str, &internal_thread_affinity)) {
		vlog_printf(VLOG_WARNING," Failed to set internal thread affinity: %s...  deferring to cpu-0.\n",
		            internal_thread_affinity_str);
	}

	if ((env_ptr = getenv(SYS_VAR_WAIT_AFTER_JOIN_MSEC)) != NULL)
		wait_after_join_msec = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_THREAD_MODE)) != NULL) {
		thread_mode = (thread_mode_t)atoi(env_ptr);
		if (thread_mode < 0 || thread_mode >= THREAD_MODE_LAST)
			thread_mode = MCE_DEFAULT_THREAD_MODE;
	}

	if ((env_ptr = getenv(SYS_VAR_BUFFER_BATCHING_MODE)) != NULL) {
		buffer_batching_mode = (buffer_batching_mode_t)atoi(env_ptr);
		if (buffer_batching_mode < 0 || buffer_batching_mode >= BUFFER_BATCHING_LAST)
			buffer_batching_mode = MCE_DEFAULT_BUFFER_BATCHING_MODE;
	}

	if (buffer_batching_mode == BUFFER_BATCHING_NONE) {
		tx_bufs_batch_tcp = 1;
		tx_bufs_batch_udp = 1;
		rx_bufs_batch = 1;
	}

	if ((env_ptr = getenv(SYS_VAR_NETLINK_TIMER_MSEC)) != NULL)
		timer_netlink_update_msec = (uint32_t)atoi(env_ptr);


	if((env_ptr = getenv(SYS_VAR_NEIGH_NUM_ERR_RETRIES))!= NULL)  {
		neigh_num_err_retries = (uint32_t)atoi(env_ptr);
	}
	if((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_DELAY_MSEC)) != NULL){
		neigh_wait_till_send_arp_msec = (uint32_t)atoi(env_ptr);
	}
	if((env_ptr = getenv(SYS_VAR_NEIGH_UC_ARP_QUATA)) != NULL){
		neigh_uc_arp_quata = (uint32_t)atoi(env_ptr);
	}

	if ((getenv(SYS_VAR_HUGETBL)) != NULL)
	{
		vlog_printf(VLOG_WARNING, "**********************************************************************************************************************\n");
		vlog_printf(VLOG_WARNING, "The '%s' parameter is no longer supported, please refer to '%s' in README.txt for more info\n", SYS_VAR_HUGETBL, SYS_VAR_MEM_ALLOC_TYPE);
		vlog_printf(VLOG_WARNING, "**********************************************************************************************************************\n");
	}

	if ((env_ptr = getenv(SYS_VAR_MEM_ALLOC_TYPE)) != NULL)
		mem_alloc_type = (alloc_mode_t)atoi(env_ptr);
	if (mem_alloc_type < 0 || mem_alloc_type >= ALLOC_TYPE_LAST)
		mem_alloc_type = MCE_DEFAULT_MEM_ALLOC_TYPE;
	if (is_hypervisor && (mem_alloc_type == ALLOC_TYPE_CONTIG)) {
		vlog_printf(VLOG_DEBUG, "The '%s' parameter can not be %d for %s.\n",
				SYS_VAR_MEM_ALLOC_TYPE, mem_alloc_type, cpuid_hv_vendor());
		mem_alloc_type = ALLOC_TYPE_HUGEPAGES;
	}

	if ((env_ptr = getenv(SYS_VAR_BF)) != NULL)
		handle_bf = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_FORK)) != NULL)
		handle_fork = atoi(env_ptr) ? true : false;

	if((env_ptr = getenv(SYS_VAR_IPOIB )) != NULL)
		enable_ipoib = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_CLOSE_ON_DUP2)) != NULL)
		close_on_dup2 = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_MTU)) != NULL)
		mtu = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_MSS)) != NULL)
		lwip_mss = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_TCP_CC_ALGO)) != NULL)
		lwip_cc_algo_mod = (uint32_t)atoi(env_ptr);

	if ((env_ptr = getenv(SYS_VAR_VMA_RX_POLL_ON_TX_TCP)) != NULL)
		rx_poll_on_tx_tcp = atoi(env_ptr) ? true : false;

	if ((env_ptr = getenv(SYS_VAR_VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME)) != NULL)
		trigger_dummy_send_getsockname = atoi(env_ptr) ? true : false;

#ifdef VMA_TIME_MEASURE
	if ((env_ptr = getenv(SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES)) != NULL) {
		vma_time_measure_num_samples = (uint32_t)atoi(env_ptr);
		if(vma_time_measure_num_samples > INST_SIZE){
			vlog_printf(VLOG_WARNING, "The value of '%s' is bigger than %d. Time samples over %d will be dropped.\n", SYS_VAR_VMA_TIME_MEASURE_NUM_SAMPLES, INST_SIZE, INST_SIZE);
		}
	}

	if ((env_ptr = getenv(SYS_VAR_VMA_TIME_MEASURE_DUMP_FILE)) != NULL){
		read_env_variable_with_pid(vma_time_measure_filename, sizeof(vma_time_measure_filename), env_ptr);
	}
#endif

}


void set_env_params()
{
	// Need to call setenv() only after getenv() is done, because /bin/sh has
	// a custom setenv() which overrides original environment.

	//setenv("MLX4_SINGLE_THREADED", "1", 0);

	/*
	 * MLX4_DEVICE_FATAL_CLEANUP tells ibv_destroy functions we
	 * want to get success errno value in case of calling them
	 * when the device was removed.
	 * It helps to destroy resources in DEVICE_FATAL state
	 */
	setenv("MLX4_DEVICE_FATAL_CLEANUP", "1", 1);

	if (safe_mce_sys().handle_bf) {
		setenv("MLX4_POST_SEND_PREFER_BF", "1", 1);
		setenv("MLX5_POST_SEND_PREFER_BF", "1", 1);
	} else {
		/* todo - these seem not to work if inline is on, since libmlx is doing (inl || bf) when deciding to bf*/
		setenv("MLX4_POST_SEND_PREFER_BF", "0", 1);
		setenv("MLX5_POST_SEND_PREFER_BF", "0", 1);
	}

	switch (safe_mce_sys().mem_alloc_type) {
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

