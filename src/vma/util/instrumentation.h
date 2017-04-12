/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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


/*
 * VMA instrumental - measure the times that certain actions takes.
 * Currently support: RX,TX,IOMUX
 * Enable: use --enable-time-measure in ./configure
 * Parameters:
 * 	VMA_TIME_MEASURE_DUMP_FILE - Name of the results file. Default: /tmp/VMA_inst.dump
 * 	VMA_TIME_MEASURE_NUM_SAMPLES - Number of samples for a dump file. Default: 10000
 * Limitations:
 * 	- No support for multi-threading
 * 	- Support only one socket
 */

#ifndef V_INSTRUMENTATION_H
#define V_INSTRUMENTATION_H

#include <stdint.h>
#include <unistd.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "vlogger/vlogger.h"

#ifdef RDTSC_MEASURE
int reset_rdtsc_counter(int idx);
void init_rdtsc();
void print_rdtsc_summary();

#define ARR_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

// recommended ratio: 100000
#define RDTSC_PRINT_RATIO 0
#define RDTSC_PERCENTILE_BUF_SIZE (1 << 20)

#define RDTSC_TAKE_START(instr) do { \
	gettimeoftsc(&g_rdtsc_instr_info_arr[instr].start); \
} while (0)

#if defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) && !defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
#define RDTSC_TAKE_START_RX_VERBS_POLL(instr_ready, instr_idle) \
	RDTSC_TAKE_START(instr_ready)
#elif !defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) && defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
#define RDTSC_TAKE_START_RX_VERBS_POLL(instr_ready, instr_idle) \
	RDTSC_TAKE_START(instr_idle)
#elif defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) && defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
#define RDTSC_TAKE_START_RX_VERBS_POLL(instr_ready, instr_idle) do { \
	RDTSC_TAKE_START(instr_ready); \
	g_rdtsc_instr_info_arr[instr_idle].start = \
		g_rdtsc_instr_info_arr[instr_ready].start; \
} while (0)
#endif

#if defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) && !defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
#define RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(instr_vma_poll, instr_cqe) \
	RDTSC_TAKE_START(instr_vma_poll)
#elif !defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) && defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
#define RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(instr_vma_poll, instr_cqe) \
	RDTSC_TAKE_START(instr_cqe)
#elif defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) && defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
#define RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(instr_vma_poll, instr_cqe) do { \
	RDTSC_TAKE_START(instr_vma_poll); \
	g_rdtsc_instr_info_arr[instr_cqe].start = \
		g_rdtsc_instr_info_arr[instr_vma_poll].start; \
} while (0)
#endif

#define RDTSC_TAKE_END(instr) do { \
	instr_info *pinst = &g_rdtsc_instr_info_arr[instr]; \
	if (pinst->start) { \
		uint64_t idx = pinst->counter & (RDTSC_PERCENTILE_BUF_SIZE - 1); \
		gettimeoftsc(&pinst->end); \
		pinst->results[idx] = \
			(pinst->start + g_rdtsc_cost <= pinst->end) ? \
			(pinst->end - pinst->start - g_rdtsc_cost) : (0); \
		pinst->cycles += pinst->results[idx]; \
		pinst->counter++; \
		pinst->start = 0; \
		if (pinst->print_ratio && \
				!(pinst->counter % pinst->print_ratio)) { \
			vlog_printf(VLOG_ERROR,"%s: %" PRIu64 " [@runtime]\n", \
				g_rdtsc_flow_names[pinst->trace_log_idx], \
					pinst->cycles / pinst->counter); \
		} \
	} \
} while (0)

enum rdtsc_flow_type {
	RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND = 0,
	RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM = 1,
	RDTSC_FLOW_TX_VERBS_POST_SEND = 2,
	RDTSC_FLOW_RX_VERBS_IDLE_POLL = 3,
	RDTSC_FLOW_RECEIVEFROM_TO_SENDTO = 4,
	RDTSC_FLOW_MEASURE_RX_LWIP = 5,
	RDTSC_FLOW_RX_DISPATCH_PACKET = 6,
	RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM = 7,
	RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL = 8,
	RDTSC_FLOW_RX_READY_POLL_TO_LWIP = 9,
	RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM = 10,
	RDTSC_FLOW_RX_VERBS_READY_POLL = 11,
	RDTSC_FLOW_RX_VERBS_POST_RECV = 12,
	RDTSC_FLOW_MAX = 13
};

typedef struct instr_info {
	tscval_t start;
	tscval_t end;
	tscval_t *results;
	uint64_t cycles;
	uint64_t counter;
	uint64_t print_ratio;
	uint16_t trace_log_idx;
} instr_info;

extern uint16_t g_rdtsc_cost;
extern char g_rdtsc_flow_names[RDTSC_FLOW_MAX][256];
extern instr_info g_rdtsc_instr_info_arr[RDTSC_FLOW_MAX];

#endif //RDTSC_MEASURE

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
#define RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL)
#else
#define RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_START do {} while (0)
#endif //RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_START

#ifdef RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL
#define RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_END \
	RDTSC_TAKE_END(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL)
#else
#define RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL_END do {} while (0)
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL

#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
#define RDTSC_FLOW_RX_VERBS_IDLE_POLL_START \
        RDTSC_TAKE_START(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#else
#define RDTSC_FLOW_RX_VERBS_IDLE_POLL_START do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_IDLE_POLL_START

#ifdef RDTSC_MEASURE_RX_VERBS_IDLE_POLL
#define RDTSC_FLOW_RX_VERBS_IDLE_POLL_END \
	RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_IDLE_POLL);
#else
#define RDTSC_FLOW_RX_VERBS_IDLE_POLL_END do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_IDLE_POLL_END

#if defined(RDTSC_MEASURE_RX_VERBS_READY_POLL) || defined(RDTSC_MEASURE_RX_VERBS_IDLE_POLL)
#define RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START \
	RDTSC_TAKE_START_RX_VERBS_POLL(RDTSC_FLOW_RX_VERBS_READY_POLL, RDTSC_FLOW_RX_VERBS_IDLE_POLL)
#else
#define RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START do {} while (0)
#endif //RDTSC_MEASURE_RX_VERBS_READY_OR_IDLE_POLL_START

#if defined(RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL) || defined(RDTSC_MEASURE_RX_CQE_RECEIVEFROM)
#define RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL_OR_CQE_RECEIVEFROM_START \
		RDTSC_TAKE_START_VMA_IDLE_POLL_CQE_TO_RECVFROM(RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL, \
					RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM);
#else
#define RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL_OR_CQE_RECEIVEFROM_START do {} while (0)
#endif //RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL_OR_CQE_RECEIVEFROM_START

#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
#define RDTSC_FLOW_RX_VERBS_READY_POLL_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_VERBS_READY_POLL)
#else
#define RDTSC_FLOW_RX_VERBS_READY_POLL_START do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_READY_POLL_START


#ifdef RDTSC_MEASURE_RX_VERBS_READY_POLL
#define RDTSC_FLOW_RX_VERBS_READY_POLL_END \
	RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_READY_POLL)
#else
#define RDTSC_FLOW_RX_VERBS_READY_POLL_END do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_READY_POLL_END

#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
#define RDTSC_FLOW_RX_READY_POLL_TO_LWIP_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_READY_POLL_TO_LWIP)
#else
#define RDTSC_FLOW_RX_READY_POLL_TO_LWIP_START do {} while (0)
#endif //RDTSC_FLOW_RX_READY_POLL_TO_LWIP_START

#ifdef RDTSC_MEASURE_RX_READY_POLL_TO_LWIP
#define RDTSC_FLOW_RX_READY_POLL_TO_LWIP_END \
	RDTSC_TAKE_END(RDTSC_FLOW_RX_READY_POLL_TO_LWIP)
#else
#define RDTSC_FLOW_RX_READY_POLL_TO_LWIP_END do {} while (0)
#endif //RDTSC_FLOW_RX_READY_POLL_TO_LWIP_END

#ifdef RDTSC_MEASURE_RX_VERBS_POST_RECV
#define RDTSC_FLOW_RX_VERBS_POST_RECV_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_VERBS_POST_RECV)
#else
#define RDTSC_FLOW_RX_VERBS_POST_RECV_START do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_POST_RECV_START

#ifdef RDTSC_MEASURE_RX_VERBS_POST_RECV
#define RDTSC_FLOW_RX_VERBS_POST_RECV_RESET \
	reset_rdtsc_counter(RDTSC_FLOW_RX_VERBS_POST_RECV);
#else
#define RDTSC_FLOW_RX_VERBS_POST_RECV_RESET do {} while (0)
#endif//RDTSC_FLOW_RX_VERBS_POST_RECV_RESET

#ifdef RDTSC_MEASURE_RX_VERBS_POST_RECV
#define RDTSC_FLOW_RX_VERBS_POST_RECV_END \
	RDTSC_TAKE_END(RDTSC_FLOW_RX_VERBS_POST_RECV);
#else
#define RDTSC_FLOW_RX_VERBS_POST_RECV_END do {} while (0)
#endif //RDTSC_FLOW_RX_VERBS_POST_RECV_END

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
#define RDTSC_FLOW_TX_VERBS_POST_SEND_START \
	RDTSC_TAKE_START(RDTSC_FLOW_TX_VERBS_POST_SEND);
#else
#define RDTSC_FLOW_TX_VERBS_POST_SEND_START do {} while (0)
#endif //RDTSC_FLOW_TX_VERBS_POST_SEND_START

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
#define RDTSC_FLOW_TX_VERBS_POST_SEND_RESET \
	reset_rdtsc_counter(RDTSC_FLOW_TX_VERBS_POST_SEND);
#else
#define RDTSC_FLOW_TX_VERBS_POST_SEND_RESET do {} while (0)
#endif //RDTSC_FLOW_TX_VERBS_POST_SEND_RESET

#ifdef RDTSC_MEASURE_TX_VERBS_POST_SEND
#define RDTSC_FLOW_TX_VERBS_POST_SEND_END \
	RDTSC_TAKE_END(RDTSC_FLOW_TX_VERBS_POST_SEND);
#else
#define RDTSC_FLOW_TX_VERBS_POST_SEND_END do {} while (0)
#endif //RDTSC_FLOW_TX_VERBS_POST_SEND_END

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_START \
	RDTSC_TAKE_START(RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND);
#else
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_START do {} while (0)
#endif //RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_START

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_RESET \
	reset_rdtsc_counter(RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND);
#else
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_RESET do {} while (0)
#endif //RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_RESET

#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_END \
	RDTSC_TAKE_END(RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND);
#else
#define RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_END do {} while (0)
#endif //RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND_END

#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
#define RDTSC_FLOW_RX_DISPATCH_PACKET_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_DISPATCH_PACKET)
#else
#define RDTSC_FLOW_RX_DISPATCH_PACKET_START do {} while (0)
#endif //RDTSC_FLOW_RX_DISPATCH_PACKET_START

#ifdef RDTSC_MEASURE_RX_DISPATCH_PACKET
#define RDTSC_FLOW_RX_DISPATCH_PACKET_END \
		RDTSC_TAKE_END(RDTSC_FLOW_RX_DISPATCH_PACKET)
#else
#define RDTSC_FLOW_RX_DISPATCH_PACKET_END do {} while (0)
#endif //RDTSC_FLOW_RX_DISPATCH_PACKET_END

#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
#define RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_START \
	RDTSC_TAKE_START(RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM)
#else
#define RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_START do {} while (0)
#endif //RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_START

#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
#define RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_END \
		RDTSC_TAKE_END(RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM)
#else
#define RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_END do {} while (0)
#endif //RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM_END

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
#define RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM)
#else
#define RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_START do {} while (0)
#endif //RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_START

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
#define RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_END \
		RDTSC_TAKE_END(RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM)
#else
#define RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_END do {} while (0)
#endif //RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM_END

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
#define RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM)
#else
#define RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_START do {} while (0)
#endif //RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_START

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
#define RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_END \
		RDTSC_TAKE_END(RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM)
#else
#define RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_END do {} while (0)
#endif //RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM_END

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
#define RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_START \
	RDTSC_TAKE_START(RDTSC_FLOW_RECEIVEFROM_TO_SENDTO)
#else
#define RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_START do {} while (0)
#endif //RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_START

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
#define RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_END \
		RDTSC_TAKE_END(RDTSC_FLOW_RECEIVEFROM_TO_SENDTO)
#else
#define RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_END do {} while (0)
#endif //RDTSC_FLOW_RECEIVEFROM_TO_SENDTO_END

#ifdef RDTSC_MEASURE_RX_LWIP
#define RDTSC_FLOW_MEASURE_RX_LWIP_START \
	RDTSC_TAKE_START(RDTSC_FLOW_MEASURE_RX_LWIP)
#else
#define RDTSC_FLOW_MEASURE_RX_LWIP_START do {} while (0)
#endif //RDTSC_FLOW_MEASURE_RX_LWIP_START

#ifdef RDTSC_MEASURE_RX_LWIP
#define RDTSC_FLOW_MEASURE_RX_LWIP_END \
		RDTSC_TAKE_END(RDTSC_FLOW_MEASURE_RX_LWIP)
#else
#define RDTSC_FLOW_MEASURE_RX_LWIP_END do {} while (0)
#endif //RDTSC_FLOW_MEASURE_RX_LWIP_END


//#define VMA_TIME_MEASURE 1
#ifdef VMA_TIME_MEASURE

#define POLL_START		0
#define CQ_IN_START		1
#define POLL_END		2
#define RX_START		3
#define RX_END			4
#define TX_START		5
#define TX_POST_SEND_START	6
#define TX_POST_SEND_END	7
#define TX_END                  8

#define POLL_START_TO_CQ_IN	9
#define POLL_CQ_IN_TO_POLL_END	10
#define POLL_DELTA		11
#define RX_START_TO_CQ_IN	12
#define RX_CQ_IN_TO_POLL_END	13
#define RX_DELTA		14
#define TX_START_TO_POST_SND_S	15
#define TX_POST_SND_S_TO_E	16
#define TX_POST_SND_E_TO_TX_END	17

#define INST_SIZE       	2000000

#define INST_SAMPLS     	(TX_END - POLL_START + 1)
#define INST_SUMS       	(TX_POST_SND_E_TO_TX_END - POLL_START_TO_CQ_IN + 1)


#define TAKE_TIME_2M(__i__)  	do {if (g_inst_cnt<INST_SIZE) gettime(&(g_inst[g_inst_cnt][__i__])); } while (0)

#define TAKE_T_POLL_START		TAKE_TIME_2M(POLL_START)
#define TAKE_POLL_CQ_IN			TAKE_TIME_2M(CQ_IN_START)
#define TAKE_T_POLL_END			TAKE_TIME_2M(POLL_END)
#define TAKE_T_RX_START			TAKE_TIME_2M(RX_START)
#define TAKE_T_RX_END			TAKE_TIME_2M(RX_END)
#define TAKE_T_TX_START			TAKE_TIME_2M(TX_START)
#define TAKE_T_TX_POST_SEND_START	TAKE_TIME_2M(TX_POST_SEND_START)
#define TAKE_T_TX_POST_SEND_END		TAKE_TIME_2M(TX_POST_SEND_END)
#define TAKE_T_TX_END			TAKE_TIME_2M(TX_END); g_inst_cnt++
#define VMA_TIME_INVALID 		((uint32_t)-1)

#define VMA_TIME_IS_LEGAL(start, end) 	(((0 == end) || (start > end) || (0== start)) ? false : true)

#define INC_POLL_COUNT 		do {if (g_inst_cnt<INST_SIZE) g_poll_cnt[g_inst_cnt]++;} while (0)
#define ZERO_POLL_COUNT 	do {if (g_inst_cnt<INST_SIZE) g_poll_cnt[g_inst_cnt]=0;} while (0)

#define INC_ERR_TX_COUNT 	g_tx_err_counter++;
#define INC_ERR_RX_COUNT 	g_rx_err_counter++;
#define INC_GO_TO_OS_TX_COUNT 	g_tx_go_to_os++;
#define INC_GO_TO_OS_RX_COUNT 	g_rx_go_to_os++;
#define INC_ERR_POLL_COUNT 	g_poll_err_counter++;


#define VMA_TIME_DEFAULT_MIN_VAL 100000000

extern struct timespec g_inst[INST_SIZE][INST_SAMPLS];
extern uint32_t g_inst_nsec[INST_SIZE][INST_SAMPLS+INST_SUMS];
extern uint32_t g_poll_cnt[INST_SIZE];
extern uint32_t g_inst_cnt;
extern uint32_t g_tx_err_counter;
extern uint32_t g_rx_err_counter;
extern uint32_t g_poll_err_counter;
extern uint32_t g_tx_go_to_os;
extern uint32_t g_rx_go_to_os;
extern uint32_t g_dump_cnt;

void init_instrumentation();
void finit_instrumentation(char* dump_file_name);

#else
#define TAKE_T_POLL_START do {} while (0)
#define TAKE_POLL_CQ_IN do {} while (0)
#define TAKE_T_POLL_END do {} while (0)
#define TAKE_T_RX_START do {} while (0)
#define TAKE_T_RX_END do {} while (0)
#define TAKE_T_TX_START do {} while (0)
#define TAKE_T_TX_POST_SEND_START do {} while (0)
#define TAKE_T_TX_POST_SEND_END do {} while (0)
#define TAKE_T_TX_END do {} while (0)
#define INC_ERR_TX_COUNT do {} while (0)
#define INC_ERR_RX_COUNT do {} while (0)
#define INC_GO_TO_OS_TX_COUNT do {} while (0)
#define INC_GO_TO_OS_RX_COUNT do {} while (0)
#define INC_ERR_POLL_COUNT do {} while (0)
#define INC_POLL_COUNT do {} while (0)
#define ZERO_POLL_COUNT do {} while (0)
#endif //VMA_TIME_MEASURE

#endif //INSTRUMENTATION
