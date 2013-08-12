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


/*
 * VMA instrumental - measure the times that certain actions takes.
 * Currently support: RX,TX,IOMUX
 * Enable: use --enable-time_measure in ./configure
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

#endif //VMA_TIME_MEASURE

#endif //INSTRUMENTATION
