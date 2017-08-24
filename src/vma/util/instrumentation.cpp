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

#include "config.h"
#include "instrumentation.h"
#include <string.h>

#ifdef RDTSC_MEASURE
#include <stdlib.h>
#include "vma/util/utils.h"

uint16_t g_rdtsc_cost = 0;
instr_info g_rdtsc_instr_info_arr[RDTSC_FLOW_MAX];
char g_rdtsc_flow_names[RDTSC_FLOW_MAX][256] = {
		{"RDTSC_FLOW_TX_SENDTO_TO_AFTER_POST_SEND"},
		{"RDTSC_FLOW_RX_CQE_RECEIVEFROM"},
		{"RDTSC_FLOW_TX_VERBS_POST_SEND"},
		{"RDTSC_FLOW_RX_VERBS_IDLE_POLL"},
		{"RDTSC_FLOW_MEASURE_RECEIVEFROM_TO_SENDTO"},
		{"RDTSC_FLOW_RX_LWIP"},
		{"RDTSC_FLOW_MEASURE_RX_DISPATCH_PACKET"},
		{"RDTSC_FLOW_PROCCESS_AFTER_BUFFER_TO_RECIVEFROM"},
		{"RDTSC_FLOW_RX_VMA_TCP_IDLE_POLL"},
		{"RDTSC_FLOW_RX_READY_POLL_TO_LWIP"},
		{"RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM"},
		{"RDTSC_FLOW_RX_VERBS_READY_POLL"},
		{"RDTSC_FLOW_RX_VERBS_POST_RECV"}
};

int reset_rdtsc_counter(int idx)
{
	tscval_t *results;
	
	if (g_rdtsc_instr_info_arr[idx].results) {
		results = g_rdtsc_instr_info_arr[idx].results;
	} else {
		results = (tscval_t*)malloc(RDTSC_PERCENTILE_BUF_SIZE * sizeof(tscval_t));
		if (!results) {
			return -1;
		}
	}

	memset((void*)(&g_rdtsc_instr_info_arr[idx]), 0, sizeof(instr_info));
	g_rdtsc_instr_info_arr[idx].print_ratio = RDTSC_PRINT_RATIO;
	g_rdtsc_instr_info_arr[idx].trace_log_idx = idx;

	memset(results, 0, RDTSC_PERCENTILE_BUF_SIZE * sizeof(tscval_t));
	g_rdtsc_instr_info_arr[idx].results = results;

	return 0;
}

void init_rdtsc()
{
	tscval_t start, end, curr;

	gettimeoftsc(&start);
	for(int i = 0; i < 1000000; i++) {
		gettimeoftsc(&curr);
		gettimeoftsc(&curr);
	}
	gettimeoftsc(&end);
	g_rdtsc_cost = (end - start)/1000000;
	vlog_printf(VLOG_INFO,"RDTSC cost is: %u cycles\n", g_rdtsc_cost);

	for(int i = 0; i < RDTSC_FLOW_MAX; i++) {
		reset_rdtsc_counter(i); // need to check return value
	}

}

int tscval_compare(const void *val1, const void *val2)
{
	return (int)(*(tscval_t*)val1 - *(tscval_t*)val2);
}

void print_rdtsc_percentiles(tscval_t *results, uint64_t size, double hz)
{
	double percentile[] = {
		0.99999, 0.9999, 0.999, 0.99, 0.90, 0.75, 0.50, 0.25
	};

	qsort(results, size, sizeof(tscval_t), tscval_compare);

	while (size && !(*results)) {
		size--;
		results++;
	}
	if (!size) {
		vlog_printf(VLOG_INFO, "All entries are zero!\n");
		return;
	}

	vlog_printf(VLOG_INFO, "Total %lu observations; each percentile contains %.2lf observations\n",
		(long unsigned)size, (double)size/100);

	vlog_printf(VLOG_INFO, "---> <MAX> observation = %8.3lfns\n", results[size-1]/hz);

	for (uint64_t i = 0; i < ARR_SIZE(percentile); i++) {
		uint64_t index = (uint64_t)(0.5 + percentile[i]*size) - 1;

		if (index < size) {
			vlog_printf(VLOG_INFO, "---> percentile %6.3lf = %8.3lfns\n",
				percentile[i] * 100, results[index]/hz);
		}
	}
	vlog_printf(VLOG_INFO, "---> <MIN> observation = %8.3lfns\n", results[0]/hz);
}

void print_rdtsc_summary()
{
	double hz_min = -1, hz_max = -1;
	uint64_t avg;
	int skip_percentile = 0;

	if (!get_cpu_hz(hz_min, hz_max)) {
		vlog_printf(VLOG_INFO, "Failure in reading CPU speeds\n");
		skip_percentile = 1;
	}
	if (!compare_double(hz_min, hz_max)) {
		vlog_printf(VLOG_INFO, "CPU cores are running at different speeds\n");
		skip_percentile = 1;
	}

	vlog_printf(VLOG_INFO,"*********** RDTSC Summary ************ \n");
	if (!skip_percentile) {
		vlog_printf(VLOG_INFO, "CPU speed: %8.3lfGHz\n", hz_min/1.e9);
	}
	for(int i = 0; i < RDTSC_FLOW_MAX; i++) {
		if (g_rdtsc_instr_info_arr[i].results) {
			if (g_rdtsc_instr_info_arr[i].counter) {
				avg = g_rdtsc_instr_info_arr[i].cycles/g_rdtsc_instr_info_arr[i].counter;
				vlog_printf(VLOG_INFO,"%s: %8.3lfns\n", g_rdtsc_flow_names[g_rdtsc_instr_info_arr[i].trace_log_idx], (avg*1e9)/hz_min);
				if (!skip_percentile) {
					print_rdtsc_percentiles(g_rdtsc_instr_info_arr[i].results, RDTSC_PERCENTILE_BUF_SIZE, hz_min/1e9);
				}
			}

			free(g_rdtsc_instr_info_arr[i].results);
		}
	}
}
#endif //RDTSC_MEASURE

#ifdef VMA_TIME_MEASURE

#include <string.h>
#include <stdlib.h>
#include <fstream>
#include <stdint.h>
#include <unistd.h>
#include "sys_vars.h"
#include "utils/clock.h"
#include "utils/rdtsc.h"

struct timespec g_inst[INST_SIZE][INST_SAMPLS];
uint32_t g_inst_nsec[INST_SIZE][INST_SAMPLS+INST_SUMS];
uint32_t g_poll_cnt[INST_SIZE];
uint32_t g_inst_cnt;
uint32_t g_tx_err_counter;
uint32_t g_rx_err_counter;
uint32_t g_poll_err_counter;
uint32_t g_tx_go_to_os;
uint32_t g_rx_go_to_os;
uint32_t g_dump_cnt = 1;

void init_instrumentation()
{
	memset(g_inst, 0, sizeof(struct timespec)*INST_SIZE*INST_SAMPLS);
	memset(g_inst_nsec, 0, sizeof(uint32_t)*INST_SIZE*(INST_SAMPLS+INST_SUMS));
	memset(g_poll_cnt, 0, sizeof(uint32_t)*INST_SIZE);
	g_inst_cnt = 0;
	g_tx_err_counter = 0;
	g_rx_err_counter = 0;
	g_poll_err_counter = 0;
	g_tx_go_to_os = 0;
	g_rx_go_to_os = 0;
}
void finit_instrumentation(char* dump_file_name)
{
	if(dump_file_name == NULL)
		return;

	if (0 >= g_inst_cnt)
		return;

	if(g_inst_cnt > INST_SIZE){
		g_inst_cnt = INST_SIZE;
	}

	std::ofstream dump_file;

	uint32_t  poll_start_to_poll_cq_min=VMA_TIME_DEFAULT_MIN_VAL, poll_start_to_poll_cq_max=0;
	double    poll_start_to_poll_cq_avg = 0;
	uint32_t  poll_cq_to_end_poll_min=VMA_TIME_DEFAULT_MIN_VAL, poll_cq_to_end_poll_max=0;
	double    poll_cq_to_end_poll_avg = 0;
	uint32_t poll_delta_max=0, poll_delta_min=VMA_TIME_DEFAULT_MIN_VAL;
	double   poll_delta_avg = 0;
	uint32_t rx_delta_max=0, rx_delta_min=VMA_TIME_DEFAULT_MIN_VAL;
	double   rx_delta_avg = 0;

	uint32_t  rx_start_to_poll_cq_min=VMA_TIME_DEFAULT_MIN_VAL, rx_start_to_poll_cq_max=0;
	double    rx_start_to_poll_cq_avg = 0;
	uint32_t  poll_cq_to_end_rx_min=VMA_TIME_DEFAULT_MIN_VAL, poll_cq_to_end_rx_max=0;
	double    poll_cq_to_end_rx_avg = 0;

	uint32_t tx_start_to_post_snd_s_min=VMA_TIME_DEFAULT_MIN_VAL, tx_start_to_post_snd_s_max=0;
	double   tx_start_to_post_snd_s_avg = 0;
	uint32_t tx_post_snd_s_to_e_min=VMA_TIME_DEFAULT_MIN_VAL, tx_post_snd_s_to_e_max=0;
	double   tx_post_snd_s_to_e_avg = 0;
	uint32_t tx_post_snd_e_to_tx_end_min=VMA_TIME_DEFAULT_MIN_VAL, tx_post_snd_e_to_tx_end_max=0;
	double   tx_post_snd_e_to_tx_end_avg = 0;
	uint32_t max_poll_count = 0;
	uint32_t poll_start_to_poll_cq = 0;
	uint32_t poll_cq_to_end_poll = 0;
	uint32_t poll_delta = 0;
	uint32_t rx_start_to_poll_cq = 0;
	uint32_t poll_cq_to_end_rx = 0;
	uint32_t rx_delta = 0;
	uint32_t tx_start_to_post_snd_s = 0;
	uint32_t tx_post_snd_e_to_tx_end = 0;
	uint32_t tx_post_snd_s_to_e = 0;

	char* dumpFileName = (char*)malloc(sizeof(char)*(FILENAME_MAX+10));
	sprintf(dumpFileName, "%s.%d.%d", dump_file_name, getpid(), g_dump_cnt);

	dump_file.open (dumpFileName);

	dump_file << "INVALID:" << VMA_TIME_INVALID <<"\n";
	dump_file << "TOTAL SAMPLES: " << g_inst_cnt << "\n";
	dump_file << "TX ERRORS:" <<  g_tx_err_counter << "\n";
	dump_file << "RX ERRORS:" <<  g_rx_err_counter << "\n";
	dump_file << "TX GO TO OS:" <<  g_tx_go_to_os << "\n";
	dump_file << "RX GO TO OS:" <<  g_rx_go_to_os << "\n";
	dump_file << "POLL ERRORS:" <<  g_poll_err_counter << "\n";

	for (uint32_t i=0; i<g_inst_cnt ; i++) {
		for (int j=0; j<INST_SAMPLS; j++) {
			g_inst_nsec[i][j]=ts_to_nsec(&(g_inst[i][j]));
		}
	}

	for (uint32_t i=0; i<g_inst_cnt; i++) {

		if(VMA_TIME_IS_LEGAL(g_inst_nsec[i][POLL_START], g_inst_nsec[i][POLL_END]))
		{
			if ((VMA_TIME_IS_LEGAL(g_inst_nsec[i][POLL_START], g_inst_nsec[i][CQ_IN_START])) &&
		    (VMA_TIME_IS_LEGAL(g_inst_nsec[i][CQ_IN_START], g_inst_nsec[i][POLL_END])))
		{
			poll_start_to_poll_cq  = 	g_inst_nsec[i][CQ_IN_START] - g_inst_nsec[i][POLL_START];
			poll_start_to_poll_cq_avg     += poll_start_to_poll_cq;
			if ( poll_start_to_poll_cq < poll_start_to_poll_cq_min )
				poll_start_to_poll_cq_min = poll_start_to_poll_cq;
			if ( poll_start_to_poll_cq > poll_start_to_poll_cq_max )
				poll_start_to_poll_cq_max = poll_start_to_poll_cq;

			poll_cq_to_end_poll  = g_inst_nsec[i][POLL_END] - g_inst_nsec[i][CQ_IN_START];
			poll_cq_to_end_poll_avg     += poll_cq_to_end_poll;
			if ( poll_cq_to_end_poll < poll_cq_to_end_poll_min )
				poll_cq_to_end_poll_min = poll_cq_to_end_poll;
			if ( poll_cq_to_end_poll > poll_cq_to_end_poll_max )
				poll_cq_to_end_poll_max = poll_cq_to_end_poll;
		}
		else {
			poll_start_to_poll_cq = VMA_TIME_INVALID;
			poll_cq_to_end_poll = VMA_TIME_INVALID;
		}

			poll_delta  = g_inst_nsec[i][POLL_END] - g_inst_nsec[i][POLL_START];
			poll_delta_avg	 += poll_delta;
			if (  poll_delta < poll_delta_min )
				poll_delta_min = poll_delta;
			if (  poll_delta > poll_delta_max )
				poll_delta_max = poll_delta;

		}
		else {
			poll_start_to_poll_cq = VMA_TIME_INVALID;
			poll_cq_to_end_poll = VMA_TIME_INVALID;
			poll_delta = VMA_TIME_INVALID;
		}

		if (VMA_TIME_IS_LEGAL(g_inst_nsec[i][RX_START], g_inst_nsec[i][RX_END])) {
			rx_delta  = g_inst_nsec[i][RX_END] - g_inst_nsec[i][RX_START];
			rx_delta_avg     += rx_delta;
			if (  rx_delta < rx_delta_min )
				rx_delta_min = rx_delta;
			if (  rx_delta > rx_delta_max )
				rx_delta_max = rx_delta;

			if (VMA_TIME_INVALID == poll_delta) {
				if ((VMA_TIME_IS_LEGAL(g_inst_nsec[i][RX_START], g_inst_nsec[i][CQ_IN_START])) &&
					(VMA_TIME_IS_LEGAL(g_inst_nsec[i][CQ_IN_START], g_inst_nsec[i][RX_END])))
				{
					rx_start_to_poll_cq  =	g_inst_nsec[i][CQ_IN_START] - g_inst_nsec[i][RX_START];
					rx_start_to_poll_cq_avg	  += rx_start_to_poll_cq;
					if ( rx_start_to_poll_cq < rx_start_to_poll_cq_min )
						rx_start_to_poll_cq_min = rx_start_to_poll_cq;
					if ( rx_start_to_poll_cq > rx_start_to_poll_cq_max )
						rx_start_to_poll_cq_max = rx_start_to_poll_cq;

					poll_cq_to_end_rx  = g_inst_nsec[i][RX_END] - g_inst_nsec[i][CQ_IN_START];
					poll_cq_to_end_rx_avg 	+= poll_cq_to_end_rx;
					if ( poll_cq_to_end_rx < poll_cq_to_end_rx_min )
						poll_cq_to_end_rx_min = poll_cq_to_end_rx;
					if ( poll_cq_to_end_rx > poll_cq_to_end_rx_max )
						poll_cq_to_end_rx_max = poll_cq_to_end_rx;
				}
				else {
					rx_start_to_poll_cq = VMA_TIME_INVALID;
					poll_cq_to_end_rx = VMA_TIME_INVALID;
				}
			}
		}
		else {
			rx_delta = VMA_TIME_INVALID;
		}

		if (VMA_TIME_IS_LEGAL(g_inst_nsec[i][TX_START],  g_inst_nsec[i][TX_POST_SEND_START]))
		{
			tx_start_to_post_snd_s   = g_inst_nsec[i][TX_POST_SEND_START] - g_inst_nsec[i][TX_START];
			tx_start_to_post_snd_s_avg     += tx_start_to_post_snd_s;
			if ( tx_start_to_post_snd_s < tx_start_to_post_snd_s_min )
				tx_start_to_post_snd_s_min = tx_start_to_post_snd_s;
			if ( tx_start_to_post_snd_s > tx_start_to_post_snd_s_max )
				tx_start_to_post_snd_s_max = tx_start_to_post_snd_s;
		}
		else {
			tx_start_to_post_snd_s = VMA_TIME_INVALID;
		}

		if (VMA_TIME_IS_LEGAL(g_inst_nsec[i][TX_POST_SEND_START],  g_inst_nsec[i][TX_POST_SEND_END]))
		{
			tx_post_snd_s_to_e   = g_inst_nsec[i][TX_POST_SEND_END] - g_inst_nsec[i][TX_POST_SEND_START];
			tx_post_snd_s_to_e_avg     += tx_post_snd_s_to_e;
			if ( tx_post_snd_s_to_e < tx_post_snd_s_to_e_min )
				tx_post_snd_s_to_e_min = tx_post_snd_s_to_e;
			if ( tx_post_snd_s_to_e > tx_post_snd_s_to_e_max )
				tx_post_snd_s_to_e_max = tx_post_snd_s_to_e;
		}
		else {
			tx_post_snd_s_to_e = VMA_TIME_INVALID;
		}

		if (VMA_TIME_IS_LEGAL( g_inst_nsec[i][TX_POST_SEND_END],  g_inst_nsec[i][TX_END])) {
			tx_post_snd_e_to_tx_end  = g_inst_nsec[i][TX_END] - g_inst_nsec[i][TX_POST_SEND_END];
			tx_post_snd_e_to_tx_end_avg     += tx_post_snd_e_to_tx_end;
			if ( tx_post_snd_e_to_tx_end < tx_post_snd_e_to_tx_end_min )
				tx_post_snd_e_to_tx_end_min = tx_post_snd_e_to_tx_end;
			if ( tx_post_snd_e_to_tx_end > tx_post_snd_e_to_tx_end_max )
				tx_post_snd_e_to_tx_end_max = tx_post_snd_e_to_tx_end;
		}
		else {
			tx_post_snd_e_to_tx_end = VMA_TIME_INVALID;
		}

		g_inst_nsec[i][POLL_START_TO_CQ_IN] = poll_start_to_poll_cq;
		g_inst_nsec[i][POLL_CQ_IN_TO_POLL_END]  = poll_cq_to_end_poll;
		g_inst_nsec[i][POLL_DELTA] = poll_delta;
		g_inst_nsec[i][RX_START_TO_CQ_IN] = rx_start_to_poll_cq;
		g_inst_nsec[i][RX_CQ_IN_TO_POLL_END]  = poll_cq_to_end_rx;
		g_inst_nsec[i][RX_DELTA] = rx_delta;
		g_inst_nsec[i][TX_START_TO_POST_SND_S] = tx_start_to_post_snd_s;
		g_inst_nsec[i][TX_POST_SND_S_TO_E] = tx_post_snd_s_to_e;
		g_inst_nsec[i][TX_POST_SND_E_TO_TX_END] = tx_post_snd_e_to_tx_end;

		if (g_poll_cnt[i] > max_poll_count)
			max_poll_count = g_poll_cnt[i];
	}

	poll_start_to_poll_cq_avg = poll_start_to_poll_cq_avg/g_inst_cnt;
	poll_cq_to_end_poll_avg = poll_cq_to_end_poll_avg/g_inst_cnt;
	poll_delta_avg = poll_delta_avg/g_inst_cnt;
	rx_delta_avg = rx_delta_avg/g_inst_cnt;
	rx_start_to_poll_cq_avg = rx_start_to_poll_cq_avg/g_inst_cnt;
	poll_cq_to_end_rx_avg = poll_cq_to_end_rx_avg/g_inst_cnt;
	tx_start_to_post_snd_s_avg = tx_start_to_post_snd_s_avg/g_inst_cnt;
	tx_post_snd_s_to_e_avg = tx_post_snd_s_to_e_avg/g_inst_cnt;
	tx_post_snd_e_to_tx_end_avg = tx_post_snd_e_to_tx_end_avg/g_inst_cnt;

	if (VMA_TIME_DEFAULT_MIN_VAL == poll_start_to_poll_cq_min)
		poll_start_to_poll_cq_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == poll_cq_to_end_poll_min)
		poll_cq_to_end_poll_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == poll_delta_min)
		poll_delta_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == rx_start_to_poll_cq_min)
		rx_start_to_poll_cq_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == poll_cq_to_end_rx_min)
		poll_cq_to_end_rx_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == rx_delta_min)
		rx_delta_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == rx_delta_max)
		rx_delta_max = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == tx_start_to_post_snd_s_min)
		tx_start_to_post_snd_s_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == tx_post_snd_s_to_e_min)
		tx_post_snd_s_to_e_min = 0;
	if (VMA_TIME_DEFAULT_MIN_VAL == tx_post_snd_e_to_tx_end_min)
		tx_post_snd_e_to_tx_end_min = 0;

	dump_file << "poll_start_to_poll_cq: min=" << poll_start_to_poll_cq_min << " max=" << poll_start_to_poll_cq_max << " avg=" << poll_start_to_poll_cq_avg << "\n";
	dump_file << "poll_cq_to_end_poll:   min=" << poll_cq_to_end_poll_min << " max=" << poll_cq_to_end_poll_max << " avg=" << poll_cq_to_end_poll_avg << "\n";
	dump_file << "poll_delta:              min=" << poll_delta_min << " max=" << poll_delta_max << " avg=" << poll_delta_avg << "\n";
	dump_file << "rx_start_to_poll_cq: min=" << rx_start_to_poll_cq_min << " max=" << rx_start_to_poll_cq_max << " avg=" << rx_start_to_poll_cq_avg << "\n";
	dump_file << "rx_cq_to_end_poll:   min=" << poll_cq_to_end_rx_min << " max=" << poll_cq_to_end_rx_max << " avg=" << poll_cq_to_end_rx_avg << "\n";
	dump_file << "rx_delta:              min=" << rx_delta_min << " max=" << rx_delta_max << " avg=" << rx_delta_avg << "\n";
	dump_file << "tx_start_to_post_snd:  min=" << tx_start_to_post_snd_s_min << " max=" << tx_start_to_post_snd_s_max << " avg=" << tx_start_to_post_snd_s_avg << "\n";
	dump_file << "tx_post_snd_s_to_e:  min=" << tx_post_snd_s_to_e_min << " max=" << tx_post_snd_s_to_e_max << " avg=" << tx_post_snd_s_to_e_avg << "\n";
	dump_file << "tx_post_snd_e_to_tx_end: min=" << tx_post_snd_e_to_tx_end_min << " max=" << tx_post_snd_e_to_tx_end_max << " avg=" << tx_post_snd_e_to_tx_end_avg << "\n";

	dump_file << "MAX_POLL_COUNT: " << max_poll_count << "\n";


	dump_file << "  poll_in      cq_poll     poll_out       rx_in        rx_out      tx_in      post_snd_s      pos_snd_e       tx_out    poll_start_to_poll_cq  poll_cq_to_end_poll  poll_delta  rx_start_to_poll_cq  poll_cq_to_end_rx  rx_delta  tx_start_to_post_snd_s tx_pos_snd_s_to_e  tx_post_snd_e_to_tx_end  g_poll_cnt\n";

	for (uint32_t i=0; i<g_inst_cnt; i++) {
		for (int j=0; j<(INST_SAMPLS+INST_SUMS); j++) {
			dump_file << g_inst_nsec[i][j] << " , ";
		}
		dump_file << g_poll_cnt[i];
		dump_file << "\n";
	}

	g_dump_cnt++;

	dump_file.close();

	init_instrumentation();

}

#endif //VMA_TIME_MEASURE

