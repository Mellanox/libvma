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



#include "instrumentation.h"


#ifdef VMA_TIME_MEASURE

#include <string.h>
#include <stdlib.h>
#include <fstream>
#include "clock.h"
#include <stdint.h>
#include <unistd.h>
#include "rdtsc.h"
#include "sys_vars.h"

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

