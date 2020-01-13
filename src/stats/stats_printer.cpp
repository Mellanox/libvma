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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "vma/util/utils.h"
#include "vma/util/vma_stats.h"
#include "vma/lwip/tcp.h"
#include "vma/vma_extra.h"
#include "vma/util/sys_vars.h"

typedef enum {
	e_K = 1024,
	e_M = 1048576
} units_t;

user_params_t user_params;

#define BYTES_TRAFFIC_UNIT		e_K

const char* to_str_socket_type(int type)
{
	switch (type) {
	case SOCK_STREAM:	return "TCP";
	case SOCK_DGRAM:	return "UDP";
	case SOCK_RAW:		return "RAW";
	default:
		break;
	}
	return "???";
}

const char* to_str_socket_type_netstat_like(int type)
{
	switch (type) {
	case SOCK_STREAM:	return "tcp";
	case SOCK_DGRAM:	return "udp";
	case SOCK_RAW:		return "raw";
	default:
		break;
	}
	return "???";
}

// Print statistics for offloaded sockets
void print_full_stats(socket_stats_t* p_si_stats, mc_grp_info_t* p_mc_grp_info, FILE* filename)
{

	if (!filename) return;

	bool b_any_activiy = false;
	char post_fix[3] = "";

	if (user_params.print_details_mode == e_deltas)
		strcpy(post_fix, "/s");
	fprintf(filename, "======================================================\n");
	fprintf(filename, "\tFd=[%d]\n", p_si_stats->fd);

	//
	// Socket information
	//
	fprintf(filename, "- %s", to_str_socket_type(p_si_stats->socket_type));
	fprintf(filename, ", %s", p_si_stats->b_blocking?"Blocked":"Non-blocked");

	//
	// Multicast information
	//
	if (p_si_stats->socket_type == SOCK_DGRAM) {
		fprintf(filename, ", MC Loop %s", p_si_stats->b_mc_loop?"Enabled ":"Disabled");
		if (p_si_stats->mc_tx_if) {
			/* cppcheck-suppress wrongPrintfScanfArgNum */
			fprintf(filename, ", MC IF = [%d.%d.%d.%d]", NIPQUAD(p_si_stats->mc_tx_if));
		}
	}
	fprintf(filename, "\n");

	//
	// Bounded + Connected information
	//
	if (p_si_stats->bound_if || p_si_stats->bound_port) {
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		fprintf(filename, "- Local Address   = [%d.%d.%d.%d:%d]\n", NIPQUAD(p_si_stats->bound_if), ntohs(p_si_stats->bound_port));
	}
	if (p_si_stats->connected_ip || p_si_stats->connected_port) {
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		fprintf(filename, "- Foreign Address = [%d.%d.%d.%d:%d]\n", NIPQUAD(p_si_stats->connected_ip), ntohs(p_si_stats->connected_port));
	}
	if (p_mc_grp_info){
		for (int grp_idx = 0; grp_idx < p_mc_grp_info->max_grp_num; grp_idx++) {
			if (p_si_stats->mc_grp_map.test(grp_idx)) {
				/* cppcheck-suppress wrongPrintfScanfArgNum */
				fprintf(filename, "- Member of = [%d.%d.%d.%d]\n", NIPQUAD(p_mc_grp_info->mc_grp_tbl[grp_idx].mc_grp));
			}
		}
	}
	if ((p_si_stats->threadid_last_rx != 0) || (p_si_stats->threadid_last_tx != 0)) {
		fprintf(filename, "- Thread Id Rx: %5u, Tx: %5u\n", p_si_stats->threadid_last_rx, p_si_stats->threadid_last_tx);
	}

	//
	// Ring Allocation Logic information
	//
	//
	if (p_si_stats->ring_alloc_logic_rx == RING_LOGIC_PER_USER_ID)
		fprintf(filename, "- RX: Ring User ID = %lu\n", p_si_stats->ring_user_id_rx);
	if (p_si_stats->ring_alloc_logic_tx == RING_LOGIC_PER_USER_ID)
		fprintf(filename, "- TX: Ring User ID = %lu\n", p_si_stats->ring_user_id_tx);

	//
	// Socket statistics
	//
	if (p_si_stats->counters.n_tx_sent_byte_count || p_si_stats->counters.n_tx_sent_pkt_count || p_si_stats->counters.n_tx_drops || p_si_stats->counters.n_tx_errors)
	{
		fprintf(filename, "Tx Offload: %u / %u / %u / %u [kilobytes/packets/drops/errors]%s\n", p_si_stats->counters.n_tx_sent_byte_count/BYTES_TRAFFIC_UNIT,p_si_stats->counters.n_tx_sent_pkt_count, p_si_stats->counters.n_tx_drops, p_si_stats->counters.n_tx_errors, post_fix);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_tx_os_bytes || p_si_stats->counters.n_tx_os_packets || p_si_stats->counters.n_tx_os_eagain || p_si_stats->counters.n_tx_os_errors)
	{
		fprintf(filename, "Tx OS info: %u / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",  p_si_stats->counters.n_tx_os_bytes/BYTES_TRAFFIC_UNIT,  p_si_stats->counters.n_tx_os_packets, p_si_stats->counters.n_tx_os_eagain, p_si_stats->counters.n_tx_os_errors, post_fix);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_tx_dummy) {
		fprintf(filename, "Tx Dummy messages : %d\n", p_si_stats->counters.n_tx_dummy);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_rx_bytes || p_si_stats->counters.n_rx_packets || p_si_stats->counters.n_rx_eagain || p_si_stats->counters.n_rx_errors)
	{
		fprintf(filename, "Rx Offload: %u / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",  p_si_stats->counters.n_rx_bytes/BYTES_TRAFFIC_UNIT,  p_si_stats->counters.n_rx_packets, p_si_stats->counters.n_rx_eagain,  p_si_stats->counters.n_rx_errors, post_fix);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_rx_os_bytes || p_si_stats->counters.n_rx_os_packets || p_si_stats->counters.n_rx_os_eagain || p_si_stats->counters.n_rx_os_errors)
	{
		fprintf(filename, "Rx OS info: %u / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",  p_si_stats->counters.n_rx_os_bytes/BYTES_TRAFFIC_UNIT,  p_si_stats->counters.n_rx_os_packets, p_si_stats->counters.n_rx_os_eagain, p_si_stats->counters.n_rx_os_errors, post_fix);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_rx_packets || p_si_stats->n_rx_ready_pkt_count)
	{
		fprintf(filename, "Rx byte: cur %u / max %u / dropped%s %u / limit %u\n", p_si_stats->n_rx_ready_byte_count, p_si_stats->counters.n_rx_ready_byte_max, post_fix,p_si_stats->counters.n_rx_ready_byte_drop, p_si_stats->n_rx_ready_byte_limit);
		fprintf(filename, "Rx pkt : cur %u / max %u / dropped%s %u\n", p_si_stats->n_rx_ready_pkt_count, p_si_stats->counters.n_rx_ready_pkt_max, post_fix,p_si_stats->counters.n_rx_ready_pkt_drop);
		b_any_activiy = true;
	}
	if (p_si_stats->n_rx_zcopy_pkt_count)
	{
		fprintf(filename, "Rx zero copy buffers: cur %u\n", p_si_stats->n_rx_zcopy_pkt_count);
		b_any_activiy = true;
	}
	if (p_si_stats->counters.n_rx_poll_miss || p_si_stats->counters.n_rx_poll_hit)
	{
		double rx_poll_hit = (double)p_si_stats->counters.n_rx_poll_hit;
		double rx_poll_hit_percentage = (rx_poll_hit / (rx_poll_hit + (double)p_si_stats->counters.n_rx_poll_miss)) * 100;
		fprintf(filename, "Rx poll: %u / %u (%2.2f%%) [miss/hit]\n",  p_si_stats->counters.n_rx_poll_miss, p_si_stats->counters.n_rx_poll_hit, rx_poll_hit_percentage);
		b_any_activiy = true;
	}

	if (p_si_stats->counters.n_rx_migrations || p_si_stats->counters.n_tx_migrations)
	{
		fprintf(filename, "Ring migrations Rx: %u, Tx: %u\n", p_si_stats->counters.n_rx_migrations, p_si_stats->counters.n_tx_migrations);
	}

	if (p_si_stats->counters.n_tx_retransmits)
	{
		fprintf(filename, "Retransmissions: %u\n", p_si_stats->counters.n_tx_retransmits);
	}

	if (b_any_activiy == false) {
		fprintf(filename, "Rx and Tx where not active\n");
	}
}

// Print statistics headers for all sockets - used in case view mode is e_netstat_like
void print_netstat_like_headers(FILE* file)
{
	static bool already_printed = false;
	if(!already_printed) fprintf(file, "Proto Offloaded Recv-Q Send-Q Local Address          Foreign Address       State       Inode      PID/Program name\n");
	already_printed = true;
}

// Print statistics of a single socket - used in case view mode is e_netstat_like
void print_netstat_like(socket_stats_t* p_si_stats, mc_grp_info_t* , FILE* file, int pid)
{
	static const int MAX_ADDR_LEN = strlen("123.123.123.123:12345"); // for max len of ip address and port together
	char process[PATH_MAX + 1];

	if(! p_si_stats->inode) return; // shmem is not updated yet

	fprintf(file, "%-5s %-9s ", to_str_socket_type_netstat_like(p_si_stats->socket_type), p_si_stats->b_is_offloaded ? "Yes" : "No");
	fprintf(file, "%-6d %-6d ", (int)p_si_stats->n_rx_ready_byte_count, (int)p_si_stats->n_tx_ready_byte_count);

	//
	// Bounded + Connected information
	//
	int len = 0;
	if (p_si_stats->bound_if || p_si_stats->bound_port) {
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		len = fprintf(file, "%d.%d.%d.%d:%-5d", NIPQUAD(p_si_stats->bound_if), ntohs(p_si_stats->bound_port));
		if (len < 0) len = 0; // error
	}
	if (len < MAX_ADDR_LEN )fprintf(file, "%*s ", MAX_ADDR_LEN-len, ""); // pad and delimiter

	fprintf(file, " ");

	if (p_si_stats->connected_ip || p_si_stats->connected_port) {
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		len = fprintf(file, "%d.%d.%d.%d:%-5d", NIPQUAD(p_si_stats->connected_ip), ntohs(p_si_stats->connected_port));
	}
	else {
		len = fprintf(file, "0.0.0.0:*");
	}
	if (len < 0) len = 0; // error
	if (len < MAX_ADDR_LEN )fprintf(file, "%*s ", MAX_ADDR_LEN-len, ""); // pad and delimiter

	const char * tcp_state = "";
	if (p_si_stats->socket_type == SOCK_STREAM) {
		tcp_state = tcp_state_str[((enum tcp_state)p_si_stats->tcp_state)];
	}

	fprintf(file, "%-11s %-10lu %d/%s\n",
			tcp_state, (u_long)p_si_stats->inode, pid,
			(get_procname(pid, process, sizeof(process)) == 0 ? process : "-")); // max tcp state len is 11 characters = ESTABLISHED
}


