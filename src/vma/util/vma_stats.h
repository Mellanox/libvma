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


#ifndef V_VMA_STATS_H
#define V_VMA_STATS_H

#include <sys/types.h>
#include <netinet/in.h>
#include <bitset>

using namespace std;

//   ------------------------------
//   | VERSION INFO		  | 
//   ------------------------------
//   | Max Num of fd blocks       |
//   ------------------------------
//   | LOG LEVEL                  |
//   ------------------------------
//   | DETAILS LEVEL              |
//   ------------------------------	
//   | MAX_VALID_SOCKINFO_BLOCKS  |
//   ------------------------------
//   | Sockinfo fd block (0)      |
//   -----------------------------
//   | Sockinfo fd block (1)      |
//   ------------------------------
//   | ...                        |
//   ------------------------------
//   | Sockinfo fd block (n)      |
//   -----------------------------
//   | empty                      |
//   ------------------------------
//   | empty                      |
//   ------------------------------
//   | CQ stats block (n)         |
//   ------------------------------
//   | MC GROUPS INFO             |
//   ------------------------------
//   | Poll stats block           |
//   ------------------------------
//   | Select stats block         |
//   ------------------------------
//   | Epoll stats block (0)      |
//   ------------------------------
//   | ...                        |
//   ------------------------------
//   | Epoll stats block (n)      |
//   ------------------------------

#define NUM_OF_SUPPORTED_CQS 		8 
#define NUM_OF_SUPPORTED_RINGS 		8
#define NUM_OF_SUPPORTED_EPFDS          15
#define MIN_STATS_SIZE	 		((sizeof(uint32_t)  + sizeof(size_t) + 6*sizeof(uint8_t) + sizeof(ring_instance_block_t)*NUM_OF_SUPPORTED_RINGS + sizeof(cq_instance_block_t)*NUM_OF_SUPPORTED_CQS + sizeof(mc_grp_info_t) + sizeof(iomux_stats_t)))
#define SHMEM_STATS_SIZE(fds_num)	MIN_STATS_SIZE + (fds_num * sizeof(socket_instance_block_t))
#define FILE_NAME_MAX_SIZE		256
#define MC_TABLE_SIZE			1024
#define MAP_SH_MEM(var,sh_stats)	(var = (sh_mem_t*)sh_stats)

//statistic file
extern FILE* g_stats_file;

//
// Common iomux stats
//
typedef struct {
	pid_t		threadid_last;
	uint32_t	n_iomux_poll_hit;
	uint32_t	n_iomux_poll_miss;
	uint32_t	n_iomux_timeouts;
	uint32_t	n_iomux_errors;
	uint32_t	n_iomux_rx_ready;
	uint32_t	n_iomux_os_rx_ready;
	uint32_t	n_iomux_polling_time;
} iomux_func_stats_t;

typedef enum {
	e_totals = 1,
	e_deltas
} print_details_mode_t;

typedef enum {
	e_basic = 1,
	e_medium,
	e_full,
	e_mc_groups
} view_mode_t;

typedef enum {
	e_by_pid_str,
	e_by_app_name,
	e_by_runn_proccess
} proc_ident_mode_t;

struct user_params_t {
	int 			interval;
	print_details_mode_t 	print_details_mode;
	view_mode_t		view_mode;
	bool 			forbid_cleaning;
	int			vma_log_level;
	int			vma_details_level;
	bool 			zero_counters;
	proc_ident_mode_t	proc_ident_mode;
	bool 			write_auth;
	int			cycles;
};

extern user_params_t user_params;

//
// Epoll group stats
//
typedef struct {
	bool                   enabled;
	int                    epfd;
	iomux_func_stats_t     stats;
} epoll_stats_t;

//
// iomux function stat info
//
typedef struct {
	iomux_func_stats_t     poll;
	iomux_func_stats_t     select;
	epoll_stats_t          epoll[NUM_OF_SUPPORTED_EPFDS];
} iomux_stats_t;

//
// multicast stat info
//
typedef struct {
	uint32_t 	sock_num;
	in_addr_t 	mc_grp;
} mc_tbl_entry_t;

typedef struct {
	uint16_t	max_grp_num;
	mc_tbl_entry_t 	mc_grp_tbl[MC_TABLE_SIZE];
} mc_grp_info_t;

//
// socket stat info
//
typedef struct {
	uint32_t		n_rx_packets;
	uint32_t		n_rx_bytes;
	uint32_t		n_rx_poll_hit;
	uint32_t		n_rx_poll_miss;
	uint32_t		n_rx_ready_pkt_max;
	uint32_t		n_rx_ready_byte_drop;
	uint32_t		n_rx_ready_pkt_drop;
	uint32_t		n_rx_ready_byte_max;
	uint32_t		n_rx_errors;
	uint32_t		n_rx_eagain;
	uint32_t		n_rx_os_packets;
	uint32_t		n_rx_os_bytes;
	uint32_t		n_rx_poll_os_hit;
	uint32_t		n_rx_os_errors;
	uint32_t		n_rx_os_eagain;
	uint32_t		n_rx_migrations;
	uint32_t		n_tx_sent_pkt_count;
	uint32_t		n_tx_sent_byte_count;
	uint32_t		n_tx_errors;
	uint32_t		n_tx_drops;
	uint32_t		n_tx_os_packets;
	uint32_t		n_tx_os_bytes;
	uint32_t		n_tx_os_errors;
	uint32_t		n_tx_os_eagain;
	uint32_t		n_tx_migrations;
} socket_counters_t;

typedef struct {
	int			fd;
	uint8_t			socket_type; // SOCK_STREAM, SOCK_DGRAM, ...
	bool			b_blocking;
	bool			b_mc_loop;
	in_addr_t		bound_if;
	in_addr_t		connected_ip;
	in_port_t		bound_port;
	in_port_t		connected_port;
	in_addr_t		mc_tx_if;
	bitset<MC_TABLE_SIZE>	mc_grp_map;
	pid_t			threadid_last_rx;
	pid_t			threadid_last_tx;
	uint32_t		n_rx_ready_pkt_count;
	uint32_t		n_rx_ready_byte_count;
	uint32_t 		n_rx_ready_byte_limit;
	uint32_t		n_rx_zcopy_pkt_count;
	socket_counters_t	counters;
} socket_stats_t;

typedef struct {
	bool 		b_enabled;
	socket_stats_t 	skt_stats;
} socket_instance_block_t;

//
// CQ stat info
//
typedef struct {
	uint64_t	n_rx_pkt_drop;
	uint32_t	n_rx_sw_queue_len;
	uint32_t	n_rx_drained_at_once_max;
	uint32_t	n_buffer_pool_len;
	double		buffer_miss_rate;
} cq_stats_t;

typedef struct {
	bool 		b_enabled;
	cq_stats_t 	cq_stats;
} cq_instance_block_t;

//
// Ring stat info
//
typedef struct {
	uint64_t	n_rx_pkt_count;
	uint64_t	n_rx_byte_count;
	uint64_t	n_rx_interrupt_requests;
	uint64_t	n_rx_interrupt_received;
	uint32_t	n_rx_cq_moderation_count;
	uint32_t	n_rx_cq_moderation_period;
} ring_stats_t;

typedef struct {
	bool 		b_enabled;
	ring_stats_t 	ring_stats;
} ring_instance_block_t;

//
// Version info
//
typedef struct {
	uint8_t		vma_lib_maj;
	uint8_t		vma_lib_min;
	uint8_t		vma_lib_rev;
	uint8_t		vma_lib_rel;
} version_info_t;

typedef struct sh_mem_t {
        int                            reader_counter; //only copy to shm upon active reader
	version_info_t			ver_info;
	size_t				max_skt_inst_num;
	uint8_t				log_level;
	uint8_t 			log_details_level;
	cq_instance_block_t		cq_inst_arr[NUM_OF_SUPPORTED_CQS];
	ring_instance_block_t		ring_inst_arr[NUM_OF_SUPPORTED_RINGS];
	mc_grp_info_t			mc_info;
	iomux_stats_t                   iomux;
	socket_instance_block_t  	skt_inst_arr[]; //sockets statistics array
} sh_mem_t;

typedef struct sh_mem_info {
	char		filename_sh_stats[FILE_NAME_MAX_SIZE];
	size_t 		shmem_size;
	int		fd_sh_stats;
	void*		p_sh_stats;
} sh_mem_info_t;

// publisher functions

void 			vma_shmem_stats_open(uint8_t** p_p_vma_log_level, uint8_t** p_p_vma_log_details);
void 			vma_shmem_stats_close();

void              	vma_stats_instance_create_socket_block(socket_stats_t*);
void 			vma_stats_instance_remove_socket_block(socket_stats_t*);

void 			vma_stats_mc_group_add(in_addr_t mc_grp, socket_stats_t* p_socket_stats);
void 			vma_stats_mc_group_remove(in_addr_t mc_grp, socket_stats_t* p_socket_stats);

void     		vma_stats_instance_create_ring_block(ring_stats_t*);
void 			vma_stats_instance_remove_ring_block(ring_stats_t*);

void     		vma_stats_instance_create_cq_block(cq_stats_t*);
void 			vma_stats_instance_remove_cq_block(cq_stats_t*);

void             	vma_stats_instance_get_poll_block(iomux_func_stats_t*);
void             	vma_stats_instance_get_select_block(iomux_func_stats_t*);

void     		vma_stats_instance_create_epoll_block(int, iomux_func_stats_t*);
void			vma_stats_instance_remove_epoll_block(iomux_func_stats_t* ep_stats);

//reader functions

void print_full_stats(socket_stats_t* p_si_stats, mc_grp_info_t* p_mc_grp_info, FILE* filename);

#endif //V_VMA_STATS_H





