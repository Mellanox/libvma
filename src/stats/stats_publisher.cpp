/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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

#include "stats/stats_data_reader.h"
#include "vma/util/vma_stats.h"
#include "vma/sock/sock-redirect.h"
#include "vma/event/event_handler_manager.h"

#define MODULE_NAME                     "STATS: "

static lock_spin	g_lock_mc_info("g_lock_mc_info");
static lock_spin	g_lock_skt_inst_arr("g_lock_skt_inst_arr");
static lock_spin	g_lock_ring_inst_arr("g_lock_ring_inst_arr");
static lock_spin	g_lock_cq_inst_arr("g_lock_cq_inst_arr");
static lock_spin	g_lock_bpool_inst_arr("g_lock_bpool_inst_arr");
static lock_spin	g_lock_iomux("g_lock_iomux");

static sh_mem_info_t	g_sh_mem_info;
static sh_mem_t*	g_sh_mem;
static sh_mem_t		g_local_sh_mem;

//statistic file
FILE* g_stats_file = NULL;
stats_data_reader*  g_p_stats_data_reader = NULL;


// keep writing statistics after a request for "duration" with "interval"
#define STATS_PUBLISH_DURATION    (10*1000) // 10 sec
#define STATS_PUBLISH_INTERVAL    500       // 500 msec

#define TIMERS_IN_STATS_PUBLISH_DURATION    (STATS_PUBLISH_DURATION/STATS_PUBLISHER_TIMER_PERIOD)
#define TIMERS_IN_STATS_PUBLISH_INTERVAL    (STATS_PUBLISH_INTERVAL/STATS_PUBLISHER_TIMER_PERIOD)

bool		printed_sock_limit_info = false;
bool		printed_ring_limit_info = false;
bool		printed_cq_limit_info = false;
bool		printed_bpool_limit_info = false;

stats_data_reader::stats_data_reader() : m_timer_handler(NULL), m_lock_data_map("m_lock_data_map")
{
}


#define LOCAL_OBJECT_DATA       iter->first
#define SHM_DATA_ADDRESS        iter->second.first
#define COPY_SIZE               iter->second.second 

bool should_write()
{
	// initial value that will prevent write to shmem before an explicit request
	static int timers_counter = TIMERS_IN_STATS_PUBLISH_DURATION + 1;

	static int reader_counter = 0;
	int prev_reader_counter = reader_counter;
	reader_counter = g_sh_mem->reader_counter;

	if (prev_reader_counter != reader_counter) {
		timers_counter = 0; // will allow writing without new request for "duration"
		return true;
	}

	if (timers_counter > TIMERS_IN_STATS_PUBLISH_DURATION)
		return false; // don't write until we'll see explicit request

	++timers_counter;

	return (timers_counter % TIMERS_IN_STATS_PUBLISH_INTERVAL == 0); // write once in interval
}


void stats_data_reader::handle_timer_expired(void *ctx)
{
	NOT_IN_USE(ctx);

	if (!should_write()) {
		return;
	}

	if (g_sh_mem->fd_dump != STATS_FD_STATISTICS_DISABLED) {
		if (g_p_event_handler_manager) {
			g_p_event_handler_manager->statistics_print(g_sh_mem->fd_dump, g_sh_mem->fd_dump_log_level);
		}
		g_sh_mem->fd_dump = STATS_FD_STATISTICS_DISABLED;
		g_sh_mem->fd_dump_log_level = STATS_FD_STATISTICS_LOG_LEVEL_DEFAULT;
	}
	stats_read_map_t::iterator iter;
	m_lock_data_map.lock();
	for (iter = m_data_map.begin(); iter != m_data_map.end(); iter++) {
		memcpy(SHM_DATA_ADDRESS, LOCAL_OBJECT_DATA, COPY_SIZE);
	}
	m_lock_data_map.unlock();

}

void stats_data_reader::register_to_timer()
{
	m_timer_handler = g_p_event_handler_manager->register_timer_event(STATS_PUBLISHER_TIMER_PERIOD, g_p_stats_data_reader, PERIODIC_TIMER, 0);
}

void stats_data_reader::add_data_reader(void* local_addr, void* shm_addr, int size)
{
	m_lock_data_map.lock();
	m_data_map[local_addr] = std::make_pair(shm_addr, size);
	m_lock_data_map.unlock();
}

void* stats_data_reader::pop_data_reader(void* local_addr)
{       
	void* rv = NULL;
	m_lock_data_map.lock();
	stats_read_map_t::iterator iter = m_data_map.find(local_addr);
	if (iter != m_data_map.end()) {//found
		rv = SHM_DATA_ADDRESS;
		m_data_map.erase(local_addr);
	}
	m_lock_data_map.unlock();
	return rv;
}

void write_version_details_to_shmem(version_info_t* p_ver_info)
{	
	p_ver_info->vma_lib_maj = VMA_LIBRARY_MAJOR;
	p_ver_info->vma_lib_min = VMA_LIBRARY_MINOR;
	p_ver_info->vma_lib_rev = VMA_LIBRARY_REVISION;
	p_ver_info->vma_lib_rel = VMA_LIBRARY_RELEASE;	
}

void vma_shmem_stats_open(vlog_levels_t** p_p_vma_log_level, uint8_t** p_p_vma_log_details)
{
	void *buf = NULL;
	void *p_shmem = NULL;
	int ret;
	size_t shmem_size = 0;
	mode_t saved_mode;

	g_p_stats_data_reader = new stats_data_reader();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (NULL == g_p_stats_data_reader) {
		vlog_printf(VLOG_ERROR,"%s:%d: Can't allocate g_p_stats_data_reader \n", __func__, __LINE__);
		goto shmem_error;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	shmem_size = SHMEM_STATS_SIZE(safe_mce_sys().stats_fd_num_max);
	buf = malloc(shmem_size);
	if (buf == NULL)
		goto shmem_error;
	memset(buf, 0, shmem_size);

	p_shmem = buf;

	if (strlen(safe_mce_sys().stats_shmem_dirname) <= 0)
		goto no_shmem;

	g_sh_mem_info.filename_sh_stats[0] = '\0';
	g_sh_mem_info.p_sh_stats = MAP_FAILED;
	ret = snprintf(g_sh_mem_info.filename_sh_stats, sizeof(g_sh_mem_info.filename_sh_stats), "%s/vmastat.%d", safe_mce_sys().stats_shmem_dirname, getpid());
	if (!((0 < ret) && (ret < (int)sizeof(g_sh_mem_info.filename_sh_stats)))) {
		vlog_printf(VLOG_ERROR, "%s: Could not create file under %s %m\n", __func__, safe_mce_sys().stats_shmem_dirname, errno);
		goto no_shmem;
	}
	saved_mode = umask(0);
	g_sh_mem_info.fd_sh_stats = open(g_sh_mem_info.filename_sh_stats, O_CREAT|O_RDWR,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	umask(saved_mode);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem_info.fd_sh_stats < 0) {
		vlog_printf(VLOG_ERROR, "%s: Could not open %s %m\n", __func__, g_sh_mem_info.filename_sh_stats, errno);
		goto no_shmem;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	ret = write(g_sh_mem_info.fd_sh_stats, buf, shmem_size);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		vlog_printf(VLOG_ERROR, "%s: Could not write to %s - %m\n", __func__, g_sh_mem_info.filename_sh_stats, errno);
		goto no_shmem;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	g_sh_mem_info.p_sh_stats = mmap(0, shmem_size, PROT_WRITE|PROT_READ, MAP_SHARED, g_sh_mem_info.fd_sh_stats, 0);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem_info.p_sh_stats == MAP_FAILED) {
		vlog_printf(VLOG_ERROR, "%s: MAP_FAILED for %s - %m\n", __func__, g_sh_mem_info.filename_sh_stats);
		goto no_shmem;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	p_shmem = g_sh_mem_info.p_sh_stats;

	free(buf);
	buf = NULL;

	goto success;

	no_shmem:
	if (g_sh_mem_info.p_sh_stats == MAP_FAILED) {
		if (g_sh_mem_info.fd_sh_stats > 0) {
			close(g_sh_mem_info.fd_sh_stats);
			unlink(g_sh_mem_info.filename_sh_stats);
		}
	}

	g_sh_mem_info.p_sh_stats = 0;

	success:

	MAP_SH_MEM(g_sh_mem, p_shmem);

	write_version_details_to_shmem(&g_sh_mem->ver_info);
	memcpy(g_sh_mem->stats_protocol_ver, STATS_PROTOCOL_VER, min(sizeof(g_sh_mem->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER)));
	g_sh_mem->max_skt_inst_num = safe_mce_sys().stats_fd_num_max;
	g_sh_mem->reader_counter = 0;
	__log_dbg("file '%s' fd %d shared memory at %p with %d max blocks\n", g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats, safe_mce_sys().stats_fd_num_max);

	// Update the shmem initial log values
	g_sh_mem->log_level = **p_p_vma_log_level;
	g_sh_mem->log_details_level = **p_p_vma_log_details;

	// Update the shmem with initial fd dump values
	g_sh_mem->fd_dump = STATS_FD_STATISTICS_DISABLED;
	g_sh_mem->fd_dump_log_level = STATS_FD_STATISTICS_LOG_LEVEL_DEFAULT;

	// ReMap internal log level to ShMem area
	*p_p_vma_log_level = &g_sh_mem->log_level;
	*p_p_vma_log_details = &g_sh_mem->log_details_level;

	g_p_stats_data_reader->register_to_timer();

	return;

	shmem_error:

	BULLSEYE_EXCLUDE_BLOCK_START
	g_sh_mem_info.fd_sh_stats = -1;
	g_sh_mem_info.p_sh_stats = MAP_FAILED;
	g_sh_mem = &g_local_sh_mem;
	g_sh_mem->reset();
	*p_p_vma_log_level = &g_sh_mem->log_level;
	*p_p_vma_log_details = &g_sh_mem->log_details_level;
	BULLSEYE_EXCLUDE_BLOCK_END
}

void vma_shmem_stats_close()
{
	if (g_sh_mem_info.p_sh_stats && g_sh_mem_info.p_sh_stats != MAP_FAILED) {
		__log_dbg("file '%s' fd %d shared memory at %p with %d max blocks\n", g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats, safe_mce_sys().stats_fd_num_max);

		BULLSEYE_EXCLUDE_BLOCK_START
		if (munmap(g_sh_mem_info.p_sh_stats, SHMEM_STATS_SIZE(safe_mce_sys().stats_fd_num_max)) != 0) {
			vlog_printf(VLOG_ERROR, "%s: file [%s] fd [%d] error while unmap shared memory at [%p]\n", __func__, g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats);
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		g_sh_mem_info.p_sh_stats = MAP_FAILED;

		if (g_sh_mem_info.fd_sh_stats)
			close(g_sh_mem_info.fd_sh_stats);

		if(!g_is_forked_child)
			unlink(g_sh_mem_info.filename_sh_stats);
	} else if (g_sh_mem_info.p_sh_stats != MAP_FAILED) {
		free(g_sh_mem);
	}
	g_sh_mem = NULL;
	g_p_vlogger_level = NULL;
	g_p_vlogger_details = NULL;
	delete g_p_stats_data_reader;
	g_p_stats_data_reader = NULL;
}

void vma_stats_instance_create_socket_block(socket_stats_t* local_stats_addr)
{
	socket_stats_t* p_skt_stats = NULL;
	g_lock_skt_inst_arr.lock();

	//search the first free sh_mem block
	for (uint32_t i = 0; i < g_sh_mem->max_skt_inst_num; i++) {
		if (g_sh_mem->skt_inst_arr[i].b_enabled == false) {
			// found free slot ,enabled and returning to the user
			p_skt_stats = &g_sh_mem->skt_inst_arr[i].skt_stats;
			g_sh_mem->skt_inst_arr[i].b_enabled = true;
			goto out;
		}

	}
	if (g_sh_mem->max_skt_inst_num + 1 < safe_mce_sys().stats_fd_num_max) {
		// allocate next sh_mem block 
		p_skt_stats = &g_sh_mem->skt_inst_arr[g_sh_mem->max_skt_inst_num].skt_stats;
		g_sh_mem->skt_inst_arr[g_sh_mem->max_skt_inst_num].b_enabled = true;
		g_sh_mem->max_skt_inst_num++;
		goto out;
	}
	else {
		if (!printed_sock_limit_info) {
			printed_sock_limit_info = true;
			vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d sockets - increase VMA_STATS_FD_NUM\n", safe_mce_sys().stats_fd_num_max);
		}
		goto out;
	}

	out:
	if (p_skt_stats) {
		p_skt_stats->reset();
		g_p_stats_data_reader->add_data_reader(local_stats_addr, p_skt_stats, sizeof(socket_stats_t));
	}
	g_lock_skt_inst_arr.unlock();
}

void vma_stats_instance_remove_socket_block(socket_stats_t* local_addr)
{

	g_lock_skt_inst_arr.lock();

	print_full_stats(local_addr, NULL, g_stats_file);
	socket_stats_t* p_skt_stats = (socket_stats_t*)g_p_stats_data_reader->pop_data_reader(local_addr);

	if (p_skt_stats == NULL) {
		__log_dbg("application vma_stats pointer is NULL\n");
		g_lock_skt_inst_arr.unlock();
		return;
	}

	//coverity - g_sh_mem->skt_inst_arr cannot be null
	/*BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem->skt_inst_arr == NULL) {
		vlog_printf(VLOG_ERROR,"%s:%d: g_sh_mem->instances_arr not init\n", __func__, __LINE__);
		g_lock_skt_stats.unlock();
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END*/

	// Search sh_mem block to release
	for (uint32_t i = 0; i < g_sh_mem->max_skt_inst_num; i++) {
		if (&g_sh_mem->skt_inst_arr[i].skt_stats == p_skt_stats) {
			g_sh_mem->skt_inst_arr[i].b_enabled = false;
			g_lock_skt_inst_arr.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)\n", __func__, __LINE__, p_skt_stats);
	g_lock_skt_inst_arr.unlock();
}

void vma_stats_mc_group_add(in_addr_t mc_grp, socket_stats_t* p_socket_stats)
{
	int empty_entry = -1; 
	int index_to_insert = -1;

	g_lock_mc_info.lock();
	for (int grp_idx = 0; grp_idx < g_sh_mem->mc_info.max_grp_num && index_to_insert == -1; grp_idx++) {
		if (g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num == 0 && empty_entry == -1)
			empty_entry = grp_idx;
		else if (g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num && g_sh_mem->mc_info.mc_grp_tbl[grp_idx].mc_grp == mc_grp) 
			index_to_insert = grp_idx;
	}

	if (index_to_insert == -1  && empty_entry != -1)
		index_to_insert = empty_entry;
	else if (index_to_insert == -1 && g_sh_mem->mc_info.max_grp_num < MC_TABLE_SIZE) {
		index_to_insert = g_sh_mem->mc_info.max_grp_num;
		g_sh_mem->mc_info.mc_grp_tbl[index_to_insert].mc_grp = mc_grp;
		g_sh_mem->mc_info.max_grp_num++;
	}

	if (index_to_insert != -1) {
		g_sh_mem->mc_info.mc_grp_tbl[index_to_insert].sock_num++;
		p_socket_stats->mc_grp_map.set((size_t)index_to_insert, 1);
	}
	g_lock_mc_info.unlock();
	if (index_to_insert == -1)
		vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d mc groups\n", MC_TABLE_SIZE);
}

void vma_stats_mc_group_remove(in_addr_t mc_grp, socket_stats_t* p_socket_stats)
{
	g_lock_mc_info.lock();
	for (int grp_idx = 0; grp_idx < g_sh_mem->mc_info.max_grp_num; grp_idx++) {
		if (g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num && g_sh_mem->mc_info.mc_grp_tbl[grp_idx].mc_grp == mc_grp) {
			p_socket_stats->mc_grp_map.set((size_t)grp_idx, 0);
			g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num--;
			if (!g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num)
				g_sh_mem->mc_info.max_grp_num--;
		}								
	}
	g_lock_mc_info.unlock();
}

void vma_stats_instance_create_ring_block(ring_stats_t* local_stats_addr)
{
	ring_stats_t* p_instance_ring = NULL;
	g_lock_ring_inst_arr.lock();
	for (int i=0; i < NUM_OF_SUPPORTED_RINGS; i++) {
		if (!g_sh_mem->ring_inst_arr[i].b_enabled) {
			g_sh_mem->ring_inst_arr[i].b_enabled = true;
			p_instance_ring = &g_sh_mem->ring_inst_arr[i].ring_stats;
			memset(p_instance_ring, 0, sizeof(*p_instance_ring));
			break;
		}
	}
	if (p_instance_ring == NULL) {
		if (!printed_ring_limit_info) {
			printed_ring_limit_info = true;
			vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d ring elements\n", NUM_OF_SUPPORTED_RINGS);
		}
	}
	else {
		g_p_stats_data_reader->add_data_reader(local_stats_addr, p_instance_ring, sizeof(ring_stats_t));
		__log_dbg("Added ring local=%p shm=%p\n", local_stats_addr, p_instance_ring);
	}
	g_lock_ring_inst_arr.unlock();
}

void vma_stats_instance_remove_ring_block(ring_stats_t* local_stats_addr)
{
	g_lock_ring_inst_arr.lock();
	__log_dbg("Remove ring local=%p\n", local_stats_addr);

	ring_stats_t* p_ring_stats = (ring_stats_t*)g_p_stats_data_reader->pop_data_reader(local_stats_addr);

	if (p_ring_stats == NULL) { // happens on the tx cq (why don't we keep tx cq stats?)
		__log_dbg("application vma_stats pointer is NULL\n");
		g_lock_ring_inst_arr.unlock();
		return;
	}

	//coverity - g_sh_mem->ring_inst_arr cannot be null
	/*BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem->ring_inst_arr == NULL) {
		vlog_printf(VLOG_ERROR,"%s:%d: g_sh_mem->instances_arr not init\n", __func__, __LINE__);
                g_lock_skt_stats.unlock();
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END*/

	// Search sh_mem block to release
	for (int i=0; i<NUM_OF_SUPPORTED_RINGS; i++) {
		if (&g_sh_mem->ring_inst_arr[i].ring_stats == p_ring_stats) {
			g_sh_mem->ring_inst_arr[i].b_enabled = false;
			g_lock_ring_inst_arr.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, p_ring_stats);
	g_lock_ring_inst_arr.unlock();
}

void vma_stats_instance_create_cq_block(cq_stats_t* local_stats_addr)
{
	cq_stats_t* p_instance_cq = NULL;
	g_lock_cq_inst_arr.lock();
	for (int i=0; i < NUM_OF_SUPPORTED_CQS; i++) {
		if (!g_sh_mem->cq_inst_arr[i].b_enabled) {
			g_sh_mem->cq_inst_arr[i].b_enabled = true;
			p_instance_cq = &g_sh_mem->cq_inst_arr[i].cq_stats;
			memset(p_instance_cq, 0, sizeof(*p_instance_cq));
			break;
		}
	}
	if (p_instance_cq == NULL) {
		if (!printed_cq_limit_info) {
			printed_cq_limit_info = true;
			vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d cq elements\n", NUM_OF_SUPPORTED_CQS);
		}
	}
	else {
		g_p_stats_data_reader->add_data_reader(local_stats_addr, p_instance_cq, sizeof(cq_stats_t));
		__log_dbg("Added cq local=%p shm=%p\n", local_stats_addr, p_instance_cq);
	}
	g_lock_cq_inst_arr.unlock();
}

void vma_stats_instance_remove_cq_block(cq_stats_t* local_stats_addr)
{
	g_lock_cq_inst_arr.lock();
	__log_dbg("Remove cq local=%p\n", local_stats_addr);

	cq_stats_t* p_cq_stats = (cq_stats_t*)g_p_stats_data_reader->pop_data_reader(local_stats_addr);

	if (p_cq_stats == NULL) { // happens on the tx cq (why don't we keep tx cq stats?)
		__log_dbg("application vma_stats pointer is NULL\n");
		g_lock_cq_inst_arr.unlock();
		return;
	}

	//coverity - g_sh_mem->cq_inst_arr cannot be null
	/*BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem->cq_inst_arr == NULL) {
		vlog_printf(VLOG_ERROR,"%s:%d: g_sh_mem->instances_arr not init\n", __func__, __LINE__);
                g_lock_skt_stats.unlock();
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END*/

	// Search sh_mem block to release
	for (int i=0; i<NUM_OF_SUPPORTED_CQS; i++) {
		if (&g_sh_mem->cq_inst_arr[i].cq_stats == p_cq_stats) {
			g_sh_mem->cq_inst_arr[i].b_enabled = false;
			g_lock_cq_inst_arr.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, p_cq_stats);
	g_lock_cq_inst_arr.unlock();
}

void vma_stats_instance_create_bpool_block(bpool_stats_t* local_stats_addr)
{
	bpool_stats_t* p_instance_bpool = NULL;
	g_lock_bpool_inst_arr.lock();
	for (int i=0; i < NUM_OF_SUPPORTED_BPOOLS; i++) {
		if (!g_sh_mem->bpool_inst_arr[i].b_enabled) {
			g_sh_mem->bpool_inst_arr[i].b_enabled = true;
			p_instance_bpool = &g_sh_mem->bpool_inst_arr[i].bpool_stats;
			memset(p_instance_bpool, 0, sizeof(bpool_stats_t));
			break;
		}
	}
	if (p_instance_bpool == NULL) {
		if (!printed_bpool_limit_info) {
			printed_bpool_limit_info = true;
			vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d buffer pools\n", NUM_OF_SUPPORTED_BPOOLS);
		}
	}
	else {
		g_p_stats_data_reader->add_data_reader(local_stats_addr, p_instance_bpool, sizeof(bpool_stats_t));
		__log_dbg("Added bpool local=%p shm=%p\n", local_stats_addr, p_instance_bpool);
	}
	g_lock_bpool_inst_arr.unlock();
}

void vma_stats_instance_remove_bpool_block(bpool_stats_t* local_stats_addr)
{
	g_lock_bpool_inst_arr.lock();
	__log_dbg("Remove bpool local=%p\n", local_stats_addr);

	bpool_stats_t* p_bpool_stats = (bpool_stats_t*)g_p_stats_data_reader->pop_data_reader(local_stats_addr);

	if (p_bpool_stats == NULL) {
		__log_dbg("application vma_stats pointer is NULL\n");
		g_lock_bpool_inst_arr.unlock();
		return;
	}

	// Search sh_mem block to release
	for (int i=0; i<NUM_OF_SUPPORTED_BPOOLS; i++) {
		if (&g_sh_mem->bpool_inst_arr[i].bpool_stats == p_bpool_stats) {
			g_sh_mem->bpool_inst_arr[i].b_enabled = false;
			g_lock_bpool_inst_arr.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, p_bpool_stats);
	g_lock_bpool_inst_arr.unlock();
}

void  vma_stats_instance_get_poll_block(iomux_func_stats_t* local_stats_addr)
{
	g_p_stats_data_reader->add_data_reader(local_stats_addr, &g_sh_mem->iomux.poll, sizeof(iomux_func_stats_t));
}

void vma_stats_instance_get_select_block(iomux_func_stats_t* local_stats_addr)
{
	g_p_stats_data_reader->add_data_reader(local_stats_addr, &g_sh_mem->iomux.select, sizeof(iomux_func_stats_t));
}

void vma_stats_instance_create_epoll_block(int fd, iomux_func_stats_t* local_stats_addr)
{
	g_lock_iomux.lock();

	for (unsigned i = 0; i < NUM_OF_SUPPORTED_EPFDS; ++i) {
		epoll_stats_t* ep_stats = &g_sh_mem->iomux.epoll[i];
		if (!ep_stats->enabled) {
			ep_stats->enabled = true;
			ep_stats->epfd = fd;
			g_p_stats_data_reader->add_data_reader(local_stats_addr, &ep_stats->stats, sizeof(iomux_func_stats_t));
			g_lock_iomux.unlock();
			return;
		}
	}

	vlog_printf(VLOG_INFO, "VMA Statistics can monitor up to %d epoll fds", NUM_OF_SUPPORTED_EPFDS);
	g_lock_iomux.unlock();
	return;
}

void vma_stats_instance_remove_epoll_block(iomux_func_stats_t* local_stats_addr)
{
	g_lock_iomux.lock();
	iomux_func_stats_t* ep_func_stats = (iomux_func_stats_t*)g_p_stats_data_reader->pop_data_reader(local_stats_addr);

	if (NULL == ep_func_stats) {
		__log_dbg("application vma_stats pointer is NULL\n");
		g_lock_iomux.unlock();
		return;
	}

	// Search ep_mem block to release
	for (int i=0; i<NUM_OF_SUPPORTED_EPFDS; i++) {
		if (&g_sh_mem->iomux.epoll[i].stats == ep_func_stats) {
			g_sh_mem->iomux.epoll[i].enabled = false;
			g_lock_iomux.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, ep_func_stats);
	g_lock_iomux.unlock();
	return;
}
