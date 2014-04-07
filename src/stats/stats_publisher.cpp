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

#include <vma/util/vma_stats.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>

#include <vma/util/lock_wrapper.h>
#include <vma/util/vtypes.h>
#include <vlogger/vlogger.h>
#include <vma/sock/sock-redirect.h>
#include <vma/event/event_handler_manager.h>
#include <vma/event/timer_handler.h>
#include <stats/stats_data_reader.h>
#include "vma/util/bullseye.h"

static lock_spin	g_lock_skt_stats("g_lock_stats");
static lock_spin	g_lock_mc_grp_info("g_lock_mc_grp_info");
static lock_spin	g_lock_ep_stats("g_lock_ep_stats");
static sh_mem_info_t	g_sh_mem_info;
static sh_mem_t*	g_sh_mem;
static sh_mem_t		g_local_sh_mem;

//statistic file
FILE* g_stats_file = NULL;
stats_data_reader*  g_p_stats_data_reader = NULL;

#define STATS_PUBLISHER_TIMER_PERIOD    200
#define TEN_SECS                        10*1000/STATS_PUBLISHER_TIMER_PERIOD

static int      reader_counter = 0;
int             ten_sec_counter = 0;
bool            active_reading = false;

bool		printed_sock_limit_info = false;
bool		printed_ring_limit_info = false;
bool		printed_cq_limit_info = false;


stats_data_reader::stats_data_reader()
{
        m_timer_handler = NULL;
}


#define LOCAL_OBJECT_DATA       iter->first
#define SHM_DATA_ADDRESS        iter->second.first
#define COPY_SIZE               iter->second.second 

bool active_reader_on()
{
        bool rv = true;

        //if there is an active reader - test the counter at 10 secs interval
        if (active_reading) {
                ten_sec_counter++;
                if (ten_sec_counter == TEN_SECS) {
                        ten_sec_counter = 0;
                        if (reader_counter == g_sh_mem->reader_counter) { // after ten secs - test for active reader
                                rv = false;
                                active_reading = false;
                        }
                }
        }
        else { // no active reader - test for one every STATS_PUBLISHER_TIMER_PERIOD
                if (reader_counter == g_sh_mem->reader_counter){
                        rv = false;
                     
                }
                else {
                        active_reading = true;
                }
        }
        // set for next round
        reader_counter = g_sh_mem->reader_counter;
        return rv;
}


void stats_data_reader::handle_timer_expired(void *ctx)
{
        NOT_IN_USE(ctx); 
        
        if (!active_reader_on()) {
                return;
        }

        stats_read_map_t::iterator iter;
	g_lock_skt_stats.lock();
	for (iter = m_data_map.begin(); iter != m_data_map.end(); iter++) {
                memcpy(SHM_DATA_ADDRESS, LOCAL_OBJECT_DATA, COPY_SIZE);
        }
	g_lock_skt_stats.unlock();

}

void stats_data_reader::register_to_timer()
{
        m_timer_handler = g_p_event_handler_manager->register_timer_event(STATS_PUBLISHER_TIMER_PERIOD, g_p_stats_data_reader, PERIODIC_TIMER, 0);
}

int stats_data_reader::add_data_reader(void* local_addr, void* shm_addr, int size)
{
        m_data_map[local_addr] = std::make_pair(shm_addr, size);
        return 0;
}

void* stats_data_reader::pop_p_skt_stats(void* local_addr)
{       
        void* rv = NULL;
        stats_read_map_t::iterator iter = m_data_map.find(local_addr);
        if (iter != m_data_map.end()) {//found
                rv = SHM_DATA_ADDRESS;
                m_data_map.erase(local_addr);
        }
        return rv;


}

void write_version_details_to_shmem(version_info_t* p_ver_info)
{	
	p_ver_info->vma_lib_maj = VMA_LIBRARY_MAJOR;
	p_ver_info->vma_lib_min = VMA_LIBRARY_MINOR;
	p_ver_info->vma_lib_rev = VMA_LIBRARY_REVISION;
	p_ver_info->vma_lib_rel = VMA_LIBRARY_RELEASE;	
}

void vma_shmem_stats_open(uint8_t** p_p_vma_log_level, uint8_t** p_p_vma_log_details)
{
	void* buf;
	int ret;
	size_t shmem_size = 0;
        mode_t saved_mode;

        g_p_stats_data_reader = new stats_data_reader();

	BULLSEYE_EXCLUDE_BLOCK_START
	if ( NULL == g_p_stats_data_reader ) {
		vlog_printf(VLOG_ERROR,"%s:%d: Can't allocate g_p_stats_data_reader \n", __func__, __LINE__);
		goto shmem_error;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	g_sh_mem_info.filename_sh_stats[0] = '\0';
	g_sh_mem_info.p_sh_stats = MAP_FAILED;
	sprintf(g_sh_mem_info.filename_sh_stats, "/tmp/vmastat.%d", getpid());
        saved_mode = umask(0);
	g_sh_mem_info.fd_sh_stats = open(g_sh_mem_info.filename_sh_stats, O_CREAT|O_RDWR, S_IRWXU | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        umask(saved_mode);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem_info.fd_sh_stats < 0) {
		vlog_printf(VLOG_ERROR, "%s: Could not open %s %m\n", __func__, g_sh_mem_info.filename_sh_stats, errno);
		goto shmem_error;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	shmem_size = SHMEM_STATS_SIZE(mce_sys.stats_fd_num_max);
	buf = malloc(shmem_size);
	memset(buf, 0, shmem_size);
	ret = write(g_sh_mem_info.fd_sh_stats, buf, shmem_size);
	free(buf);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (ret < 0) {
		vlog_printf(VLOG_ERROR, "%s: Could not write to %s - %m\n", __func__, g_sh_mem_info.filename_sh_stats, errno);
		goto shmem_error;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	g_sh_mem_info.p_sh_stats = mmap(0, shmem_size, PROT_WRITE|PROT_READ, MAP_SHARED, g_sh_mem_info.fd_sh_stats, 0);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem_info.p_sh_stats == MAP_FAILED) {
		vlog_printf(VLOG_ERROR, "%s: MAP_FAILED for %s - %m\n", __func__, g_sh_mem_info.filename_sh_stats);
		goto shmem_error;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	MAP_SH_MEM(g_sh_mem, g_sh_mem_info.p_sh_stats);
	
	write_version_details_to_shmem(&g_sh_mem->ver_info);
	g_sh_mem->max_skt_inst_num = mce_sys.stats_fd_num_max;
        g_sh_mem->reader_counter = 0;
	vlog_printf(VLOG_DEBUG, "%s: file '%s' fd %d shared memory at %p with %d max blocks\n", __func__, g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats, mce_sys.stats_fd_num_max);

	// Update the shmem initial log values
	g_sh_mem->log_level = **p_p_vma_log_level;
	g_sh_mem->log_details_level = **p_p_vma_log_details;

	// ReMap internal log level to ShMem area
	*p_p_vma_log_level = &g_sh_mem->log_level;
	*p_p_vma_log_details = &g_sh_mem->log_details_level;

        g_p_stats_data_reader->register_to_timer();

	return;

shmem_error:

	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_sh_mem_info.fd_sh_stats > 0) {
		close(g_sh_mem_info.fd_sh_stats);
		unlink(g_sh_mem_info.filename_sh_stats);
	}
	g_sh_mem_info.fd_sh_stats = -1;
	g_sh_mem_info.p_sh_stats = MAP_FAILED;
	g_sh_mem = &g_local_sh_mem;
	memset((void*)g_sh_mem, 0, sizeof(sh_mem_t));
	*p_p_vma_log_level = &g_sh_mem->log_level;
	*p_p_vma_log_details = &g_sh_mem->log_details_level;
	BULLSEYE_EXCLUDE_BLOCK_END
}

void vma_shmem_stats_close()
{
	if (g_sh_mem_info.p_sh_stats && g_sh_mem_info.p_sh_stats != MAP_FAILED) {
		vlog_printf(VLOG_DEBUG, "%s: file '%s' fd %d shared memory at %p with %d max blocks\n", __func__, g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats, mce_sys.stats_fd_num_max);

		BULLSEYE_EXCLUDE_BLOCK_START
		if (munmap(g_sh_mem_info.p_sh_stats, SHMEM_STATS_SIZE(mce_sys.stats_fd_num_max)) != 0) {
			vlog_printf(VLOG_ERROR, "%s: file [%s] fd [%d] error while unmap shared memory at [%p]\n", __func__, g_sh_mem_info.filename_sh_stats, g_sh_mem_info.fd_sh_stats, g_sh_mem_info.p_sh_stats);
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		g_sh_mem_info.p_sh_stats = MAP_FAILED;

		if (g_sh_mem_info.fd_sh_stats)
			close(g_sh_mem_info.fd_sh_stats);

		if(!g_is_forked_child)
			unlink(g_sh_mem_info.filename_sh_stats);
	}
	g_sh_mem = NULL;
	g_p_vlogger_level = NULL;
	g_p_vlogger_details = NULL;
}

void vma_stats_instance_create_socket_block(socket_stats_t* local_stats_addr)
{
	socket_stats_t* p_skt_stats = NULL;
	g_lock_skt_stats.lock();

	//search the first free sh_mem block
	for (uint32_t i = 0; i < g_sh_mem->max_skt_inst_num; i++) {
		if (g_sh_mem->skt_inst_arr[i].b_enabled == false) {
			// found free slot ,enabled and returning to the user
			p_skt_stats = &g_sh_mem->skt_inst_arr[i].skt_stats;
			g_sh_mem->skt_inst_arr[i].b_enabled = true;
			goto out;
		}

	}
	if (g_sh_mem->max_skt_inst_num + 1 < mce_sys.stats_fd_num_max) {
		// allocate next sh_mem block 
		p_skt_stats = &g_sh_mem->skt_inst_arr[g_sh_mem->max_skt_inst_num].skt_stats;
		g_sh_mem->skt_inst_arr[g_sh_mem->max_skt_inst_num].b_enabled = true;
		g_sh_mem->max_skt_inst_num++;
		goto out;
	}
	else {
		if (!printed_sock_limit_info) {
			printed_sock_limit_info = true;
			vlog_printf(VLOG_INFO, "Can only monitor %d socket in statistics - increase VMA_STATS_FD_NUM!\n", mce_sys.stats_fd_num_max);
		}
		goto out;
	}

out:
	if (p_skt_stats) {
		memset(p_skt_stats, 0, sizeof(socket_stats_t));
		p_skt_stats->mc_grp_map.reset();
                g_p_stats_data_reader->add_data_reader(local_stats_addr, p_skt_stats, sizeof(socket_stats_t));
	}
	g_lock_skt_stats.unlock();
}

void vma_stats_instance_remove_socket_block(socket_stats_t* local_addr)
{

	g_lock_skt_stats.lock();

	vlog_printf(VLOG_DEBUG, "%s:%d\n", __func__, __LINE__);
	print_full_stats(local_addr, NULL, g_stats_file);
	socket_stats_t* p_skt_stats = (socket_stats_t*)g_p_stats_data_reader->pop_p_skt_stats(local_addr);

	if (p_skt_stats == NULL) {
		vlog_printf(VLOG_DEBUG,"%s:%d: application vma_stats pointer is NULL\n", __func__, __LINE__);
		g_lock_skt_stats.unlock();
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
			g_lock_skt_stats.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)\n", __func__, __LINE__, p_skt_stats);
	g_lock_skt_stats.unlock();
}

void vma_stats_mc_group_add(in_addr_t mc_grp, socket_stats_t* p_socket_stats)
{
	int empty_entry = -1; 
	int index_to_insert = -1;
	
	g_lock_mc_grp_info.lock();
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
	g_lock_mc_grp_info.unlock();
	if (index_to_insert == -1)
		vlog_printf(VLOG_WARNING, "Cannot stat more than %d mc groups !\n", MC_TABLE_SIZE);
}

void vma_stats_mc_group_remove(in_addr_t mc_grp, socket_stats_t* p_socket_stats)
{
	g_lock_mc_grp_info.lock();
	for (int grp_idx = 0; grp_idx < g_sh_mem->mc_info.max_grp_num; grp_idx++) {
		if (g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num && g_sh_mem->mc_info.mc_grp_tbl[grp_idx].mc_grp == mc_grp) {
			p_socket_stats->mc_grp_map.set((size_t)grp_idx, 0);
			g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num--;
			if (!g_sh_mem->mc_info.mc_grp_tbl[grp_idx].sock_num)
				g_sh_mem->mc_info.max_grp_num--;
		}								
	}
	g_lock_mc_grp_info.unlock();
}

void vma_stats_instance_create_ring_block(ring_stats_t* local_stats_addr)
{
	ring_stats_t* p_instance_ring = NULL;
	g_lock_skt_stats.lock();
	for (int i=0; i < NUM_OF_SUPPORTED_RINGS; i++) {
		if (!g_sh_mem->ring_inst_arr[i].b_enabled) {
			g_sh_mem->ring_inst_arr[i].b_enabled = true;
			p_instance_ring = &g_sh_mem->ring_inst_arr[i].ring_stats;
			memset(p_instance_ring, 0, sizeof(ring_stats_t));
			break;
		}
	}
	if (p_instance_ring == NULL) {
		if (!printed_ring_limit_info) {
			printed_ring_limit_info = true;
			vlog_printf(VLOG_INFO, "Can only monitor %d ring elements for statistics !\n", NUM_OF_SUPPORTED_RINGS);
		}
	}
        else {
                g_p_stats_data_reader->add_data_reader(local_stats_addr, p_instance_ring, sizeof(ring_stats_t));
                vlog_printf(VLOG_DEBUG, "%s:%d: Added ring local=%p shm=%p\n", __func__, __LINE__, local_stats_addr, p_instance_ring);
        }
	g_lock_skt_stats.unlock();
}

void vma_stats_instance_remove_ring_block(ring_stats_t* local_stats_addr)
{
	g_lock_skt_stats.lock();
        vlog_printf(VLOG_DEBUG, "%s:%d: Remove ring local=%p\n", __func__, __LINE__, local_stats_addr);

        ring_stats_t* p_ring_stats = (ring_stats_t*)g_p_stats_data_reader->pop_p_skt_stats(local_stats_addr);

	if (p_ring_stats == NULL) { // happens on the tx cq (why don't we keep tx cq stats?)
		vlog_printf(VLOG_DEBUG, "%s:%d: application vma_stats pointer is NULL\n", __func__, __LINE__);
                g_lock_skt_stats.unlock();
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
			g_lock_skt_stats.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, p_ring_stats);
	g_lock_skt_stats.unlock();
}

void vma_stats_instance_create_cq_block(cq_stats_t* local_stats_addr)
{
	cq_stats_t* p_instance_cq = NULL;
	g_lock_skt_stats.lock();
	for (int i=0; i < NUM_OF_SUPPORTED_CQS; i++) {
		if (!g_sh_mem->cq_inst_arr[i].b_enabled) {
			g_sh_mem->cq_inst_arr[i].b_enabled = true;
			p_instance_cq = &g_sh_mem->cq_inst_arr[i].cq_stats;
			memset(p_instance_cq, 0, sizeof(cq_stats_t));
			break;
		}
	}
	if (p_instance_cq == NULL) {
		if (!printed_cq_limit_info) {
			printed_cq_limit_info = true;
			vlog_printf(VLOG_INFO, "Can only monitor %d cq elements for statistics !\n", NUM_OF_SUPPORTED_CQS);
		}
	}
        else {
                g_p_stats_data_reader->add_data_reader(local_stats_addr, p_instance_cq, sizeof(cq_stats_t));
                vlog_printf(VLOG_DEBUG, "%s:%d: Added cq local=%p shm=%p\n", __func__, __LINE__, local_stats_addr, p_instance_cq);
        }
	g_lock_skt_stats.unlock();
}

void vma_stats_instance_remove_cq_block(cq_stats_t* local_stats_addr)
{
	g_lock_skt_stats.lock();
        vlog_printf(VLOG_DEBUG, "%s:%d: Remove cq local=%p\n", __func__, __LINE__, local_stats_addr);

        cq_stats_t* p_cq_stats = (cq_stats_t*)g_p_stats_data_reader->pop_p_skt_stats(local_stats_addr);

	if (p_cq_stats == NULL) { // happens on the tx cq (why don't we keep tx cq stats?)
		vlog_printf(VLOG_DEBUG, "%s:%d: application vma_stats pointer is NULL\n", __func__, __LINE__);
                g_lock_skt_stats.unlock();
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
			g_lock_skt_stats.unlock();
			return;
		}
	}

	vlog_printf(VLOG_ERROR, "%s:%d: Could not find user pointer (%p)", __func__, __LINE__, p_cq_stats);
	g_lock_skt_stats.unlock();
}

void  vma_stats_instance_get_poll_block(iomux_func_stats_t* local_stats_addr)
{
	g_lock_ep_stats.lock();
        g_p_stats_data_reader->add_data_reader(local_stats_addr, &g_sh_mem->iomux.poll, sizeof(iomux_func_stats_t));
	g_lock_ep_stats.unlock();
}

void vma_stats_instance_get_select_block(iomux_func_stats_t* local_stats_addr)
{
	g_lock_ep_stats.lock();
        g_p_stats_data_reader->add_data_reader(local_stats_addr, &g_sh_mem->iomux.select, sizeof(iomux_func_stats_t));
	g_lock_ep_stats.unlock();
}

void vma_stats_instance_create_epoll_block(int fd, iomux_func_stats_t* local_stats_addr)
{
	g_lock_ep_stats.lock();

	for (unsigned i = 0; i < NUM_OF_SUPPORTED_EPFDS; ++i) {
		epoll_stats_t* ep_stats = &g_sh_mem->iomux.epoll[i];
		if (!ep_stats->enabled) {
			ep_stats->enabled = true;
			ep_stats->epfd = fd;
			g_p_stats_data_reader->add_data_reader(local_stats_addr, &ep_stats->stats, sizeof(iomux_func_stats_t));
			g_lock_ep_stats.unlock();
			return;
		}
	}

	vlog_printf(VLOG_WARNING, "Cannot stat more than %d epoll sets\n", NUM_OF_SUPPORTED_EPFDS);
	g_lock_ep_stats.unlock();
	return;
}

void vma_stats_instance_remove_epoll_block(iomux_func_stats_t* local_stats_addr)
{
	g_lock_ep_stats.lock();
        epoll_stats_t* ep_stats = (epoll_stats_t*)g_p_stats_data_reader->pop_p_skt_stats(local_stats_addr);
        if (ep_stats)
                ep_stats->enabled = false;
	g_lock_ep_stats.unlock();
}

