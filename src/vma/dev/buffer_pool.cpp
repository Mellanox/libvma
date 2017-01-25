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


#include "buffer_pool.h"

#include <stdlib.h>
#include <sys/param.h> // for MIN
#include <sys/shm.h>
#include <sys/mman.h>

#include "vlogger/vlogger.h"
#include "vma/util/sys_vars.h"
#include "vma/util/verbs_extra.h"
#include "vma/proto/mem_buf_desc.h"
#include "vma/util/bullseye.h"

#include "ib_ctx_handler_collection.h"

#define MODULE_NAME 	"bpool"

buffer_pool::buffer_pool(size_t buffer_count, size_t buf_size, mem_buf_desc_owner *owner, pbuf_free_custom_fn custom_free_function) :
			m_n_buffers(0), m_n_buffers_created(buffer_count),
			m_is_contig_alloc(true), m_shmid(-1),
			m_p_mr_arr(NULL), m_mr_arr_size(0), m_p_head(NULL)
{
	size_t sz_aligned_element = 0;
	uint8_t *ptr_buff, *ptr_desc;
	uint64_t access = VMA_IBV_ACCESS_LOCAL_WRITE;

	__log_info_func("count = %d", buffer_count);

	size_t size;
	if (buffer_count) {
		sz_aligned_element = (buf_size + MCE_ALIGNMENT) & (~MCE_ALIGNMENT);
		size = (sizeof(mem_buf_desc_t) + sz_aligned_element) * buffer_count + MCE_ALIGNMENT;
	} else {
		size = buf_size;
	}

	//
	//Huge pages falls back to Contiguous pages that falls back to Anon (Malloc).
	//
	switch (mce_sys.mem_alloc_type) {
	case ALLOC_TYPE_HUGEPAGES:
		if (!hugetlb_alloc(size)) {
			__log_info_dbg("Failed allocating huge pages, falling back to contiguous pages");
		}
		else {
			__log_info_dbg("Huge pages allocation passed successfully");
			if (!register_memory(size, access)) {
				__log_info_dbg("failed registering huge pages data memory block");
				free_bpool_resources();
				throw_vma_exception_no_msg();
			}
			break;
		}
	case ALLOC_TYPE_CONTIG:
#ifndef VMA_IBV_ACCESS_ALLOCATE_MR
		m_is_contig_alloc = false;
#else
		m_data_block = NULL;
		access |= VMA_IBV_ACCESS_ALLOCATE_MR; // for contiguous pages use only
		if (!register_memory(size, access)) {
			__log_info_dbg("Failed allocating contiguous pages");
			m_is_contig_alloc = false;
		}
		else {
			__log_info_dbg("Contiguous pages allocation passed successfully");
			break;
		}
#endif
	case ALLOC_TYPE_ANON:
	default:
		__log_info_dbg("allocating memory using malloc()");
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
		access &= ~VMA_IBV_ACCESS_ALLOCATE_MR;
#endif
		m_data_block = malloc(size);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_data_block == NULL) {
			__log_info_dbg("failed allocating data memory block (size=%d Kbytes) (errno=%d %m)",
					size/1024, errno);
			free_bpool_resources();
			throw_vma_exception_no_msg();
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!register_memory(size, access)) {
			__log_info_dbg("failed registering data memory block");
			free_bpool_resources();
			throw_vma_exception_no_msg();
		}
		break;
	}

	if (!buffer_count) return;

	// Align pointers
	ptr_buff = (uint8_t *)((unsigned long)((char*)m_data_block + MCE_ALIGNMENT) & (~MCE_ALIGNMENT));
	ptr_desc = ptr_buff + sz_aligned_element * buffer_count;

	// Split the block to buffers
	for (size_t i = 0; i < buffer_count; ++i) {

		mem_buf_desc_t* ptr_desc_mbdt = (mem_buf_desc_t*)ptr_desc;
		memset(ptr_desc_mbdt, 0, sizeof (*ptr_desc_mbdt));
		mem_buf_desc_t *desc = new (ptr_desc) mem_buf_desc_t(ptr_buff, buf_size);
		desc->serial_num = i;
		desc->p_desc_owner = owner;
		desc->lwip_pbuf.custom_free_function = custom_free_function;
		desc->p_bpool=this;
		put_buffer_helper(desc);

		ptr_buff += sz_aligned_element;
		ptr_desc += sizeof(mem_buf_desc_t);
	}

	__log_info_func("done");
}

buffer_pool::~buffer_pool()
{
	free_bpool_resources();
}

void buffer_pool::free_bpool_resources()
{
	if (m_n_buffers == m_n_buffers_created) {
		__log_info_func("count %lu, missing %lu", m_n_buffers, m_n_buffers_created-m_n_buffers);
	}
	else {
		__log_info_dbg("count %lu, missing %lu", m_n_buffers, m_n_buffers_created - m_n_buffers);
	}

	// Unregister memory
	for (uint i=0; i < m_mr_arr_size; i++) {
		ibv_mr *mr = m_p_mr_arr[i];
		ib_ctx_handler* p_ib_ctx_handler = g_p_ib_ctx_handler_collection->get_ib_ctx(mr->context);
		if (!p_ib_ctx_handler->is_removed()) {
			IF_VERBS_FAILURE(ibv_dereg_mr(mr)) {
				__log_info_err("failed de-registering a memory region (errno=%d %m)", errno);
			} ENDIF_VERBS_FAILURE;
		}
	}

	// Release mr array
	delete[] m_p_mr_arr;

	// Release memory
	if (m_shmid >= 0) { // Huge pages mode
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_data_block && (shmdt(m_data_block) != 0)) {
			__log_info_err("shmem detach failure %m");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	} else if (!m_is_contig_alloc){ // in contig mode 'ibv_dereg_mr' will free all allocates resources
		free(m_data_block);
	}

	__log_info_func("done");
}

bool buffer_pool::hugetlb_alloc(size_t sz_bytes)
{
	size_t hugepagemask = 4 * 1024 * 1024 - 1;
	sz_bytes = (sz_bytes + hugepagemask) & (~hugepagemask);

	__log_info_dbg("Allocating %ld bytes in huge tlb", sz_bytes);

	// allocate memory
	m_shmid = shmget(IPC_PRIVATE, sz_bytes,
			SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	if (m_shmid < 0) {

		// Stop trying to use HugePage if failed even once
		mce_sys.mem_alloc_type = ALLOC_TYPE_CONTIG;

		vlog_printf(VLOG_WARNING, "***************************************************************\n");
		vlog_printf(VLOG_WARNING, "* NO IMMEDIATE ACTION NEEDED!                                 *\n");
		vlog_printf(VLOG_WARNING, "* Not enough hugepage resources for VMA memory allocation.    *\n");
		vlog_printf(VLOG_WARNING, "* VMA will continue working with regular memory allocation.   *\n");
		vlog_printf(VLOG_INFO,    "* Optional: 1. Switch to a different memory allocation type   *\n");
		vlog_printf(VLOG_INFO,	  "* 	     (%s= 0 or 1)	            *\n", SYS_VAR_MEM_ALLOC_TYPE);
		vlog_printf(VLOG_INFO,    "*           2. Restart process after increasing the number of *\n");
		vlog_printf(VLOG_INFO,    "*              hugepages resources in the system:             *\n");
		vlog_printf(VLOG_INFO,    "* \"cat /proc/meminfo |  grep -i HugePage\"                     *\n");
		vlog_printf(VLOG_INFO,    "* \"echo 1000000000 > /proc/sys/kernel/shmmax\"                 *\n");
		vlog_printf(VLOG_INFO,    "* \"echo 800 > /proc/sys/vm/nr_hugepages\"                      *\n");
		vlog_printf(VLOG_WARNING, "* Please refer to the memory allocation section in the VMA's  *\n");
		vlog_printf(VLOG_WARNING, "* User Manual for more information			    *\n");
		vlog_printf(VLOG_WARNING, "***************************************************************\n");
		return false;
	}

	// get pointer to allocated memory
	m_data_block = shmat(m_shmid, NULL, 0);
	if (m_data_block == (void*)-1) {
		__log_info_warn("Shared memory attach failure (errno=%d %m)", errno);
		shmctl(m_shmid, IPC_RMID, NULL);
		m_shmid = -1;
		m_data_block = NULL;
		return false;
	}

	// mark 'to be destroyed' when process detaches from shmem segment
	// this will clear the HugePage resources even if process if killed not nicely
	if (shmctl(m_shmid, IPC_RMID, NULL)) {
		__log_info_warn("Shared memory contrl mark 'to be destroyed' failed (errno=%d %m)", errno);
	}

	// We want to determine now that we can lock it. Note: it was claimed that without actual mlock, linux might be buggy on this with huge-pages
	int rc = mlock(m_data_block, sz_bytes);
	if (rc!=0) {
		__log_info_warn("mlock of shared memory failure (errno=%d %m)", errno);
		if (shmdt(m_data_block) != 0) {
			__log_info_err("shmem detach failure %m");
		}
		m_data_block = NULL; // no value to try shmdt later
		m_shmid = -1;
		return false;
	}

	return true;
}

bool buffer_pool::register_memory(size_t size, uint64_t access)
{
	if (m_p_mr_arr) {
		__log_info_warn("Function register_memory called but memory is already registered. Please refer to README.txt for more info");
		return true;
	}

	m_mr_arr_size = g_p_ib_ctx_handler_collection->get_num_devices();
	m_p_mr_arr = new ibv_mr*[m_mr_arr_size];


	BULLSEYE_EXCLUDE_BLOCK_START
	if (g_p_ib_ctx_handler_collection->mem_reg_on_all_devices(m_data_block, size, m_p_mr_arr,
			m_mr_arr_size, access) != m_mr_arr_size) {
		if (m_data_block) {
			__log_info_warn("Failed registering memory, This might happen due to low MTT entries. Please refer to README.txt for more info");
			__log_info_dbg("Failed registering memory block with device (ptr=%p size=%ld%s) (errno=%d %m)",
					m_data_block, size, errno);
			free_bpool_resources();
			throw_vma_exception_no_msg();
		} else {
			__log_info_warn("Failed allocating or registering memory in contiguous mode. Please refer to README.txt for more info");
			return false;
		}
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (!m_data_block) { // contig pages mode
		m_data_block = m_p_mr_arr[0]->addr;
		if (!m_data_block) {
			__log_info_dbg("Failed registering memory, check that OFED is loaded successfully");
			free_bpool_resources();
			throw_vma_exception_no_msg();
		}
	}

	return true;
}

mem_buf_desc_t *buffer_pool::get_buffers(size_t count, const ib_ctx_handler *p_ib_ctx_h)
{
	NOT_IN_USE(p_ib_ctx_h);
	mem_buf_desc_t *next, *head;

	__log_info_funcall("requested %lu, present %lu, created %lu",
			   count, m_n_buffers, m_n_buffers_created);

	if (m_n_buffers < count) {
		static vlog_levels_t log_severity = VLOG_DEBUG; // DEBUG severity will be used only once - at the 1st time

		VLOG_PRINTF_INFO(log_severity, "not enough buffers in the pool (requested: %lu, have: %lu, created: %lu)",
				count, m_n_buffers, m_n_buffers_created);

		log_severity = VLOG_FUNC; // for all times but the 1st one

		return NULL;
	}

	// pop buffers from the list
	head = NULL;
	m_n_buffers -= count;

	while (count > 0) {
		next = m_p_head->p_next_desc;
		m_p_head->p_next_desc = head;
		head = m_p_head;
		m_p_head = next;
		--count;
	}

	return head;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
/*
 * this function is minimal C version of Floyd's cycle-finding algorithm
 * just for determining whether a circle exists or not.
 * Complexity is O(n)
 * see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
 */
bool isCircle (mem_buf_desc_t *pNode) {
	if (!pNode) return false;

	mem_buf_desc_t *p1 = pNode;
	mem_buf_desc_t *p2 = pNode;

	while (p2->p_next_desc && p2->p_next_desc->p_next_desc)
	{
		p1 = p1->p_next_desc;
		p2 = p2->p_next_desc->p_next_desc;
		if (p1 == p2)
			return true;
	}
	return false;
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

typedef mem_buf_desc_t* Node;

static inline Node f(Node x) {
	// NOTE: after we determined we have a circle, no need to check for nullity
	return x->p_next_desc;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
// full version of Floyd's cycle-finding algorithm
// see: http://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
void Floyd_LogCircleInfo(Node x0) {

	// The main phase of the algorithm, finding a repetition x_mu = x_2mu
	// The hare moves twice as quickly as the tortoise
	Node tortoise = f(x0); // f(x0) is the element/node next to x0.
	Node hare = f(f(x0));
	while (tortoise != hare) {
		tortoise = f(tortoise);
		hare = f(f(hare));
	}

	// at this point tortoise position is equvi-distant from x0
	// and current hare position (which is the same as tortoise position).  This is
	// true because tortoise moved exactly half of the hare way.
	// so hare (set to tortoise-current position and move at tortoise speed) moving in
	// circle and tortoise (set to x0 ) moving towards circle, must meet at
	// current hare position (== current turtle position).  Realize that they move
	// in same speed, the first intersection will be the beginning of the circle.
	//

	// Find the position of the first repetition of length mu
	// The hare and tortoise move at the same speeds
	int mu = 0; // first index that starts the circle
	hare = tortoise;
	tortoise = x0;
	const int MAX_STEPS = 1 << 24; // = 16M
	while (tortoise != hare) {
		tortoise = f(tortoise);
		hare = f(hare);
		mu++;
		if (mu > MAX_STEPS) break;  // extra safety; not really needed
	}

	// Find the length of the shortest cycle starting from x_mu
	// The hare moves while the tortoise stays still
	int lambda = 1; //circle length
	hare = f(tortoise);
	while (tortoise != hare) {
		hare = f(hare);
		lambda++;
		if (lambda > MAX_STEPS) break;  // extra safety; not really needed
	}
	vlog_printf (VLOG_ERROR, "circle first index (mu) = %d, circle length (lambda) = %d", mu, lambda);
}

void buffer_pool::buffersPanic()
{
	if (isCircle(m_p_head))
	{
		__log_info_err("Circle was found in buffer_pool");

		// print mu & lambda of circle
		Floyd_LogCircleInfo(m_p_head);
	}
	else
	{
		__log_info_info("no circle was found in buffer_pool");
	}

	// log backtrace
	const int MAX_BACKTRACE = 25;
	char **symbols;
	void *addresses[MAX_BACKTRACE];
	int count = backtrace(addresses, MAX_BACKTRACE);
	symbols = backtrace_symbols(addresses, count);
	for (int i = 0; i < count; ++i) {
		vlog_printf(VLOG_ERROR, "   %2d  %s\n", i, symbols[i]);
	}

	__log_info_panic("m_n_buffers(%lu) > m_n_buffers_created(%lu)", m_n_buffers, m_n_buffers_created);
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

inline void buffer_pool::put_buffer_helper(mem_buf_desc_t *buff)
{
#if _VMA_LIST_DEBUG
	if (buff->node.is_list_member()) {
		vlog_printf(VLOG_WARNING, "buffer_pool::put_buffer_helper - buff is already a member in a list (list id = %s)\n", buff->node.list_id());
	}
#endif
	buff->p_next_desc = m_p_head;
	free_lwip_pbuf(&buff->lwip_pbuf);
	m_p_head = buff;
	m_n_buffers++;
}

int buffer_pool::put_buffers(mem_buf_desc_t *buff_list)
{
	int count = 0;
	mem_buf_desc_t *next;
	__log_info_funcall("returning list, present %lu, created %lu", m_n_buffers, m_n_buffers_created);
	while (buff_list) {
		next = buff_list->p_next_desc;
		put_buffer_helper(buff_list);
		buff_list = next;
		count++;

		if (unlikely(m_n_buffers > m_n_buffers_created)) {
			buffersPanic();
		}
	}
	return count;
}

void buffer_pool::put_buffers(descq_t *buffers, size_t count)
{
	mem_buf_desc_t *buff_list, *next;
	__log_info_funcall("returning %lu, present %lu, created %lu", count, m_n_buffers, m_n_buffers_created);
	while (count > 0 && !buffers->empty()) {
		buff_list = buffers->back();
		buffers->pop_back();
		while (buff_list) {
			next = buff_list->p_next_desc;
			put_buffer_helper(buff_list);
			buff_list = next;

			if (unlikely(m_n_buffers > m_n_buffers_created)) {
				buffersPanic();
			}
		}
		--count;
	}
}

uint32_t buffer_pool::get_lkey_by_ctx(const ib_ctx_handler* ctx)
{
	return m_p_mr_arr[ctx->get_dev_index()]->lkey;
}

size_t buffer_pool::get_free_count()
{
	return m_n_buffers;
}

