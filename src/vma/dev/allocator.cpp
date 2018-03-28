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

#include <dev/allocator.h>
#include <sys/shm.h>
#include <sys/mman.h>

#define MODULE_NAME	"allocator"

vma_allocator::vma_allocator()
{
	__log_info_dbg("");

	m_shmid = -1;
	m_data_block = NULL;
	m_non_contig_access_mr = VMA_IBV_ACCESS_LOCAL_WRITE;
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
	m_is_contig_alloc = true;
	m_contig_access_mr = VMA_IBV_ACCESS_LOCAL_WRITE |
			     VMA_IBV_ACCESS_ALLOCATE_MR;
#else
	m_is_contig_alloc = false;
	m_contig_access_mr = 0;
#endif

	__log_info_dbg("Done");
}

vma_allocator::~vma_allocator()
{
	__log_info_dbg("");

	// Unregister memory
	lkey_map_ib_ctx_map_t::iterator iter;
	while ((iter = m_lkey_map_ib_ctx.begin()) != m_lkey_map_ib_ctx.end()) {
		ib_ctx_handler* p_ib_ctx_h = iter->first;
		p_ib_ctx_h->mem_dereg(iter->second);
		m_lkey_map_ib_ctx.erase(iter);
	}
	// Release memory
	if (m_shmid >= 0) { // Huge pages mode
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_data_block && (shmdt(m_data_block) != 0)) {
			__log_info_err("shmem detach failure %m");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	// in contig mode 'ibv_dereg_mr' will free all allocates resources
	} else if (!m_is_contig_alloc) {
		if (m_data_block)
			free(m_data_block);
	}

	__log_info_dbg("Done");
}

void* vma_allocator::alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h)
{
	switch (safe_mce_sys().mem_alloc_type) {
	case ALLOC_TYPE_HUGEPAGES:
		if (!hugetlb_alloc(size)) {
			__log_info_dbg("Failed allocating huge pages, "
				       "falling back to contiguous pages");
		}
		else {
			__log_info_dbg("Huge pages allocation passed successfully");
			if (!register_memory(size, p_ib_ctx_h, m_non_contig_access_mr)) {
				__log_info_dbg("failed registering huge pages data memory block");
				throw_vma_exception("failed registering huge pages data memory"
						" block");
			}
			break;
		}
	// fallthrough
	case ALLOC_TYPE_CONTIG:
		if (m_is_contig_alloc) {
			if (!register_memory(size, p_ib_ctx_h, m_contig_access_mr)) {
				__log_info_dbg("Failed allocating contiguous pages");
			}
			else {
				__log_info_dbg("Contiguous pages allocation passed successfully");
				break;
			}
		}
	// fallthrough
	case ALLOC_TYPE_ANON:
	default:
		__log_info_dbg("allocating memory using malloc()");
		m_is_contig_alloc = false;
		m_data_block = malloc(size);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_data_block == NULL) {
			__log_info_dbg("failed allocating data memory block "
					"(size=%d Kbytes) (errno=%d %m)", size/1024, errno);
			throw_vma_exception("failed allocating data memory block");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!register_memory(size, p_ib_ctx_h, m_non_contig_access_mr)) {
			__log_info_dbg("failed registering data memory block");
			throw_vma_exception("failed registering data memory block");
		}
		break;
	}
	__log_info_dbg("allocated memory at %p, size %zd", m_data_block, size);
	return m_data_block;
}

ibv_mr* vma_allocator::find_ibv_mr_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
	lkey_map_ib_ctx_map_t::const_iterator iter = m_lkey_map_ib_ctx.find(p_ib_ctx_h);
	if (iter != m_lkey_map_ib_ctx.end()) {
		return p_ib_ctx_h->get_mem_reg(iter->second);
	}

	return NULL;
}

uint32_t vma_allocator::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
	lkey_map_ib_ctx_map_t::const_iterator iter = m_lkey_map_ib_ctx.find(p_ib_ctx_h);
	if (iter != m_lkey_map_ib_ctx.end()) {
		return iter->second;
	}

	return (uint32_t)(-1);
}

bool vma_allocator::hugetlb_alloc(size_t sz_bytes)
{
	size_t hugepagemask = 4 * 1024 * 1024 - 1;
	sz_bytes = (sz_bytes + hugepagemask) & (~hugepagemask);

	__log_info_dbg("Allocating %zd bytes in huge tlb", sz_bytes);

	// allocate memory
	m_shmid = shmget(IPC_PRIVATE, sz_bytes,
			SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	if (m_shmid < 0) {

		// Stop trying to use HugePage if failed even once
		safe_mce_sys().mem_alloc_type = ALLOC_TYPE_CONTIG;

		vlog_printf(VLOG_WARNING, "**************************************************************\n");
		vlog_printf(VLOG_WARNING, "* NO IMMEDIATE ACTION NEEDED!                                 \n");
		vlog_printf(VLOG_WARNING, "* Not enough hugepage resources for VMA memory allocation.    \n");
		vlog_printf(VLOG_WARNING, "* VMA will continue working with regular memory allocation.   \n");
		vlog_printf(VLOG_INFO, "   * Optional:                                                   \n");
		vlog_printf(VLOG_INFO, "   *   1. Switch to a different memory allocation type           \n");
		vlog_printf(VLOG_INFO, "   *      (%s!= %d)                                              \n",
				SYS_VAR_MEM_ALLOC_TYPE, ALLOC_TYPE_HUGEPAGES);
		vlog_printf(VLOG_INFO, "   *   2. Restart process after increasing the number of         \n");
		vlog_printf(VLOG_INFO, "   *      hugepages resources in the system:                     \n");
		vlog_printf(VLOG_INFO, "   *      \"echo 1000000000 > /proc/sys/kernel/shmmax\"          \n");
		vlog_printf(VLOG_INFO, "   *      \"echo 800 > /proc/sys/vm/nr_hugepages\"               \n");
		vlog_printf(VLOG_WARNING, "* Please refer to the memory allocation section in the VMA's  \n");
		vlog_printf(VLOG_WARNING, "* User Manual for more information                            \n");
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
		__log_info_warn("Shared memory contrl mark 'to be destroyed' failed "
				"(errno=%d %m)", errno);
	}

	// We want to determine now that we can lock it. Note: it was claimed
	// that without actual mlock, linux might be buggy on this with huge-pages
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

bool vma_allocator::register_memory(size_t size, ib_ctx_handler *p_ib_ctx_h,
				    uint64_t access)
{
	ib_context_map_t *ib_ctx_map = NULL;
	ib_ctx_handler *p_ib_ctx_h_ref = p_ib_ctx_h;
	uint32_t lkey = (uint32_t)(-1);
	bool failed = false;

	ib_ctx_map = g_p_ib_ctx_handler_collection->get_ib_cxt_list();
	if (ib_ctx_map) {
		ib_context_map_t::iterator iter;

		for (iter = ib_ctx_map->begin(); iter != ib_ctx_map->end(); iter++) {
			p_ib_ctx_h = iter->second;
			if (p_ib_ctx_h_ref && p_ib_ctx_h != p_ib_ctx_h_ref) {
				continue;
			}
			lkey = p_ib_ctx_h->mem_reg(m_data_block, size, access);
			if (lkey == (uint32_t)(-1)) {
				__log_info_warn("Failure during memory registration on dev: %s addr=%p length=%d",
						p_ib_ctx_h->get_ibname(), m_data_block, size);
				failed = true;
				break;
			} else {
				m_lkey_map_ib_ctx[p_ib_ctx_h] = lkey;
				if (NULL == m_data_block) {
					m_data_block = p_ib_ctx_h->get_mem_reg(lkey)->addr;
				}
				errno = 0; //ibv_reg_mr() set errno=12 despite successful returning
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
				if ((access & VMA_IBV_ACCESS_ALLOCATE_MR) != 0) { // contig pages mode
					// When using 'IBV_ACCESS_ALLOCATE_MR', ibv_reg_mr will return a pointer that its 'addr' field will hold the address of the allocated memory.
					// Second registration and above is done using 'IBV_ACCESS_LOCAL_WRITE' and the 'addr' we received from the first registration.
					access &= ~VMA_IBV_ACCESS_ALLOCATE_MR;
				}
#endif
				__log_info_dbg("Registered memory on dev: %s addr=%p length=%d",
						p_ib_ctx_h->get_ibname(), m_data_block, size);
			}
			if (p_ib_ctx_h == p_ib_ctx_h_ref) {
				break;
			}
		}
	} else {
		failed = true;
	}

	if (failed) {
		if (m_data_block) {
			__log_info_warn("Failed registering memory, This might happen "
					"due to low MTT entries. Please refer to README.txt "
					"for more info");
			__log_info_dbg("Failed registering memory block with device "
					"(ptr=%p size=%ld%s) (errno=%d %m)",
					m_data_block, size, errno);
			throw_vma_exception("Failed registering memory");
		}
		__log_info_warn("Failed allocating or registering memory in "
				"contiguous mode. Please refer to README.txt for more "
				"info");
		return false;
	}

	__log_info_dbg("Registered memory on %d ib_ctx", m_lkey_map_ib_ctx.size());

	return true;
}
