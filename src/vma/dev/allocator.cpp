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

#include <dev/allocator.h>
#include <sys/shm.h>
#include <sys/mman.h>

#define MODULE_NAME	"allocator"

vma_allocator::vma_allocator() :
		m_mr_list(NULL),
		m_mr_list_len(0),
		m_shmid(-1),
		m_data_block(NULL) {
	m_non_contig_access_mr = VMA_IBV_ACCESS_LOCAL_WRITE;
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
	m_is_contig_alloc = true;
	m_contig_access_mr = VMA_IBV_ACCESS_LOCAL_WRITE |
			     VMA_IBV_ACCESS_ALLOCATE_MR;
#else
	m_is_contig_alloc = false;
	m_contig_access_mr = 0;
#endif

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

uint32_t vma_allocator::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h) const
{
	ibv_device* dev = p_ib_ctx_h->get_ibv_device();
	for (size_t i = 0; i < m_mr_list_len; ++i) {
		if (dev == m_mr_list[i]->context->device) {
			return m_mr_list[i]->lkey;
		}
	}
	return 0;
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
	bool failed = false;
	if (p_ib_ctx_h) {
		m_mr_list = new ibv_mr*[1];
		m_mr_list[0] = p_ib_ctx_h->mem_reg(m_data_block, size, access);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_mr_list[0] == NULL) {
			failed = true;
		} else {
			m_mr_list_len = 1;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		m_mr_list_len = 1;
	} else {
		size_t dev_num = g_p_ib_ctx_handler_collection->get_num_devices();
		m_mr_list = new ibv_mr*[dev_num];

		BULLSEYE_EXCLUDE_BLOCK_START
		if ((m_mr_list_len = g_p_ib_ctx_handler_collection->mem_reg_on_all_devices(m_data_block,
				size, m_mr_list, dev_num, access)) != dev_num) {
			failed = true;
		}
		BULLSEYE_EXCLUDE_BLOCK_END
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
	if (!m_data_block) { // contig pages mode
		m_data_block = m_mr_list[0]->addr;
		if (!m_data_block) {
			__log_info_dbg("Failed registering memory, check that OFED is "
					"loaded successfully");
			throw_vma_exception("Failed registering memory");
		}
	}
	return true;
}

vma_allocator::~vma_allocator() {
	// Unregister memory
	for (size_t i = 0; i < m_mr_list_len; ++i) {
		ib_ctx_handler* p_ib_ctx_handler =
				g_p_ib_ctx_handler_collection->get_ib_ctx(m_mr_list[i]->context);
		p_ib_ctx_handler->mem_dereg(m_mr_list[i]);
	}
	delete[] m_mr_list;
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
}

