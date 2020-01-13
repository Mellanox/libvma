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

#include <dev/allocator.h>
#include <sys/shm.h>
#include <sys/mman.h>

#define MODULE_NAME	"allocator"

vma_allocator::vma_allocator()
{
	__log_info_dbg("");

	m_shmid = -1;
	m_length = 0;
	m_data_block = NULL;
	m_mem_alloc_type = safe_mce_sys().mem_alloc_type;

	__log_info_dbg("Done");
}

vma_allocator::~vma_allocator()
{
	__log_info_dbg("");

	// Unregister memory
	deregister_memory();
	if (!m_data_block) {
		__log_info_dbg("m_data_block is null");
		return;
	}
	switch (m_mem_alloc_type) {
		case ALLOC_TYPE_EXTERNAL:
			// not allocated by us
		case ALLOC_TYPE_CONTIG:
			// freed as part of deregister_memory
			break;
		case ALLOC_TYPE_HUGEPAGES:
			if (m_shmid > 0) {
				if (shmdt(m_data_block) != 0) {
					__log_info_err("shmem detach failure %m");
				}
			} else { // used mmap
				if (munmap(m_data_block, m_length)) {
					__log_info_err("failed freeing memory "
							"with munmap errno "
							"%d", errno);
				}
			}
			break;
		case ALLOC_TYPE_ANON:
			free(m_data_block);
			break;
		default:
			__log_info_err("Unknown memory allocation type %d",
					m_mem_alloc_type);
			break;
	}
	__log_info_dbg("Done");
}

void* vma_allocator::alloc_and_reg_mr(size_t size, ib_ctx_handler *p_ib_ctx_h, void *ptr /* NULL */)
{
	uint64_t access = VMA_IBV_ACCESS_LOCAL_WRITE;

	if (ptr) {
		m_mem_alloc_type = ALLOC_TYPE_EXTERNAL;
	}
	switch (m_mem_alloc_type) {
	case ALLOC_TYPE_EXTERNAL:
		m_data_block = ptr;
		register_memory(size, p_ib_ctx_h, access);
		break;
	case ALLOC_TYPE_HUGEPAGES:
		if (!hugetlb_alloc(size)) {
			__log_info_dbg("Failed allocating huge pages, "
				       "falling back to another memory allocation method");
		}
		else {
			__log_info_dbg("Huge pages allocation passed successfully");
			m_mem_alloc_type = ALLOC_TYPE_HUGEPAGES;
			register_memory(size, p_ib_ctx_h, access);
			break;
		}
	// fallthrough
	case ALLOC_TYPE_CONTIG:
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
		if (mce_sys_var::HYPER_MSHV != safe_mce_sys().hypervisor) {
			register_memory(size, p_ib_ctx_h, (access | VMA_IBV_ACCESS_ALLOCATE_MR));
			__log_info_dbg("Contiguous pages allocation passed successfully");
			m_mem_alloc_type = ALLOC_TYPE_CONTIG;
			break;
		}
#endif
	// fallthrough
	case ALLOC_TYPE_ANON:
	default:
		__log_info_dbg("allocating memory using malloc()");
		align_simple_malloc(size); // if fail will raise exception
		m_mem_alloc_type = ALLOC_TYPE_ANON;
		register_memory(size, p_ib_ctx_h, access);
		break;
	}
	__log_info_dbg("allocated memory using type: %d at %p, size %zd",
			m_mem_alloc_type, m_data_block, size);

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
	const size_t hugepagemask = 4 * 1024 * 1024 - 1;

	m_length = (sz_bytes + hugepagemask) & (~hugepagemask);

	if (hugetlb_mmap_alloc()) {
		return true;
	}
	if (hugetlb_sysv_alloc()) {
		return true;
	}

	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "**************************************************************\n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "* NO IMMEDIATE ACTION NEEDED!                                 \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "* Not enough hugepage resources for VMA memory allocation.    \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "* VMA will continue working with regular memory allocation.   \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   * Optional:                                                   \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *   1. Switch to a different memory allocation type           \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *      (%s!= %d)                                              \n",
			SYS_VAR_MEM_ALLOC_TYPE, ALLOC_TYPE_HUGEPAGES);
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *   2. Restart process after increasing the number of         \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *      hugepages resources in the system:                     \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *      \"echo 1000000000 > /proc/sys/kernel/shmmax\"          \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_INFO, "   *      \"echo 800 > /proc/sys/vm/nr_hugepages\"               \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "* Please refer to the memory allocation section in the VMA's  \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "* User Manual for more information                            \n");
	VLOG_PRINTF_ONCE_THEN_DEBUG(VLOG_WARNING, "**************************************************************\n");
	return false;
}

bool vma_allocator::hugetlb_mmap_alloc()
{
#ifdef MAP_HUGETLB
	__log_info_dbg("Allocating %zd bytes in huge tlb using mmap", m_length);

	m_data_block = mmap(NULL, m_length,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS |
			MAP_POPULATE | MAP_HUGETLB, -1, 0);
	if (m_data_block == MAP_FAILED) {
		__log_info_dbg("failed allocating %zd using mmap %d", m_length,
				errno);
		m_data_block = NULL;
		return false;
	}
	return true;
#else
	return false;
#endif
}


bool vma_allocator::hugetlb_sysv_alloc()
{
	__log_info_dbg("Allocating %zd bytes in huge tlb with shmget", m_length);

	// allocate memory
	m_shmid = shmget(IPC_PRIVATE, m_length,
			SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	if (m_shmid < 0) {
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
	int rc = mlock(m_data_block, m_length);
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

void vma_allocator::align_simple_malloc(size_t sz_bytes)
{
	int ret = 0;
	long page_size = sysconf(_SC_PAGESIZE);

	if (page_size > 0) {
		m_length = (sz_bytes + page_size - 1) & (~page_size - 1);
		ret = posix_memalign(&m_data_block, page_size, m_length);
		if (!ret) {
			__log_info_dbg("allocated %zd aligned memory at %p",
					m_length, m_data_block);
			return;
		}
	}
	__log_info_dbg("failed allocating memory with posix_memalign size %zd "
			"returned %d (errno=%d %m) ", m_length, ret, errno);

	m_length = sz_bytes;
	m_data_block = malloc(sz_bytes);

	if (m_data_block == NULL) {
		__log_info_dbg("failed allocating data memory block "
				"(size=%d bytes) (errno=%d %m)", sz_bytes, errno);
		throw_vma_exception("failed allocating data memory block");
	}
	__log_info_dbg("allocated memory using malloc()");
}

void vma_allocator::register_memory(size_t size, ib_ctx_handler *p_ib_ctx_h,
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
	}

	/* Possible cases:
	 * 1. no IB device: it is not possible to register memory
	 *  - return w/o error
	 * 2. p_ib_ctx_h is null: try to register on all IB devices
	 *  - fatal return if at least one IB device can not register memory
	 *  - return w/o error in case no issue is observed
	 * 3. p_ib_ctx is defined: try to register on specific device
	 *  - fatal return if device is found and registration fails
	 *  - return w/o error in case no issue is observed or device is not found
	 */
	if (failed) {
		__log_info_warn("Failed registering memory, This might happen "
				"due to low MTT entries. Please refer to README.txt "
				"for more info");
		if (m_data_block) {
			__log_info_dbg("Failed registering memory block with device "
					"(ptr=%p size=%ld%s) (errno=%d %m)",
					m_data_block, size, errno);
		}
		throw_vma_exception("Failed registering memory");
	}

	return;
}

void vma_allocator::deregister_memory()
{
	ib_ctx_handler *p_ib_ctx_h = NULL;
	ib_context_map_t *ib_ctx_map = NULL;
	uint32_t lkey = (uint32_t)(-1);

	ib_ctx_map = g_p_ib_ctx_handler_collection->get_ib_cxt_list();
	if (ib_ctx_map) {
		ib_context_map_t::iterator iter;

		for (iter = ib_ctx_map->begin(); iter != ib_ctx_map->end(); iter++) {
			p_ib_ctx_h = iter->second;
			lkey = find_lkey_by_ib_ctx(p_ib_ctx_h);
			if (lkey != (uint32_t)(-1)) {
				p_ib_ctx_h->mem_dereg(lkey);
				m_lkey_map_ib_ctx.erase(p_ib_ctx_h);
			}
		}
	}
	m_lkey_map_ib_ctx.clear();
}
