/*
 * allocator.cpp
 *
 *  Created on: Feb 22, 2017
 *      Author: rafiw
 */

#include <dev/allocator.h>

#define MODULE_NAME	"allocator"

vma_allocator::vma_allocator() : m_shmid(-1), m_data_block(NULL),
#ifdef VMA_IBV_ACCESS_ALLOCATE_MR
		m_is_contig_alloc(true)
#else
		m_is_contig_alloc(false)
#endif
	{
}

void* vma_allocator::allocAndRegMr(size_t size, ib_ctx_handler *p_ib_ctx_h) {
	uint64_t access = VMA_IBV_ACCESS_LOCAL_WRITE;
	uint64_t access_mr = VMA_IBV_ACCESS_LOCAL_WRITE |
			     VMA_IBV_ACCESS_ALLOCATE_MR;
	size += MCE_ALIGNMENT;
	switch (safe_mce_sys().mem_alloc_type) {
	case ALLOC_TYPE_HUGEPAGES:
		if (!hugetlb_alloc(size)) {
			__log_info_dbg("Failed allocating huge pages, "
				       "falling back to contiguous pages");
		}
		else {
			__log_info_dbg("Huge pages allocation passed successfully");
			if (!register_memory(size, p_ib_ctx_h, access)) {
				__log_info_dbg("failed registering huge pages data memory block");
				throw_vma_exception("failed registering huge pages data memory"
						" block");
			}
			break;
		}
	// fallthrough
	case ALLOC_TYPE_CONTIG:
		if (m_is_contig_alloc) {
			if (!register_memory(size, p_ib_ctx_h, access_mr)) {
				__log_info_dbg("Failed allocating contiguous pages");
				m_is_contig_alloc = false;
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
		m_data_block = malloc(size);
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_data_block == NULL) {
			__log_info_dbg("failed allocating data memory block "
					"(size=%d Kbytes) (errno=%d %m)", size/1024, errno);
			throw_vma_exception("failed allocating data memory block");
		}
		BULLSEYE_EXCLUDE_BLOCK_END
		if (!register_memory(size, p_ib_ctx_h, access)) {
			__log_info_dbg("failed registering data memory block");
			throw_vma_exception("failed registering data memory block");
		}
		break;
	}
	return m_data_block;
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
		vlog_printf(VLOG_INFO, "   *      \"cat /proc/meminfo |  grep -i HugePage\"              \n");
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
	if (p_ib_ctx_h) {
		ibv_mr *mr = p_ib_ctx_h->mem_reg(m_data_block, size, access);
		if (mr == NULL){
			if (m_data_block) {
				__log_info_warn("Failed registering memory, This might happen "
						"due to low MTT entries. Please refer to README.txt "
						"for more info");
				__log_info_dbg("Failed registering memory block with device "
						"(ptr=%p size=%ld%s) (errno=%d %m)", m_data_block,
						size, errno);
				throw_vma_exception("Failed registering memory block");
			} else {
				__log_info_warn("Failed allocating or registering memory in "
						"contiguous mode. Please refer to README.txt for more "
						"info");
				return false;
			}
		}
		m_mrs.push_back(mr);
		if (!m_data_block) { // contig pages mode
			m_data_block = mr->addr;
		}
	} else {
		size_t num_devices = g_p_ib_ctx_handler_collection->get_num_devices();
		ibv_mr *mrs[num_devices];

		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_p_ib_ctx_handler_collection->mem_reg_on_all_devices(m_data_block,
				size, mrs, num_devices, access) != num_devices) {
			if (m_data_block) {
				__log_info_warn("Failed registering memory, This might happen "
						"due to low MTT entries. Please refer to README.txt "
						"for more info");
				__log_info_dbg("Failed registering memory block with device "
						"(ptr=%p size=%ld%s) (errno=%d %m)",
						m_data_block, size, errno);
				throw_vma_exception("Failed registering memory");
			} else {
				__log_info_warn("Failed allocating or registering memory in "
						"contiguous mode. Please refer to README.txt for more "
						"info");
				return false;
			}
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		if (!m_data_block) { // contig pages mode
			m_data_block = mrs[0]->addr;
			if (!m_data_block) {
				__log_info_dbg("Failed registering memory, check that OFED is "
						"loaded successfully");
				throw_vma_exception("Failed registering memory");
			}
		}
		for (size_t i = 0; i < num_devices; ++i) {
			m_mrs.push_back(mrs[i]);
		}
	}
	return true;
}

uint32_t vma_allocator::find_lkey_by_ib_ctx(ib_ctx_handler *p_ib_ctx_h)
{
	uint32_t lkey = 0;
	if (likely(p_ib_ctx_h)) {
		std::deque<ibv_mr*>::iterator iter;
		for (iter = m_mrs.begin(); iter != m_mrs.end(); ++iter) {
			ibv_mr *mr = *iter;
			if (mr->context->device == p_ib_ctx_h->get_ibv_device()) {
				lkey = mr->lkey;
				break;
			}
		}
	}
	return lkey;
}

vma_allocator::~vma_allocator() {
	// Unregister memory
	std::deque<ibv_mr*>::iterator iter_mrs;
	for (iter_mrs = m_mrs.begin(); iter_mrs != m_mrs.end(); ++iter_mrs) {

		ibv_mr *mr = *iter_mrs;
		ib_ctx_handler* p_ib_ctx_handler =
				g_p_ib_ctx_handler_collection->get_ib_ctx(mr->context);
		if (!p_ib_ctx_handler->is_removed()) {
			IF_VERBS_FAILURE(ibv_dereg_mr(mr)) {
				__log_info_err("failed de-registering a memory region "
						"(errno=%d %m)", errno);
			} ENDIF_VERBS_FAILURE;
		}
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
}

