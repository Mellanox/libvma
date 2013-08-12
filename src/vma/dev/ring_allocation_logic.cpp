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


#include "vma/dev/ring_allocation_logic.h"


#define MODULE_NAME 		"ral"

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "%s:%d:%s() "
#undef	__INFO__
#define __INFO__		m_tostr.c_str()

#define ral_logpanic		__log_info_panic
#define ral_logerr		__log_info_err
#define ral_logwarn		__log_info_warn
#define ral_loginfo		__log_info_info
#define ral_logdbg		__log_info_dbg
#define ral_logfunc		__log_info_func
#define ral_logfuncall		__log_info_funcall


ring_allocation_logic::ring_allocation_logic(ring_logic_t ring_allocation_logic, int ring_migration_ratio, int fd):
	m_tostr("base"), m_ring_allocation_logic(ring_allocation_logic), m_ring_migration_ratio(ring_migration_ratio),
	m_fd(fd), m_migration_try_count(ring_migration_ratio), m_migration_candidate(0)
{
	m_res_key = get_res_key_by_logic();
}

resource_allocation_key ring_allocation_logic::get_res_key_by_logic()
{
	resource_allocation_key key = DEFAULT_RING_KEY;

	switch (m_ring_allocation_logic) {
	case RING_LOGIC_PER_INTERFACE:
		key = 0;
		break;
	case RING_LOGIC_PER_SOCKET:
		key = m_fd;
		break;
	case RING_LOGIC_PER_THREAD:
		key = pthread_self();
		break;
	case RING_LOGIC_PER_CORE:
	case RING_LOGIC_PER_CORE_ATTACH_THREADS:
		key = sched_getcpu();
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		//not suppose to get here
		ral_logdbg("non-valid ring logic = %d", m_ring_allocation_logic);
		break;
	BULLSEYE_EXCLUDE_BLOCK_END
	}

	return key;
}

resource_allocation_key ring_allocation_logic::create_new_key(int suggested_cpu /* = NO_CPU */)
{
	if (m_ring_allocation_logic == RING_LOGIC_PER_CORE_ATTACH_THREADS) {
		pthread_t tid = pthread_self();
		int cpu = g_cpu_manager.reserve_cpu_for_thread(tid, suggested_cpu);
		if (cpu >= 0) {
			m_res_key = cpu;
			return cpu;
		}
	}

	m_res_key = get_res_key_by_logic();
	return m_res_key;
}

/*
 * return true if ring migration is recommended for this thread.
 */
bool ring_allocation_logic::should_migrate_ring()
{
	if (m_ring_allocation_logic < RING_LOGIC_PER_THREAD) {
		return false;
	}

	if (m_ring_migration_ratio < 0) {
		return false;
	}

	ral_logfuncall("currently accessed from thread=%lu, cpu=%d", pthread_self(), sched_getcpu());

	int count_max = m_ring_migration_ratio;
	if (m_migration_candidate) {
		count_max = CANDIDATE_STABILITY_ROUNDS;
		resource_allocation_key current_id = get_res_key_by_logic();
		if (m_migration_candidate != current_id) {
			m_migration_candidate = 0;
			m_migration_try_count = 0;
			return false;
		}
	}

	if (m_migration_try_count < count_max) {
		m_migration_try_count++;
		return false;
	} else {
		m_migration_try_count = 0;
	}

	if (!m_migration_candidate) {
		resource_allocation_key current_id = get_res_key_by_logic();
		if (m_res_key == current_id || g_n_internal_thread_id == current_id) {
			return false;
		}
		m_migration_candidate = current_id;
		return false;
	}

	ral_logdbg("migrating from ring of id=%lu to ring of id=%lu", m_res_key, m_migration_candidate);
	m_migration_candidate = 0;

	return true;
}


cpu_manager g_cpu_manager;
__thread int g_n_thread_cpu_core = NO_CPU;

cpu_manager::cpu_manager()
{
	memset(m_cpu_thread_count, 0, sizeof(m_cpu_thread_count));
}

int cpu_manager::reserve_cpu_for_thread(pthread_t tid, int suggested_cpu /* = NO_CPU */)
{
	lock();
	int cpu = g_n_thread_cpu_core;
	if (cpu != NO_CPU) { //already reserved
		unlock();
		return cpu;
	}

	cpu_set_t* cpu_set = NULL;
	cpu_set = CPU_ALLOC(MAX_CPU);
	if (!cpu_set) {
		unlock();
		__log_err("failed to allocate cpu set");
		return -1;
	}
	size_t cpu_set_size = CPU_ALLOC_SIZE(MAX_CPU);
	CPU_ZERO_S(cpu_set_size, cpu_set);
	if (pthread_getaffinity_np(tid, cpu_set_size, cpu_set)) {
		unlock();
		CPU_FREE(cpu_set);
		__log_err("pthread_getaffinity_np failed for tid=%lu (errno=%d %m)", tid, errno);
		return -1;
	}

	if (CPU_COUNT_S(cpu_set_size, cpu_set) == 0) {
		unlock();
		__log_err("no cpu available for tid=%lu", tid);
		CPU_FREE(cpu_set);
		return -1;
	}

	if (CPU_COUNT_S(cpu_set_size, cpu_set) == 1) { //already attached
		for (cpu = 0; cpu < MAX_CPU && !CPU_ISSET_S(cpu, cpu_set_size, cpu_set); cpu++) {}
	} else { //need to choose one cpu to attach to
		int min_cpu_count = -1;
		for (int i = 0; i < MAX_CPU; i++) {
			if (!CPU_ISSET_S(i, cpu_set_size, cpu_set)) continue;
			if (min_cpu_count < 0 || m_cpu_thread_count[i] < min_cpu_count) {
				min_cpu_count = m_cpu_thread_count[i];
				cpu = i;
			}
		}
		if (suggested_cpu >= 0
			&& CPU_ISSET_S(suggested_cpu, cpu_set_size, cpu_set)
			&& m_cpu_thread_count[suggested_cpu] <= min_cpu_count + 1 ) {
			cpu = suggested_cpu;
		}
		CPU_ZERO_S(cpu_set_size, cpu_set);
		CPU_SET_S(cpu, cpu_set_size, cpu_set);
		__log_dbg("attach tid=%lu running on cpu=%d to cpu=%d", tid, sched_getcpu(), cpu);
		if (pthread_setaffinity_np(tid, cpu_set_size, cpu_set)) {
			unlock();
			CPU_FREE(cpu_set);
			__log_err("pthread_setaffinity_np failed for tid=%lu to cpu=%d (errno=%d %m)", tid, cpu, errno);
			return -1;
		}
	}

	CPU_FREE(cpu_set);
	g_n_thread_cpu_core = cpu;
	m_cpu_thread_count[cpu]++;
	unlock();
	return cpu;
}
