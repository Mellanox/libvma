/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#include <dev/ring_profile.h>
#include "vma/dev/ring_allocation_logic.h"


#define MODULE_NAME 		"ral"

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "%s:%d:%s() "
#undef	__INFO__
#define __INFO__		to_str()

#define ral_logpanic		__log_info_panic
#define ral_logerr		__log_info_err
#define ral_logwarn		__log_info_warn
#define ral_loginfo		__log_info_info
#define ral_logdbg		__log_info_dbg
#define ral_logfunc		__log_info_func
#define ral_logfuncall		__log_info_funcall

ring_allocation_logic::ring_allocation_logic(): m_owner(NULL),
						m_ring_migration_ratio(0),
						m_source(-1),
						m_migration_try_count(0),
						m_migration_candidate(0),
						m_active(true),
						m_res_key()
{
	m_str[0] = '\0';
	m_type = "";
}

ring_allocation_logic::ring_allocation_logic(ring_logic_t allocation_logic,
					     int ring_migration_ratio, source_t source,
					     resource_allocation_key &ring_profile):
	m_owner(NULL), m_ring_migration_ratio(ring_migration_ratio),
	m_source(source), m_migration_try_count(ring_migration_ratio)
{
	if (ring_profile.get_ring_alloc_logic() == RING_LOGIC_PER_INTERFACE &&
	    ring_profile.get_ring_profile_key() < START_RING_INDEX) {
		ring_profile.set_ring_alloc_logic(allocation_logic);
	}
	m_res_key = resource_allocation_key(ring_profile);
	m_migration_candidate = 0;
	m_res_key.set_user_id_key(calc_res_key_by_logic());

	m_str[0] = '\0';
	m_type = "";

	m_active = true;
}

/**
 *
 * @return the key that is part of a unique id in rings map
 */
uint64_t ring_allocation_logic::calc_res_key_by_logic()
{
	uint64_t res_key = 0;
	switch (m_res_key.get_ring_alloc_logic()) {
	case RING_LOGIC_PER_INTERFACE:
		res_key = 0;
		if (safe_mce_sys().tcp_ctl_thread > CTL_THREAD_DISABLE)
			res_key = 1;
		break;
	case RING_LOGIC_PER_IP:
		res_key = m_source.m_ip;
		break;
	case RING_LOGIC_PER_SOCKET:
		res_key = m_source.m_fd;
		break;
	case RING_LOGIC_PER_USER_ID:
		res_key = m_res_key.get_user_id_key();
		break;
	case RING_LOGIC_PER_THREAD:
		res_key = pthread_self();
		break;
	case RING_LOGIC_PER_CORE:
	case RING_LOGIC_PER_CORE_ATTACH_THREADS:
		res_key = sched_getcpu();
		break;
	BULLSEYE_EXCLUDE_BLOCK_START
	default:
		//not suppose to get here
		ral_logdbg("non-valid ring logic = %d", m_res_key.get_ring_alloc_logic());
		break;
	BULLSEYE_EXCLUDE_BLOCK_END
	}
	return res_key;
}

resource_allocation_key* ring_allocation_logic::create_new_key(in_addr_t addr, int suggested_cpu /* = NO_CPU */)
{
	if (m_res_key.get_ring_alloc_logic() == RING_LOGIC_PER_CORE_ATTACH_THREADS) {
		pthread_t tid = pthread_self();
		int cpu = g_cpu_manager.reserve_cpu_for_thread(tid, suggested_cpu);
		if (cpu >= 0) {
			m_res_key.set_user_id_key(cpu);
			return &m_res_key;
		}
	}

	if (m_res_key.get_ring_alloc_logic() == RING_LOGIC_PER_IP) {
		m_source.m_ip = addr;
	}

	m_res_key.set_user_id_key(calc_res_key_by_logic());
	return &m_res_key;
}

/*
 * return true if ring migration is recommended.
 */
bool ring_allocation_logic::should_migrate_ring()
{
	ral_logfuncall("currently accessed from thread=%lu, cpu=%d", pthread_self(), sched_getcpu());

	if (false == m_active) {
		return false;
	}

	int count_max = m_ring_migration_ratio;
	if (m_migration_candidate) {
		count_max = CANDIDATE_STABILITY_ROUNDS;
		uint64_t new_id = calc_res_key_by_logic();
		if (m_migration_candidate != new_id) {
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
		// save current used allocation key
		// no need to save profile, and allocation logic
		uint64_t curr_id = m_res_key.get_user_id_key();
		// calc new key
		uint64_t new_id = calc_res_key_by_logic();
		if (new_id == curr_id || g_n_internal_thread_id == curr_id) {
			return false;
		}
		m_migration_candidate = new_id;
		return false;
	}

	ral_logdbg("migrating from ring of id=%s to ring of id=%lu",
		   m_res_key.to_str(), m_migration_candidate);
	m_migration_candidate = 0;

	return true;
}

const char* ring_allocation_logic::to_str()
{
	if (unlikely(m_str[0] == '\0')) {
		snprintf(m_str, sizeof(m_str), "[%s=%p]", m_type, m_owner);
	}
	return m_str;
}

cpu_manager g_cpu_manager;
__thread int g_n_thread_cpu_core = NO_CPU;

cpu_manager::cpu_manager()
{
	reset();
}

void cpu_manager::reset()
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

	cpu_set_t cpu_set;
	CPU_ZERO(&cpu_set);

	int ret = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpu_set);
	if (ret) {
		unlock();
		__log_err("pthread_getaffinity_np failed for tid=%lu, ret=%d (errno=%d %m)", tid, ret, errno);
		return -1;
	}

	int avail_cpus = CPU_COUNT(&cpu_set);
	if (avail_cpus == 0) {
		unlock();
		__log_err("no cpu available for tid=%lu", tid);
		return -1;
	}

	if (avail_cpus == 1) { //already attached
		for (cpu = 0; cpu < MAX_CPU && !CPU_ISSET(cpu, &cpu_set); cpu++) {}
	} else { //need to choose one cpu to attach to
		int min_cpu_count = -1;
		for (int i = 0, j = 0; i < MAX_CPU && j < avail_cpus; i++) {
			if (!CPU_ISSET(i, &cpu_set)) continue;
			j++;
			if (min_cpu_count < 0 || m_cpu_thread_count[i] < min_cpu_count) {
				min_cpu_count = m_cpu_thread_count[i];
				cpu = i;
			}
		}
		if (suggested_cpu >= 0
			&& CPU_ISSET(suggested_cpu, &cpu_set)
			&& m_cpu_thread_count[suggested_cpu] <= min_cpu_count + 1 ) {
			cpu = suggested_cpu;
		}
		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);
		__log_dbg("attach tid=%lu running on cpu=%d to cpu=%d", tid, sched_getcpu(), cpu);
		ret = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpu_set);
		if (ret) {
			unlock();
			__log_err("pthread_setaffinity_np failed for tid=%lu to cpu=%d, ret=%d (errno=%d %m)", tid, cpu, ret, errno);
			return -1;
		}
	}

	g_n_thread_cpu_core = cpu;
	if (cpu > NO_CPU && cpu < MAX_CPU)
		m_cpu_thread_count[cpu]++;
	unlock();
	return cpu;
}
