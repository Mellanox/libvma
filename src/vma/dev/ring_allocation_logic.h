/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef RING_ALLOCATION_LOGIC_H_
#define RING_ALLOCATION_LOGIC_H_

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/util/sys_vars.h"
#include "vma_extra.h"

#define CANDIDATE_STABILITY_ROUNDS 20
#define RAL_STR_MAX_LENGTH 100

#define MAX_CPU CPU_SETSIZE
#define NO_CPU -1

class source_t {
public:

	int         m_fd;
	in_addr_t   m_ip;

	source_t(int fd) : m_fd(fd), m_ip(INADDR_ANY) {}
	source_t(in_addr_t ip) : m_fd(-1), m_ip(ip) {}
};

/**
 * this class is responsible for the AL (allocation logic).
 * i gets the AL from the socket\environment variable and return
 * a key which represent the resource behind the allocation logic, it can
 * be the cpu witch the thread runs on or the threadID...
 * this key is part of the ring key configured in ring_alloc_logic_attr
 */
class ring_allocation_logic
{
protected:
	ring_allocation_logic();
	ring_allocation_logic(ring_logic_t ring_allocation_logic,
			      int ring_migration_ratio, source_t source,
			      resource_allocation_key &ring_profile);


public:
	/* careful, you'll lose the previous key !! */
	resource_allocation_key* create_new_key(in_addr_t addr, int suggested_cpu = NO_CPU);

	resource_allocation_key* get_key() { return &m_res_key; }

	bool			should_migrate_ring();
	bool			is_logic_support_migration() { return m_res_key.get_ring_alloc_logic() >= RING_LOGIC_PER_THREAD && m_ring_migration_ratio > 0;}
	uint64_t		calc_res_key_by_logic();
	inline ring_logic_t get_alloc_logic_type() { return m_res_key.get_ring_alloc_logic(); }
	inline void		enable_migration(bool active) { m_active = active; }
	const char*		to_str();

protected:
	char			m_str[RAL_STR_MAX_LENGTH];
	const char*		m_type;
	const void*		m_owner;

private:
	int			m_ring_migration_ratio;
	source_t		m_source;
	int			m_migration_try_count;
	uint64_t		m_migration_candidate;
	bool			m_active;
	resource_allocation_key	m_res_key;
};

class ring_allocation_logic_rx : public ring_allocation_logic
{
public:
	ring_allocation_logic_rx():ring_allocation_logic(){}
	ring_allocation_logic_rx(source_t source, resource_allocation_key &ring_profile, const void* owner):
		ring_allocation_logic(safe_mce_sys().ring_allocation_logic_rx,
				      safe_mce_sys().ring_migration_ratio_rx,
				      source, ring_profile) {
		m_type = "Rx";
		m_owner = owner;
	}
};

class ring_allocation_logic_tx : public ring_allocation_logic
{
public:
	ring_allocation_logic_tx():ring_allocation_logic(){}
	ring_allocation_logic_tx(source_t source, resource_allocation_key &ring_profile, const void* owner):
		ring_allocation_logic(safe_mce_sys().ring_allocation_logic_tx,
				      safe_mce_sys().ring_migration_ratio_tx,
				      source, ring_profile) {
		m_type = "Tx";
		m_owner = owner;
	}
};


class cpu_manager;
extern cpu_manager g_cpu_manager;

class cpu_manager : public lock_mutex
{
public:
	cpu_manager();
	void reset();
	int reserve_cpu_for_thread(pthread_t tid, int suggested_cpu = NO_CPU);

private:
	int m_cpu_thread_count[MAX_CPU];
};

#endif /* RING_ALLOCATION_LOGIC_H_ */
