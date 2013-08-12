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


#ifndef RING_ALLOCATION_LOGIC_H_
#define RING_ALLOCATION_LOGIC_H_

#include "vlogger/vlogger.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/util/sys_vars.h"
#include "vma/util/bullseye.h"

#define DEFAULT_RING_KEY 0
#define CANDIDATE_STABILITY_ROUNDS 20

#define RAL_TOSTR(to, type, owner) {char buf[100];sprintf(buf, "[%s=%p]",(type),(owner));(to) = buf;}

#define MAX_CPU 64
#define NO_CPU -1

class ring_allocation_logic
{

protected:

	ring_allocation_logic(ring_logic_t ring_allocation_logic, int ring_migration_ratio, int fd);


public:
	/* careful, you'll lose the previous key !! */
	resource_allocation_key create_new_key(int suggested_cpu = NO_CPU);

	resource_allocation_key get_key() { return m_res_key; }

	bool should_migrate_ring();

protected:
	string m_tostr;

private:
	ring_logic_t		m_ring_allocation_logic;
	int			m_ring_migration_ratio;
	int 			m_fd;

	int			m_migration_try_count;
	resource_allocation_key	m_migration_candidate;
	resource_allocation_key	m_res_key;

	resource_allocation_key get_res_key_by_logic();

};

class ring_allocation_logic_rx : public ring_allocation_logic
{
public:
	ring_allocation_logic_rx(int fd, const void* owner = NULL):
		ring_allocation_logic(mce_sys.ring_allocation_logic_rx,
				mce_sys.ring_migration_ratio_rx,
				fd) { RAL_TOSTR(m_tostr, "Rx",owner); }
};

class ring_allocation_logic_tx : public ring_allocation_logic
{
public:
	ring_allocation_logic_tx(int fd, const void* owner = NULL):
		ring_allocation_logic(mce_sys.ring_allocation_logic_tx,
				mce_sys.ring_migration_ratio_tx,
				fd) { RAL_TOSTR(m_tostr, "Tx",owner); }
};


class cpu_manager;
extern cpu_manager g_cpu_manager;

class cpu_manager : public lock_mutex
{
public:
	cpu_manager();
	int reserve_cpu_for_thread(pthread_t tid, int suggested_cpu = NO_CPU);

private:
	int m_cpu_thread_count[MAX_CPU];
};

#endif /* RING_ALLOCATION_LOGIC_H_ */
