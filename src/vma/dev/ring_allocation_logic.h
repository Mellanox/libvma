/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef RING_ALLOCATION_LOGIC_H_
#define RING_ALLOCATION_LOGIC_H_

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "vma/dev/net_device_table_mgr.h"
#include "vma/util/sys_vars.h"

#define DEFAULT_RING_KEY 0
#define CANDIDATE_STABILITY_ROUNDS 20

#define RAL_TOSTR(to, type, owner) {char buf[100];sprintf(buf, "[%s=%p]",(type),(owner));(to) = buf;}

#define MAX_CPU CPU_SETSIZE
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
		ring_allocation_logic(safe_mce_sys().ring_allocation_logic_rx,
				safe_mce_sys().ring_migration_ratio_rx,
				fd) { RAL_TOSTR(m_tostr, "Rx",owner); }
};

class ring_allocation_logic_tx : public ring_allocation_logic
{
public:
	ring_allocation_logic_tx(int fd, const void* owner = NULL):
		ring_allocation_logic(safe_mce_sys().ring_allocation_logic_tx,
				safe_mce_sys().ring_migration_ratio_tx,
				fd) { RAL_TOSTR(m_tostr, "Tx",owner); }
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
