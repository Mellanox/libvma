/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>


#include "hash.h"
#include "tc.h"
#include "daemon.h"


int open_store(void);
void close_store(void);

static void free_store_pid(void *ptr);


int open_store(void)
{
	daemon_cfg.ht = hash_create(&free_store_pid, daemon_cfg.opt.max_pid_num);

	return (NULL == daemon_cfg.ht ? -EFAULT : 0);
}

void close_store(void)
{
	hash_destroy(daemon_cfg.ht);
}

static void free_store_pid(void *ptr)
{
	struct store_pid *value;

	if (ptr) {
		value = (struct store_pid *)ptr;
		hash_destroy(value->ht);
		free(value);
	}
}
