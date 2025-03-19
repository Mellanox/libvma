/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef VMA_IF_H_
#define VMA_IF_H_

#include <sys/socket.h>
#include <linux/if.h>

/* defined in net/if.h but that conflicts with linux/if.h... */
extern "C" unsigned int if_nametoindex (__const char *__ifname) __THROW;
extern "C" char *if_indextoname (unsigned int __ifindex, char *__ifname) __THROW;

#endif
