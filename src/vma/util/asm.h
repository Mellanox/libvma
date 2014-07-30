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


#ifndef ASM_H_
#define ASM_H_

#if defined(__aarch64__)
#include "asm-arm64.h"
#elif defined(__powerpc64__)
#include "asm-ppc64.h"
#else
#include "asm-x86.h"
#endif

#endif
