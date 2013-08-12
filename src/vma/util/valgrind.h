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


#ifndef VMA_VALGRIND_H_
#define VMA_VALGRIND_H_

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/* Valgrind compatibility */
#ifndef NVALGRIND
#  include <valgrind/memcheck.h>
#  ifndef VALGRIND_MAKE_MEM_DEFINED
#    define VALGRIND_MAKE_MEM_DEFINED(p, n)   VALGRIND_MAKE_READABLE(p, n)
#  endif
#  ifndef VALGRIND_MAKE_MEM_UNDEFINED
#    define VALGRIND_MAKE_MEM_UNDEFINED(p, n) VALGRIND_MAKE_WRITABLE(p, n)
#  endif
#else
#  define VALGRIND_MAKE_MEM_DEFINED(p, n)
#  define VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#  define VALGRIND_MAKE_MEM_NOACCESS(p, n)
#  define VALGRIND_CREATE_MEMPOOL(n,p,x)
#  define VALGRIND_DESTROY_MEMPOOL(p)
#  define VALGRIND_MEMPOOL_ALLOC(n,p,x)
#  define VALGRIND_MEMPOOL_FREE(n,p)
#  define RUNNING_ON_VALGRIND                0
#endif


#endif
