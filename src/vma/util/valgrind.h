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
