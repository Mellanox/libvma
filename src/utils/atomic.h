/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef ATOMIC_H_
#define ATOMIC_H_

#include "asm.h"

#if defined(__clang__) && __has_builtin(__atomic_load_n)             \
                       && __has_builtin(__atomic_store_n)            \
                       && __has_builtin(__atomic_add_fetch)          \
                       && __has_builtin(__atomic_exchange_n)         \
                       && __has_builtin(__atomic_compare_exchange_n) \
                       && defined(__ATOMIC_RELAXED)                  \
                       && defined(__ATOMIC_CONSUME)                  \
                       && defined(__ATOMIC_ACQUIRE)                  \
                       && defined(__ATOMIC_RELEASE)                  \
                       && defined(__ATOMIC_ACQ_REL)                  \
                       && defined(__ATOMIC_SEQ_CST)
  #define USE_BUILTIN_ATOMIC
#elif defined(__GNUC__) && \
	((__GNUC__ >= 5) || (__GNUC__ >= 4 && __GNUC_MINOR__ >= 7))
  #define USE_BUILTIN_ATOMIC
#else
  #define __ATOMIC_RELAXED		0
  #define __ATOMIC_CONSUME		1
  #define __ATOMIC_ACQUIRE		2
  #define __ATOMIC_RELEASE		3
  #define __ATOMIC_ACQ_REL		4
  #define __ATOMIC_SEQ_CST		5
#endif

/*
 *  C++11 memory model
 */
enum memory_order {
	/* memory_order_relaxed:
	 * Only atomicity is provided there are no constraints on reordering of memory
	 * accesses around the atomic variable.
	 */
	memory_order_relaxed = __ATOMIC_RELAXED,
	memory_order_consume = __ATOMIC_CONSUME,
	/* memory_order_acquire:
	 * No reads in the current thread can be reordered before this load.
	 * This ensures that all writes in other threads that release the same atomic variable
	 * are visible in the current thread.
	 */
	memory_order_acquire = __ATOMIC_ACQUIRE,
	memory_order_release = __ATOMIC_RELEASE,
	memory_order_acq_rel = __ATOMIC_ACQ_REL,
	/* memory_order_seq_cst:
	 * Enforces total ordering. The operation has the same semantics as acquire-release operation
	 * (memory_order_acq_rel), and additionally has sequentially-consistent operation ordering.
	 */
	memory_order_seq_cst = __ATOMIC_SEQ_CST
};

#define ATOMIC_INIT(i)  { (i) }

#ifndef __vma_atomic_fetch_add_explicit
	#if defined(USE_BUILTIN_ATOMIC)
		#define atomic_fetch_add_explicit(_obj, _operand, _order)                      \
			__atomic_fetch_add(&(obj)->value, _operand, _order)
	#elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER)
		#define atomic_fetch_add_explicit(_obj, _order)                                \
			__sync_fetch_and_add(&(_obj)->value, _operand)
	#else
		#error "atomic_fetch_add_explicit() is not supported"
	#endif
#else
	#define atomic_fetch_add_explicit   __vma_atomic_fetch_add_explicit
#endif /* atomic_load_explicit */


/**
 * Atomically stores 'value' into '*object', respecting the given memory order.
 * @param _obj pointer of type atomic_t.
 * @param _val required value.
 * @param _order memory order.
 */
#ifndef __vma_atomic_store_explicit
	#if defined(USE_BUILTIN_ATOMIC)
		#define atomic_store_explicit(_obj, _val, _order)                              \
			__atomic_store_n(&(_obj)->value, (_val), (_order))
	#elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER)
		#define atomic_store_explicit(_obj, _val, _order)                              \
			do {                                                                       \
				__sync_synchronize();                                                  \
				(_obj)->value = (_val);                                                \
				__sync_synchronize();                                                  \
			}                                                                          \
			while (0)
	#else
		#error "atomic_store_explicit() is not supported"
	#endif
#else
	#define atomic_store_explicit   __vma_atomic_store_explicit
#endif /* atomic_store_explicit */

/**
 * Atomically loads 'value' from '*object', respecting the given memory order.
 * @param _obj pointer of type atomic_t.
 * @param _order memory order.
 * @return Value before add.
 */
#ifndef __vma_atomic_load_explicit
	#if defined(USE_BUILTIN_ATOMIC)
		#define atomic_load_explicit(_obj, _order)                                     \
			__atomic_load_n(&(_obj)->value, (_order))
	#elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER)
		#define atomic_load_explicit(_obj, _order)                                     \
			__sync_fetch_and_add(&(_obj)->value, 0)
	#else
		#error "atomic_load_explicit() is not supported"
	#endif
#else
	#define atomic_load_explicit   __vma_atomic_load_explicit
#endif /* atomic_load_explicit */

/**
 * Read atomic variable.
 * @param _obj pointer of type atomic_t
 * @return Value of the atomic.
 *
 * Atomically reads the value of @v.
 */
#define atomic_read(_obj) \
		atomic_load_explicit((_obj), memory_order_relaxed)
/**
 * Set atomic variable.
 * @param _obj pointer of type atomic_t.
 * @param _val required value.
 */
#define atomic_set(_obj, _val) \
		atomic_store_explicit((_obj), (_val), memory_order_relaxed)

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param obj pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_inc(atomic_t *obj)
{
	return atomic_fetch_add_explicit(obj, 1, memory_order_acquire);
}

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param obj pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_dec(atomic_t *obj)
{
	return atomic_fetch_add_explicit(obj, -1, memory_order_acquire);
}

#endif /* ATOMIC_H_ */
