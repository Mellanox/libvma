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
#include "utils/bullseye.h"

struct atomic_t {
	__volatile__ int counter;
};

#define ATOMIC_INIT(i)  { (i) }

/**
 * Read atomic variable.
 * @param v pointer of type atomic_t
 * @return Value of the atomic.
 *
 * Atomically reads the value of @v.
 */
#define atomic_read(v) ((v)->counter)

/**
 * Set atomic variable.
 * @param v pointer of type atomic_t.
 * @param i required value.
 */
#define atomic_set(v,i) (((v)->counter) = (i))

#if 0

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

/**
 *  Returns current contents of addr and replaces contents with value.
 *  @param value Values to set.
 *  @param addr Address to set.
 *  @return Previous value of *addr.
 */
template<typename T>
static inline T atomic_swap(T new_value, T *addr)
{
	return (T)xchg((unsigned long)new_value, (void*)addr);
}

/**
 *  Replaces *addr with new_value if it equals old_value.
 *  @param old_value Expected value.
 *  @param new_value Value to set.
 *  @param addr Address to set.
 *  @return true if was set, false if not.
 */
template<typename T>
static bool atomic_cas(T old_value, T new_value, T *addr)
{
	return cmpxchg((unsigned long)old_value, (unsigned long)new_value, (void*)addr);
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

#endif

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_inc(atomic_t *v)
{
	return atomic_fetch_and_add(1, &v->counter);
}

/**
 * Add to the atomic variable.
 * @param i integer value to add.
 * @param v pointer of type atomic_t.
 * @return Value before add.
 */
static inline int atomic_fetch_and_dec(atomic_t *v)
{
	return atomic_fetch_and_add(-1, &v->counter);
}

#endif /* ATOMIC_H_ */
