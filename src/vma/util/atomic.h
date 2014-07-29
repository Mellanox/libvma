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


#ifndef ATOMIC_H_
#define ATOMIC_H_

#include "asm.h"

struct atomic_t {
	__volatile__ int counter;
};

#define ATOMIC_DECLARE_INIT(i) 	{ counter: i }

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

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
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
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif


#endif /* ATOMIC_H_ */
