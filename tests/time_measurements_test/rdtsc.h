/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2011.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef V_RDTSC_H
#define V_RDTSC_H

#include "clock.h"
#include <stdint.h>
#include <unistd.h>

/**
 * RDTSC extensions
 */
typedef unsigned long long tscval_t;

#define TSCVAL_INITIALIZER	(0)

/**
 * Read RDTSC register
 */
static inline void gettimeoftsc(tscval_t *p_tscval)
{
	register uint32_t upper_32, lower_32;

	// ReaD Time Stamp Counter (RDTCS)
	__asm__ __volatile__("rdtsc" : "=a" (lower_32), "=d" (upper_32));

	// Copy to user
	*p_tscval = (((tscval_t)upper_32) << 32) | lower_32;
}

/**
 * Calibrate RDTSC with CPU speed 
 * @return number of tsc ticks per second
 */
static inline tscval_t get_tsc_rate_per_second()
{
	static tscval_t tsc_per_second = TSCVAL_INITIALIZER;
	if (!tsc_per_second) {
		uint64_t delta_usec;
		timespec ts_before, ts_after, ts_delta;
		tscval_t tsc_before, tsc_after, tsc_delta;
	
		// Measure the time actually slept because usleep() is very inaccurate.
		clock_gettime(CLOCK_MONOTONIC, &ts_before);
		gettimeoftsc(&tsc_before);
		usleep(1000);
		clock_gettime(CLOCK_MONOTONIC, &ts_after);
		gettimeoftsc(&tsc_after);
	
		// Calc delta's
		tsc_delta = tsc_after - tsc_before;
		ts_sub(&ts_after, &ts_before, &ts_delta);
		delta_usec = ts_to_usec(&ts_delta);
	
		// Calc rate
		tsc_per_second = tsc_delta * USEC_PER_SEC / delta_usec;
	}
	return tsc_per_second;
}

/**
 * 'gettimeofday()' based on RDTSC 
 * Re-sync with system clock no more then once a second
 */
inline int gettimefromtsc(struct timespec *ts)
{
	static tscval_t tsc_start = TSCVAL_INITIALIZER;
	static struct timespec ts_start = TIMESPEC_INITIALIZER;

	struct timespec ts_delta = TIMESPEC_INITIALIZER;
	tscval_t tsc_now, tsc_delta;
	uint64_t nsec_delta = 0;
	
	if (!ts_isset(&ts_start)) {
		clock_gettime(CLOCK_MONOTONIC, &ts_start);
		gettimeoftsc(&tsc_start);
	}
	gettimeoftsc(&tsc_now);
	tsc_delta = tsc_now - tsc_start;
	nsec_delta = tsc_delta * NSEC_PER_SEC / get_tsc_rate_per_second();

	ts_delta.tv_sec = nsec_delta / NSEC_PER_SEC;
	ts_delta.tv_nsec = nsec_delta - ts_delta.tv_sec * NSEC_PER_SEC;
	ts_add(&ts_start, &ts_delta, ts);

	// Once a second re-sync our start time with real time-of-day
	if (tsc_delta > get_tsc_rate_per_second())
		ts_clear(&ts_start);
	return 0;
}

static inline int gettime(struct timespec *ts)
{
	return clock_gettime(CLOCK_MONOTONIC, ts);
	//return gettimefromtsc(ts);
}

static inline int gettimerdtsc(struct timespec *ts)
{
	//return clock_gettime(CLOCK_MONOTONIC, ts);
	return gettimefromtsc(ts);
}

static inline int gettime(struct timeval *tv)
{
	return gettimeofday(tv, NULL);
}

#endif //RDTSC_H
