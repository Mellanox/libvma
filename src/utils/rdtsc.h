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


#ifndef RDTSC_H
#define RDTSC_H

#include <time.h>
#include "asm.h"
#include "clock.h"

/**
 * RDTSC extensions
 */
typedef unsigned long long tscval_t;

#define TSCVAL_INITIALIZER	(0)

/**
* Read the CPU's Hz (based on /proc/cpuinfo Mhz report)
* Provide the MAX and MIN values, which might be the case if core are running at power control states
* Return true on success, false on any failure
**/
bool get_cpu_hz(double &hz_min, double &hz_max);

/**
 * Calibrate TSC with CPU speed
 * @return number of tsc ticks per second
 */
static inline tscval_t get_tsc_rate_per_second()
{
	static tscval_t tsc_per_second = TSCVAL_INITIALIZER;
	if (!tsc_per_second) {
		double hz_min = -1, hz_max = -1;
		if (get_cpu_hz(hz_min, hz_max)) {
			tsc_per_second = (tscval_t)hz_max;
		}
		else {
			// failure calibrating TSC to CPU speed
			tsc_per_second = 2 * 1e6; // assume 2 MHz CPU speed
		}
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

#ifndef VMA_TIME_MEASURE
	// Once a second re-sync our start time with real time-of-day
	if (tsc_delta > get_tsc_rate_per_second())
		ts_clear(&ts_start);
#endif

	return 0;
}

static inline int gettime(struct timespec *ts)
{
#ifdef VMA_TIME_MEASURE
	return clock_gettime(CLOCK_MONOTONIC, ts);
#else
	return gettimefromtsc(ts);
#endif
}

static inline int gettime(struct timeval *tv)
{
	return gettimeofday(tv, NULL);
}

#endif //RDTSC_H
