/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef RDTSC_H
#define RDTSC_H

#include <time.h>
#include <stdio.h>
#include <sys/param.h> // for MAX & MIN

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
static bool get_cpu_hz(double &hz_min, double &hz_max)
{
	FILE* f;
	char buf[256];
	bool first_run = true;

	f = fopen("/proc/cpuinfo", "r");
	if (!f) {
		return false;
	}

	while (fgets(buf, sizeof(buf), f)) {
		double mhz = 0;
		int rc = 0;

#if defined(__ia64__)
		rc = sscanf(buf, "itc MHz : %lf", &mhz);
#elif defined(__powerpc__)
		rc = sscanf(buf, "clock : %lf", &mhz);
#elif defined(__aarch64__)
		rc = sscanf(buf, "BogoMIPS : %lf", &mhz);
		mhz /= 2;
#else
		rc = sscanf(buf, "cpu MHz : %lf", &mhz);
#endif
		if (rc != 1) {
			continue;
		}
		if (first_run) {
			// first time align of all values
			first_run = false;
			hz_max = hz_min = mhz;
			continue;
		}
		hz_min = MIN(hz_min, mhz);
		hz_max = MAX(hz_max, mhz);
	}
	fclose(f);

	// Convert to Hz before return to caller
	// (original values are in MHz)
	hz_min = hz_min * 1.0e6;
	hz_max = hz_max * 1.0e6;
	return true;
}

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
