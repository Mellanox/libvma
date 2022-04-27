/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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


#ifndef VTIME_H_
#define VTIME_H_

#include <stdint.h>

class vtime {
public:

    typedef long long time_t;

    static const time_t MXM_MSEC_PER_SEC = 1000ull;       /* Milli */
    static const time_t MXM_USEC_PER_SEC = 1000000ul;     /* Micro */
    static const time_t MXM_NSEC_PER_SEC = 1000000000ul;  /* Nano */


    static inline time_t current() {
        time_t time;
#if defined (__x86_64__) || defined(__i386__)
        uint32_t low, high;
        asm volatile ("rdtsc" : "=a" (low), "=d" (high));
        time = ((time_t)high << 32) | (time_t)low;
#  define MXM_TIME_CPU_CLOCK 1
#elif defined(__PPC__) || defined(__PPC64__)
        asm volatile ("mftb %0" : "=r" (time) : );
#  define MXM_TIME_CPU_CLOCK 1
#elif defined(__ia64__)
        asm volatile ("mov %0=ar.itc" : "=r" (ret));
#  define MXM_TIME_CPU_CLOCK 1
#else
        /* Fallback - use microseconds from gettimeofday() */
        struct timeval tv;
        gettimeofday(&tv, NULL);
        time = tv.tv_usec + tv.tv_sec * MXM_USEC_PER_SEC;
#  define MXM_TIME_CPU_CLOCK 0
#endif
        return time;
    }


    /**
     * @return The clock value of a single second.
     */
    static inline double time_sec_value() {
#if MXM_TIME_CPU_CLOCK
        return get_cpu_clocks_per_sec();
#else
        return MXM_USEC_PER_SEC;
#endif
    }


    /**
     * Convert seconds to time units.
     */
    static inline time_t time_from_sec(double sec) {
        return sec * time_sec_value();
    }

    /**
     * Convert MXM time units to seconds.
     */
    static inline double time_to_sec(time_t time) {
        return time / time_sec_value();
    }

private:
    typedef unsigned long long cycles_t;

    vtime();

    static double get_cpu_clocks_per_sec();
    static double sample_get_cpu_mhz(void);
    static double proc_get_cpu_mhz(int no_cpu_freq_fail);
    static double get_cpu_mhz(int no_cpu_freq_fail);

    double m_clocks_per_sec;

};

#endif
