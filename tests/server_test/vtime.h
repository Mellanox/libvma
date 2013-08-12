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
