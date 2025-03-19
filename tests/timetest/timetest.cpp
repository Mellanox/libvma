/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2014-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "utils/clock.h"
#include "utils/rdtsc.h"

#define ITERATION_NUM 10000000
#define ITERATION_NUM_LOW_PPS 100
#define LOW_PPS_SLEEP_USEC 10000

int main(int argc, char* argv[])
{
	if (argc) {};
	if (argv) {};

	struct sched_param sp;
	sp.sched_priority = 30;
	sched_setscheduler(0, SCHED_FIFO, &sp);

        std::cout << "--------------------------------------------------------------------------------" << std::endl;
        std::cout << "" << std::endl;
        std::cout << "" << std::endl;

	std::cout << "Get time using clock_gettime(CLOCK_MONOTONIC):" << std::endl;


	int64_t timeall = 0;

	timespec* times1 = new timespec[ITERATION_NUM];

	for(int i=0;i<ITERATION_NUM;i++){
		gettime(&times1[i]);
	}
	for(int i=0;i<ITERATION_NUM-1;i++){
		timespec m_elapsed = TIMESPEC_INITIALIZER;
		ts_sub(&times1[i+1], &times1[i], &m_elapsed);
		timeall += ts_to_nsec(&m_elapsed);
		//std::cout << i << ": " << ts_to_nsec(&m_elapsed) << std::endl;
	}
	double clockmon_avg = ((double)timeall)/(ITERATION_NUM-1);
	std::cout << "clock_gettime(CLOCK_MONOTONIC)  AVG: " << clockmon_avg << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "Get time using RDTSC:" << std::endl;

	timeall = 0;

	timespec* times2 = new timespec[ITERATION_NUM];

	for(int i=0;i<ITERATION_NUM;i++){
		gettimefromtsc(&times2[i]);
	}
	for(int i=0;i<ITERATION_NUM-1;i++){
		timespec m_elapsed = TIMESPEC_INITIALIZER;
		ts_sub(&times2[i+1], &times2[i], &m_elapsed);
		if (i > 0) timeall += ts_to_nsec(&m_elapsed);
		//std::cout << i << ": " << ts_to_nsec(&m_elapsed) << std::endl;
	}
	double rdtsc_avg = ((double)timeall)/(ITERATION_NUM-2);
	std::cout << "RDTSC  AVG: " << rdtsc_avg << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "Get time using gettimeofday:" << std::endl;

	timeall = 0;

	timeval* times = new timeval[ITERATION_NUM];
	for(int i=0;i<ITERATION_NUM;i++){
		gettime(&times[i]);
	}
	for(int i=0;i<ITERATION_NUM-1;i++){
		timeval m_elapsed = TIMEVAL_INITIALIZER;
		tv_sub(&times[i+1], &times[i], &m_elapsed);
		timeall += tv_to_nsec(&m_elapsed);
		//std::cout << i << ": " << tv_to_nsec(&m_elapsed) << std::endl;
	}

	double timeofday_avg = ((double)timeall)/(ITERATION_NUM-1);
	std::cout << "gettimeofday  AVG: " << timeofday_avg << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "Get time using clock_gettime(CLOCK_MONOTONIC) - low pps:" << std::endl;

	timeall = 0;

	for(int i=0;i<ITERATION_NUM_LOW_PPS;i++){

		usleep(LOW_PPS_SLEEP_USEC);
		timespec m_start = TIMESPEC_INITIALIZER;
		timespec m_elapsed = TIMESPEC_INITIALIZER;
		timespec m_current = TIMESPEC_INITIALIZER;
		gettime(&m_start);
		gettime(&m_current);
		ts_sub(&m_current, &m_start, &m_elapsed);
		timeall += ts_to_nsec(&m_elapsed);
		//std::cout << i << ": " << ts_to_nsec(&m_elapsed) << std::endl;
	}

	double clockmon_avg_lowpps = ((double)timeall)/(ITERATION_NUM_LOW_PPS-1);
	std::cout << "clock_gettime(CLOCK_MONOTONIC) - low pps  AVG: " << clockmon_avg_lowpps << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "Get time using RDTSC - low pps:" << std::endl;

	timeall = 0;

	for(int i=0;i<ITERATION_NUM_LOW_PPS;i++){

		usleep(LOW_PPS_SLEEP_USEC);
		timespec m_start = TIMESPEC_INITIALIZER;
		timespec m_elapsed = TIMESPEC_INITIALIZER;
		timespec m_current = TIMESPEC_INITIALIZER;
		gettimefromtsc(&m_start);
		gettimefromtsc(&m_current);
		ts_sub(&m_current, &m_start, &m_elapsed);
		if(i > 0) timeall += ts_to_nsec(&m_elapsed);
		//std::cout << i << ": " << ts_to_nsec(&m_elapsed) << std::endl;
	}

	double rdtsc_avg_lowpps = ((double)timeall)/(ITERATION_NUM_LOW_PPS-2);
	std::cout << "RDTSC - low pps  AVG: " << rdtsc_avg_lowpps << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "Get time using gettimeofday - low pps:" << std::endl;

	timeall = 0;

	for(int i=0;i<ITERATION_NUM_LOW_PPS;i++){
		usleep(LOW_PPS_SLEEP_USEC);
		timeval start = TIMEVAL_INITIALIZER, current = TIMEVAL_INITIALIZER, elapsed = TIMEVAL_INITIALIZER;
		gettime(&start);
		gettime(&current);
		tv_sub(&current, &start, &elapsed);
		timeall += tv_to_nsec(&elapsed);
		//std::cout << i << ": " << tv_to_nsec(&elapsed) << std::endl;
	}

	double timeofday_avg_lowpps = ((double)timeall)/(ITERATION_NUM_LOW_PPS-1);
	std::cout << "gettimeofday - low pps  AVG: " << timeofday_avg_lowpps << " nsec" << std::endl;

	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "" << std::endl;

	std::cout << "" << std::endl;
	std::cout << "SUMMARY:" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "Timer resolution:" << std::endl;
	std::cout << "------------------" << std::endl;
	std::cout << "clock_gettime(CLOCK_MONOTONIC)  AVG: " << clockmon_avg << " nsec" << std::endl;
	std::cout << "RDTSC  AVG: " << rdtsc_avg << " nsec" << std::endl;
	std::cout << "gettimeofday  AVG: " << timeofday_avg << " nsec" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "Timer resolution - 100 samples per sec:" << std::endl;
	std::cout << "----------------------------------------" << std::endl;
	std::cout << "clock_gettime(CLOCK_MONOTONIC) - low pps  AVG: " << clockmon_avg_lowpps << " nsec" << std::endl;
	std::cout << "RDTSC - low pps  AVG: " << rdtsc_avg_lowpps << " nsec" << std::endl;
	std::cout << "gettimeofday - low pps  AVG: " << timeofday_avg_lowpps << " nsec" << std::endl;
        std::cout << "--------------------------------------------------------------------------------" << std::endl;
	double hz_min = -1, hz_max = -1;
	if (get_cpu_hz(hz_min, hz_max)) {
		std::cout << "Check CPU speeds: min= " << hz_min/1e6 << " MHz, max= " << hz_max/1e6 << " MHz" << std::endl;
	}
	else {
		std::cout << "Check CPU speeds: FAILURE from get_cpu_hz()" << std::endl;
	}
	
	delete [] times;
	delete [] times1;
	delete [] times2;
	
	return 0;
}
