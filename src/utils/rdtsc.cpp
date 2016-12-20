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


/*
 * system includes
 */
#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */


#include <stdio.h>
#include <sys/param.h> // for MAX & MIN
#include "utils/rdtsc.h"


bool get_cpu_hz(double &hz_min, double &hz_max)
{
	FILE* f;
	char buf[256];
	bool first_run = true;

	f = fopen("/proc/cpuinfo", "r");
	if (!f) {
		return false;
	}

	while (fgets(buf, sizeof(buf), f)) {
		double mhz;
		int rc;

#if defined(__ia64__)
		rc = sscanf(buf, "itc MHz : %lf", &mhz);
#elif defined(__powerpc__)
		rc = sscanf(buf, "clock : %lf", &mhz);
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


