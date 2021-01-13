/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef TESTS_GTEST_COMMON_LOG_H_
#define TESTS_GTEST_COMMON_LOG_H_

extern struct gtest_configure_t gtest_conf;

#define log_fatal(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 0)                             \
			fprintf(stderr, "[    FATAL ] " fmt, ##__VA_ARGS__);    \
			exit(1);    \
	} while (0)

#define log_error(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 1)                             \
			fprintf(stderr, "[    ERROR ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_warn(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 2)                             \
			fprintf(stderr, "[     WARN ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_info(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 3)                             \
			printf("\033[0;3%sm" "[     INFO ] " fmt "\033[m", "4", ##__VA_ARGS__);    \
	} while (0)

#define log_trace(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 4)                             \
			printf("\033[0;3%sm" "[    TRACE ] " fmt "\033[m", "7", ##__VA_ARGS__);    \
	} while (0)

#endif /* TESTS_GTEST_COMMON_LOG_H_ */
