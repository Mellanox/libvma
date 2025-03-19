/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_LOG_H_
#define TESTS_GTEST_COMMON_LOG_H_

extern struct gtest_configure_t gtest_conf;

#define log_fatal(fmt, ...) \
	do {                                                       \
		if (gtest_conf.log_level > 0) {                           \
			fprintf(stderr, "[    FATAL ] " fmt, ##__VA_ARGS__);    \
		}               \
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
