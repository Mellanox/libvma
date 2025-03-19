/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_UDP_BASE_H_
#define TESTS_GTEST_UDP_BASE_H_


/**
 * UDP Base class for tests
 */
class udp_base : public testing::Test, public test_base {
public:
    static int sock_create(void);
    static int sock_create_nb(void);

protected:
	virtual void SetUp();
	virtual void TearDown();
};

#endif /* TESTS_GTEST_UDP_BASE_H_ */
