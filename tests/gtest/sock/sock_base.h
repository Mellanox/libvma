/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_SOCK_BASE_H_
#define TESTS_GTEST_SOCK_BASE_H_


/**
 * SOCK Base class for tests
 */
class sock_base : public testing::Test, public test_base {
protected:
	virtual void SetUp();
	virtual void TearDown();
};

#endif /* TESTS_GTEST_SOCK_BASE_H_ */
