/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef TESTS_GTEST_MIX_BASE_H_
#define TESTS_GTEST_MIX_BASE_H_

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"


class mix_base : public testing::Test, public test_base
{
protected:
	virtual void SetUp();
	virtual void TearDown();
};

#endif //TESTS_GTEST_MIX_VASE_H_

