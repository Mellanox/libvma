/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TESTS_GTEST_COMMON_CMN_H_
#define TESTS_GTEST_COMMON_CMN_H_

#include <stdexcept>
#include <sstream>
#include <string>

namespace cmn {

class test_skip_exception : public std::exception {
public:
    test_skip_exception(const std::string& reason = "") : m_reason("[  SKIPPED ] ") {
        m_reason += reason;
    }
    virtual ~test_skip_exception() _GLIBCXX_NOTHROW {
    }

    const char* what() const _GLIBCXX_NOTHROW {
        return m_reason.c_str();
    }

private:
    std::string m_reason;
};

#define SKIP_TRUE(_expr, _reason) \
    if (!(_expr)) { \
		log_warn(_reason "\n"); \
		GTEST_SKIP(); \
    }

} /* namespace: cmn */

#endif /* TESTS_GTEST_COMMON_CMN_H_ */
