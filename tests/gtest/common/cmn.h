/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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
