/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#ifndef TESTS_GTEST_VMA_BASE_H_
#define TESTS_GTEST_VMA_BASE_H_

#include <vma_extra.h>

/**
 * To enable vma tests you need to set below VMA_EXTRA_API_ENABLED to 1
 * or you can add the following CPPFLAG during compilation 'make CPPFLAGS="-DVMA_EXTRA_API_ENABLED=1"'
 */
#ifndef VMA_EXTRA_API_ENABLED
#define VMA_EXTRA_API_ENABLED 0
#endif

/**
 * VMA Base class for tests
 */
class vma_base : public testing::Test, public test_base {
protected:
	virtual void SetUp();
	virtual void TearDown();

protected:
	struct vma_api_t *vma_api;
};

#endif /* TESTS_GTEST_VMA_BASE_H_ */
