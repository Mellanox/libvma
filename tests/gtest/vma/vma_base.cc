/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"
#include "common/base.h"
#include "common/cmn.h"

#include "vma_base.h"

void vma_base::SetUp()
{
	errno = EOK;

#if defined(EXTRA_API_ENABLED) && (EXTRA_API_ENABLED == 1)
	vma_api = vma_get_api();
	SKIP_TRUE(vma_api, "vma test suite should be launched under libvma.so");
#else
	SKIP_TRUE(0, "Tests should be compiled as make CPPFLAGS=-DEXTRA_API_ENABLED=1")
#endif /* EXTRA_API_ENABLED */
}

void vma_base::TearDown()
{
}
