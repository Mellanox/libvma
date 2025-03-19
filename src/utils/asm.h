/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef ASM_H_
#define ASM_H_

#if defined(__aarch64__)
#include "asm-arm64.h"
#elif defined(__powerpc64__)
#include "asm-ppc64.h"
#elif defined(__x86_64__)
#include "asm-x86.h"
#else
#error No architecture specific memory barrier definitions found!
#endif

#endif
