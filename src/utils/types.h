/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

#ifndef likely
#define likely(x)			__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)			__builtin_expect(!!(x), 0)
#endif

#ifndef NOT_IN_USE
#define NOT_IN_USE(a)			((void)(a))
#endif

#endif //TYPES_H
