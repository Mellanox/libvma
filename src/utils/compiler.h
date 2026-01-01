/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef SRC_UTILS_COMPILER_H_
#define SRC_UTILS_COMPILER_H_

/**
 * Macro for marking functions as having public visibility.
 */
#if defined(DEFINED_EXPORT_SYMBOL)
  #define EXPORT_SYMBOL  __attribute__((__visibility__("default")))
#else
  #define EXPORT_SYMBOL
#endif

#endif /* SRC_UTILS_COMPILER_H_ */

