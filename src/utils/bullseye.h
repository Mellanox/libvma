/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


/*
 * Bullseye Coverage Definitions
*/
#ifndef BULLSEYE_H_
#define BULLSEYE_H_

#ifndef _BullseyeCoverage
#define _BullseyeCoverage 0
#endif

#if _BullseyeCoverage
#define BULLSEYE_EXCLUDE_BLOCK_START	"BullseyeCoverage save off";
#define BULLSEYE_EXCLUDE_BLOCK_END	"BullseyeCoverage restore";
#else
#define BULLSEYE_EXCLUDE_BLOCK_START
#define BULLSEYE_EXCLUDE_BLOCK_END
#endif


#endif /* BULLSEYE_H_ */
