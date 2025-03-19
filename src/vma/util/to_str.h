/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


/* This class should be inherited by all classed that need to be printed
*/
#ifndef TO_STR_H_
#define TO_STR_H_

#include <string>

/* coverity[missing_move_assignment] */
class tostr
{
public:
	virtual ~tostr(){};
	virtual const std::string to_str() const { return std::string(""); };
};

#endif /* TO_STR_H_ */
