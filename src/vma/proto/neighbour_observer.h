/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */



#ifndef NEIGHBOUR_OBSERVER_H
#define NEIGHBOUR_OBSERVER_H

#include "vma/util/sys_vars.h"
#include "vma/infra/subject_observer.h"

class neigh_observer : public observer
{
public:
	virtual transport_type_t get_obs_transport_type() const = 0;
};

#endif /* NEIGHBOUR_OBSERVER_H */
