/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef EVENT_H
#define EVENT_H

#include <typeinfo>
#include <stdio.h>
#include <stdint.h>
#include "utils/bullseye.h"
#include "vma/util/to_str.h"

class event : public tostr  {
        public:
		enum type{
			UNKNOWN_EVENT,
			SEND_EVENT,
			DROP_EVENT
		};

		type m_type;
                event(void* notifier=NULL) : m_type(UNKNOWN_EVENT), m_notifier(notifier) {}
                virtual ~event() {};

                virtual  const std::string to_str() const
                {
                	char outstr[1024];
                	sprintf(outstr, "EVENT_TYPE=%s NOTIFIER_PTR=%llu", typeid(*this).name(), (long long unsigned int)m_notifier);
                	return std::string(outstr);
                }

        private:
                void* m_notifier;
};


#endif /* EVENT_H */
