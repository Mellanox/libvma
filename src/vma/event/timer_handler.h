/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef TIMER_HANDLER_H
#define TIMER_HANDLER_H

#include <atomic>

#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"

/**
 * simple timer notification.
 * Any class that inherit timer_handler should also inherit cleanable_obj, and use clean_obj instead of delete.
 * It must implement the clean_obj method to delete the object from the internal thread.
 */
class timer_handler
{
private:
	lock_spin m_handle_mutex{"timer_handler"};
	std::atomic<bool> m_destroy_in_progress{false};
protected:
	virtual void handle_timer_expired(void* user_data) = 0;

public:
	timer_handler() = default;

	virtual ~timer_handler() {
		if( !m_destroy_in_progress.load()) {
			m_destroy_in_progress = true;
			vlog_printf(VLOG_DEBUG, "Destroying timer_handler without destroy in progress.\n
		}
		{
			m_handle_mutex.lock();
			m_handle_mutex.unlock();
		}
	};

	void safe_handle_timer_expired(void* user_data) {
		if(!m_destroy_in_progress.load()) {
			if (m_handle_mutex.trylock() == 0) {
				handle_timer_expired(user_data);
				m_handle_mutex.unlock();
			}
		}
	}

/**
  * Sets the destroying state of the object to indicate that destruction is in progress.
  *
  * If `wait_for_handler` is set to true, this method will ensure that the mutex
  * used for handling operations (m_handle_mutex) is acquired and released, effectively
  * waiting for any pending handler operation to complete.
  *
  * @param wait_for_handler If true, waits for the handler mutex to ensure
  *                         handler finish before proceeding.
  *                         Defaults to false.
  *
  * @return The previous state of the destruction flag.
  *         Returns true if a destruction process was already in progress before
  *         this method was called, otherwise false.
  */
	bool set_destroying_state(bool wait_for_handler = false) {
		bool result = m_destroy_in_progress.exchange(true);
		if( wait_for_handler ) {
			m_handle_mutex.lock();
			m_handle_mutex.unlock();
		}
		return result;
	}
};

#endif
