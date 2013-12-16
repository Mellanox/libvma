/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef LOCK_WRAPPER_H
#define LOCK_WRAPPER_H

#include <pthread.h>
#include <execinfo.h>
#include <string.h>
#include <stdio.h>
#include "rdtsc.h"
#include <vma/util/vtypes.h>

#define likely(x)			__builtin_expect(!!(x), 1)
#define unlikely(x)			__builtin_expect(!!(x), 0)

#define NO_LOCK_STATS

#ifndef LOCK_STATS

// pthread lock stats counter for debugging

class lock_base
{
public:
	lock_base(const char *m_lock_name = NULL) : m_lock_name(m_lock_name) {};
	virtual ~lock_base() {};
	virtual inline int      lock() { return 0; };
	virtual inline int      trylock() { return 0; };
	virtual inline int      unlock() { return 0; };
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	const char*             to_str() { return m_lock_name; }
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
protected:
	tscval_t                start_lock_wait() { return 0; };
	void                    end_lock_wait(tscval_t start_time) {start_time = 0; NOT_IN_USE(start_time);};
private:
	const char*             m_lock_name;
};

#else //LOCK_STATS


#include <stdlib.h>
#include <stdio.h>

//
// pthread counting mutex
//
class lock_base
{
public:
	lock_base(const char *name) {
		m_lock_count = 0;
		m_lock_wait_time = 0;
		m_lock_name = name;
		m_prev_print_time = 0;
		m_print_interval = get_tsc_rate_per_second() * 5;
	};

	virtual ~lock_base() {
		if (m_lock_count > 1000) {
			print_stats();
		}
	};

	virtual inline int lock() {
		m_lock_count++;
		return 0;
	};

	virtual inline int trylock() {
		m_lock_count++;
		return 0;
	}

	virtual inline int unlock() {
		return 0;
	};

	const char*             to_str() { return m_lock_name; }

private:
	void print_stats() {
		printf("[lock %s %p] --- locked %d times average wait %.2f us ---\n",
				to_str(), this, m_lock_count, avg_lock_wait() * 1000000.0);
	}

	const char*             m_lock_name;
	int                     m_lock_count;
	tscval_t                m_lock_wait_time;
	tscval_t                m_prev_print_time;
	tscval_t                m_print_interval;

protected:
	tscval_t start_lock_wait() {
		tscval_t t;
		gettimeoftsc(&t);
		return t;
	}

	void end_lock_wait(tscval_t start_time) {
		tscval_t t;
		gettimeoftsc(&t);
		m_lock_wait_time += (t - start_time);
		if (t - m_prev_print_time > m_print_interval) {
			print_stats();
			m_prev_print_time = t;
		}
	}

	double avg_lock_wait() {
		return (m_lock_wait_time /
			static_cast<double>(get_tsc_rate_per_second())) / m_lock_count ;
	}
};
#endif //LOCK_STATS


/**
 * pthread spinlock
 */
class lock_spin : public lock_base
{
public:
	lock_spin(const char *name = "lock_spin") : lock_base(name) {
		pthread_spin_init(&m_lock, 0);
	};
	~lock_spin() {
		pthread_spin_destroy(&m_lock);
	};
	inline int lock() {
		tscval_t t = start_lock_wait();
		int ret = pthread_spin_lock(&m_lock);
		lock_base::lock();
		end_lock_wait(t);
		return ret;
	};
	inline int trylock() {
		int ret = pthread_spin_trylock(&m_lock);
		lock_base::trylock();
		return ret;
	};
	inline int unlock() {
		lock_base::unlock();
		return pthread_spin_unlock(&m_lock);
	};

protected:
	pthread_spinlock_t	m_lock;
};

/**
 * pthread spinlock
 */
class lock_spin_recursive : public lock_spin
{
public:
	lock_spin_recursive(const char *name = "lock_spin_recursive") :
		lock_spin(name), m_lock_count(0) {
		memset(&m_invalid_owner, 0xff, sizeof(m_invalid_owner));
		m_owner = m_invalid_owner;
	};
	~lock_spin_recursive() {};

	inline int lock() {
		pthread_t self = pthread_self();
		if (m_owner == self) {
			++m_lock_count;
			return 0;
		}
		tscval_t t = start_lock_wait();
		int ret = lock_spin::lock();
		if (likely(ret == 0)) {
			++m_lock_count;
			m_owner = self;
		}
		end_lock_wait(t);
		return ret;
	};
	inline int trylock() {
		pthread_t self = pthread_self();
		if (m_owner == self) {
			++m_lock_count;
			return 0;
		}
		int ret = lock_spin::trylock();
		if (ret == 0) {
			++m_lock_count;
			m_owner = self;
		}
		return ret;
	};
	inline int unlock() {
		if (--m_lock_count == 0) {
			m_owner = m_invalid_owner;
			return lock_spin::unlock();
		}
		return 0;
	};

protected:
	pthread_t		m_owner;
	pthread_t		m_invalid_owner;
	int			m_lock_count;
};

/**
 * pthread mutex
 */
class lock_mutex : public lock_base
{
public:
	lock_mutex(const char *name = "lock_mutex",
	           int mtx_type = PTHREAD_MUTEX_DEFAULT) : lock_base(name) {
		pthread_mutexattr_t mtx_attr;
		pthread_mutexattr_init(&mtx_attr);
		pthread_mutexattr_settype(&mtx_attr, mtx_type);
		pthread_mutex_init(&m_lock, &mtx_attr);
	};
	~lock_mutex() {
		pthread_mutex_destroy(&m_lock);
	};
	inline int lock() {
		tscval_t t = start_lock_wait();
		int ret = pthread_mutex_lock(&m_lock);
		lock_base::lock();
		end_lock_wait(t);
		return ret;
	};
	inline int trylock() {
		int ret = pthread_mutex_trylock(&m_lock);
		lock_base::trylock();
		return ret;
		};
	inline int unlock() {
		lock_base::unlock();
		return pthread_mutex_unlock(&m_lock);
	};

protected:
	pthread_mutex_t		m_lock;
};


/**
 * pthread recursive mutex
 */
class lock_mutex_recursive : public lock_mutex
{
public:
	lock_mutex_recursive(const char *name = "lock_mutex_recursive") :
	    lock_mutex(name, PTHREAD_MUTEX_RECURSIVE) {};
	~lock_mutex_recursive()	{};
};


/**
 * pthread condition with mutex
 */
class lock_mutex_cond : public lock_mutex
{
public:
	lock_mutex_cond(const char *name = "lock_mutex_cond") : lock_mutex(name) {
		pthread_cond_init(&m_cond, NULL);
	};
	~lock_mutex_cond() {
		pthread_cond_destroy(&m_cond);
	};
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
	int signal() {
		return pthread_cond_signal(&m_cond);
	}
	;
	int broadcast() {
		return pthread_cond_broadcast(&m_cond);
	};
	int wait() {
		return pthread_cond_wait(&m_cond, &m_lock);
	};
	int timedwait(const struct timespec *__restrict abstime) {
		return pthread_cond_timedwait(&m_cond, &m_lock, abstime);
	};
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

protected:
	pthread_cond_t		m_cond;
};

/**
 * automatic unlock at end of scope where this object was defined on
 * Input: lock_base of lock kind as reference
 */
class auto_unlocker
{
public:
	auto_unlocker(lock_base& lock) : m_lock(lock) {
		m_lock.lock();
		//printf("[%s %p] locked\n", m_lock.to_str(), this);
	};
	~auto_unlocker() {
		//printf("[%s %p] unlocking\n", m_lock.to_str(), this);
		m_lock.unlock();
	};

private:
	lock_base&	m_lock;
};

#endif //LOCK_WRAPPER_H
