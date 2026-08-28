/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_KERNEL_H_
#define TEST_ZEPHYR_KERNEL_H_

#include <pthread.h>

struct k_mutex {
	pthread_mutex_t value;
};

#define K_FOREVER 0
#define K_MUTEX_DEFINE(name) struct k_mutex name = { PTHREAD_MUTEX_INITIALIZER }

static inline int k_mutex_lock(struct k_mutex *mutex, int timeout)
{
	(void)timeout;
	return pthread_mutex_lock(&mutex->value);
}

static inline int k_mutex_unlock(struct k_mutex *mutex)
{
	return pthread_mutex_unlock(&mutex->value);
}

#endif
