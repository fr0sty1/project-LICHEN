/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_TEST_ZEPHYR_KERNEL_H_
#define LICHEN_TEST_ZEPHYR_KERNEL_H_

#include <pthread.h>
#include <stdint.h>

#define K_FOREVER (-1)

struct k_mutex {
	pthread_mutex_t native;
};

#define K_MUTEX_DEFINE(name) \
	struct k_mutex name = {.native = PTHREAD_MUTEX_INITIALIZER}

static inline int k_mutex_lock(struct k_mutex *mutex, int32_t timeout)
{
	(void)timeout;
	return pthread_mutex_lock(&mutex->native);
}

static inline int k_mutex_unlock(struct k_mutex *mutex)
{
	return pthread_mutex_unlock(&mutex->native);
}

extern int64_t lichen_test_uptime_ms;

static inline int64_t k_uptime_get(void)
{
	return lichen_test_uptime_ms;
}

#endif /* LICHEN_TEST_ZEPHYR_KERNEL_H_ */
