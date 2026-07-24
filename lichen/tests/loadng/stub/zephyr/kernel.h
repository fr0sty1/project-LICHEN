/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Stub Zephyr kernel.h for native LOADng tests.
 * Provides minimal types needed by loadng.c.
 */

#ifndef ZEPHYR_KERNEL_H_
#define ZEPHYR_KERNEL_H_

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

struct k_mutex {
	atomic_flag locked;
};

#define K_MUTEX_DEFINE(name) struct k_mutex name = { .locked = ATOMIC_FLAG_INIT }
#define K_FOREVER (-1)

static inline void k_mutex_lock(struct k_mutex *m, int timeout)
{
	(void)timeout;
	while (atomic_flag_test_and_set(&m->locked)) {
	}
}

static inline void k_mutex_unlock(struct k_mutex *m)
{
	atomic_flag_clear(&m->locked);
}

#endif /* ZEPHYR_KERNEL_H_ */
