/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Stub zephyr/sys/atomic.h for native LOADng tests. */

#ifndef ZEPHYR_SYS_ATOMIC_H_
#define ZEPHYR_SYS_ATOMIC_H_

#include <stdatomic.h>

typedef atomic_int atomic_t;

#define ATOMIC_INIT(val) (val)

static inline int atomic_dec(atomic_t *target)
{
	return atomic_fetch_sub(target, 1);
}

static inline void atomic_set(atomic_t *target, int val)
{
	atomic_store(target, val);
}

#endif /* ZEPHYR_SYS_ATOMIC_H_ */
