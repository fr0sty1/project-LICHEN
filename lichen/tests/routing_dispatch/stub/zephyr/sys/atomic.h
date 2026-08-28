/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#ifndef LICHEN_TEST_ZEPHYR_SYS_ATOMIC_H_
#define LICHEN_TEST_ZEPHYR_SYS_ATOMIC_H_

#include <stdint.h>

typedef int32_t atomic_t;

static inline atomic_t atomic_inc(atomic_t *target)
{
	atomic_t previous = *target;
	*target = previous + 1;
	return previous;
}

#endif /* LICHEN_TEST_ZEPHYR_SYS_ATOMIC_H_ */
