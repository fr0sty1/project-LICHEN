/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Stub zephyr/sys/util.h for native LOADng tests. */

#ifndef ZEPHYR_SYS_UTIL_H_
#define ZEPHYR_SYS_UTIL_H_

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#endif /* ZEPHYR_SYS_UTIL_H_ */
