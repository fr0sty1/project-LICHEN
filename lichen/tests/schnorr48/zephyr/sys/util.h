/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef ZEPHYR_SYS_UTIL_H_
#define ZEPHYR_SYS_UTIL_H_

/* Minimal shim for non-Zephyr test builds */

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* Frame length constants (normally from Kconfig) */
#ifndef LICHEN_MAX_FRAME_LEN
#define LICHEN_MAX_FRAME_LEN 255
#endif

#ifndef LICHEN_MAX_FRAME_BODY_LEN
#define LICHEN_MAX_FRAME_BODY_LEN 254
#endif

/* ARRAY_SIZE helper (normally from Zephyr sys/util.h) */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#endif /* ZEPHYR_SYS_UTIL_H_ */
