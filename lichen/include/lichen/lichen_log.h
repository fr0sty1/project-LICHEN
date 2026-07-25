/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Logging abstraction for LICHEN C code.
 *
 * On Zephyr: wraps zephyr/logging/log.h
 * On host:   fprintf to stderr (for unit tests)
 *
 * Usage:
 *   #include <lichen/lichen_log.h>
 *   LICHEN_LOG_MODULE(my_module, LOG_LEVEL_INF);
 *   ...
 *   LOG_ERR("something failed: %d", err);
 */

#ifndef LICHEN_LOG_H
#define LICHEN_LOG_H

#ifdef __ZEPHYR__

#include <zephyr/logging/log.h>

#define LICHEN_LOG_MODULE(name, level) LOG_MODULE_REGISTER(name, level)

#else /* Host build */

#include <stdio.h>

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERR  1
#define LOG_LEVEL_WRN  2
#define LOG_LEVEL_INF  3
#define LOG_LEVEL_DBG  4

#define LICHEN_LOG_MODULE(name, level) \
	static const int _lichen_log_level __attribute__((unused)) = (level)

#define LOG_ERR(fmt, ...) \
	fprintf(stderr, "ERR: " fmt "\n", ##__VA_ARGS__)

#define LOG_WRN(fmt, ...) \
	fprintf(stderr, "WRN: " fmt "\n", ##__VA_ARGS__)

#define LOG_INF(fmt, ...) \
	do { if (_lichen_log_level >= LOG_LEVEL_INF) \
		fprintf(stderr, "INF: " fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define LOG_DBG(fmt, ...) \
	do { if (_lichen_log_level >= LOG_LEVEL_DBG) \
		fprintf(stderr, "DBG: " fmt "\n", ##__VA_ARGS__); \
	} while (0)

#endif /* __ZEPHYR__ */

#endif /* LICHEN_LOG_H */
