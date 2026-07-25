/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file standalone_config.h
 * @brief Standalone test config defaults for Kconfig-based options
 *
 * This header provides sensible defaults for CONFIG_* macros that are
 * normally defined by Zephyr's Kconfig/autoconf.h. For standalone test
 * builds without Zephyr, this header ensures the code compiles with
 * reasonable default values.
 *
 * Include this BEFORE any LICHEN headers that depend on CONFIG_* macros.
 */

#ifndef LICHEN_STANDALONE_CONFIG_H_
#define LICHEN_STANDALONE_CONFIG_H_

/* Only provide defaults when NOT building under Zephyr */
#ifndef __ZEPHYR__

/* replay.h, l2 peer tables: max neighbors for replay windows */
#ifndef CONFIG_LICHEN_LINK_MAX_NEIGHBORS
#define CONFIG_LICHEN_LINK_MAX_NEIGHBORS 16
#endif

/* link.h: maximum frame length for LoRa */
#ifndef LICHEN_MAX_FRAME_LEN
#define LICHEN_MAX_FRAME_LEN 254
#endif

#ifndef LICHEN_MAX_FRAME_BODY_LEN
#define LICHEN_MAX_FRAME_BODY_LEN 250
#endif

#endif /* !__ZEPHYR__ */

#endif /* LICHEN_STANDALONE_CONFIG_H_ */
