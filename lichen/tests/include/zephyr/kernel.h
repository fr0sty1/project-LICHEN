/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zephyr/kernel.h
 * @brief Minimal host-test stub for \<zephyr/kernel.h\>
 *
 * Standalone host tests include real LICHEN headers whose public structs
 * embed Zephyr types (e.g. struct k_mutex in lichen/rpl_routing.h). This
 * stub provides just enough for those headers to parse on the host; it is
 * never linked against Zephyr objects. Guarded so it can only leak into
 * LICHEN_RPL_TEST builds.
 */

#ifndef ZEPHYR_HOST_TEST_KERNEL_H_
#define ZEPHYR_HOST_TEST_KERNEL_H_

#include <stdint.h>

#ifndef LICHEN_RPL_TEST
#error "Host-test zephyr/kernel.h stub is only for LICHEN_RPL_TEST builds"
#endif

struct k_mutex {
	uint32_t lock_word;
};

#endif /* ZEPHYR_HOST_TEST_KERNEL_H_ */
