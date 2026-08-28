/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_TEST_STUB_ZEPHYR_KERNEL_H_
#define LICHEN_TEST_STUB_ZEPHYR_KERNEL_H_

/* Only completeness is needed to compile the public adapter structure. */
struct k_mutex {
	unsigned int opaque;
};

#endif /* LICHEN_TEST_STUB_ZEPHYR_KERNEL_H_ */
