/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LORA_CAD_H_
#define LICHEN_LORA_CAD_H_

#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/device.h>
#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*lichen_lora_cad_fn)(const struct device *dev,
				  k_timeout_t timeout, bool *busy);

/** Register a CAD callback for a concrete LoRa device. */
int lichen_lora_cad_register(const struct device *dev,
			     lichen_lora_cad_fn callback);

/** Run CAD through the registered LICHEN extension; errors fail closed. */
int lichen_lora_cad_run(const struct device *dev, k_timeout_t timeout,
		       bool *busy);

#ifdef __cplusplus
}
#endif
#endif /* __ZEPHYR__ */

#endif /* LICHEN_LORA_CAD_H_ */
