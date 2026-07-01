/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LORA_LOOPBACK_TEST_H_
#define LICHEN_LORA_LOOPBACK_TEST_H_

#include <stdint.h>

struct device;

struct lora_loopback_test_stats {
	uint32_t sent_packets;
	uint32_t received_packets;
};

void lora_loopback_test_reset(const struct device *dev);
void lora_loopback_test_get_stats(const struct device *dev,
				  struct lora_loopback_test_stats *stats);

#endif /* LICHEN_LORA_LOOPBACK_TEST_H_ */
