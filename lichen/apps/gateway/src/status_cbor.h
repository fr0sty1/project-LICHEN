/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_STATUS_CBOR_H_
#define LICHEN_GATEWAY_STATUS_CBOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/hal.h>

#define LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE 704U
#define LICHEN_GATEWAY_STATUS_CBOR_MAX_ROLE_LEN 15U

size_t lichen_gateway_encode_status_cbor(
	uint8_t *buf, size_t buf_size, uint16_t rank, const char *role,
	bool rpl_capable, uint32_t uptime_ms,
	const struct lichen_hal_power_snapshot *power,
	const struct lichen_hal_location_time_snapshot *location_time,
	const struct lichen_hal_time_snapshot *time);

#endif /* LICHEN_GATEWAY_STATUS_CBOR_H_ */
