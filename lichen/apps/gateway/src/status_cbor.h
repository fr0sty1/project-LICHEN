/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_STATUS_CBOR_H_
#define LICHEN_GATEWAY_STATUS_CBOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/hal.h>

#define LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE 832U
#define LICHEN_GATEWAY_STATUS_CBOR_MAX_ROLE_LEN 15U

/**
 * @brief Queue statistics for /status/queues endpoint
 *
 * Per spec/appendix-bufferbloat.md: queue metrics for diagnostics.
 */
struct lichen_gateway_queue_stats {
	uint32_t packets_queued;         /**< Total packets accepted */
	uint32_t packets_dropped_deadline; /**< Dropped due to deadline expiry */
	uint32_t packets_dropped_full;   /**< Dropped due to queue full */
	uint32_t max_latency_ms;         /**< Worst-case queue time observed */
	uint32_t avg_latency_ms;         /**< Smoothed average queue time */
};

/** Maximum CBOR size for queue stats (5 uint32s + map overhead) */
#define LICHEN_GATEWAY_QUEUES_CBOR_MAX_SIZE 64U

size_t lichen_gateway_encode_status_cbor(
	uint8_t *buf, size_t buf_size, uint16_t rank, const char *role,
	bool rpl_capable, uint32_t uptime_ms,
	const struct lichen_hal_power_snapshot *power,
	const struct lichen_hal_location_time_snapshot *location_time,
	const struct lichen_hal_time_snapshot *time);

/**
 * @brief Encode queue statistics as CBOR for /status/queues endpoint.
 *
 * Produces a CBOR map with keys: packets_queued, dropped_deadline,
 * dropped_full, max_latency_ms, avg_latency_ms.
 *
 * @param buf      Output buffer
 * @param buf_size Buffer size (must be >= LICHEN_GATEWAY_QUEUES_CBOR_MAX_SIZE)
 * @param stats    Queue statistics to encode
 * @return Encoded byte count, or 0 on error
 */
size_t lichen_gateway_encode_queues_cbor(
	uint8_t *buf, size_t buf_size,
	const struct lichen_gateway_queue_stats *stats);

#endif /* LICHEN_GATEWAY_STATUS_CBOR_H_ */
