/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_L2_DAD_H_
#define LICHEN_L2_DAD_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_DAD_PACKET_LEN 64U
#define LICHEN_DAD_PROBE_COUNT 3U
#define LICHEN_DAD_EUI64_LEN 8U

struct lichen_dad_exchange {
	uint8_t challenger_eui64[LICHEN_DAD_EUI64_LEN];
	uint16_t short_addr;
	uint8_t probes_sent;
	bool conflict_detected;
	bool completed;
	bool cancelled;
};

bool lichen_dad_short_addr_is_reserved(uint16_t short_addr);
int lichen_dad_target(uint16_t short_addr, uint8_t target[16]);
int lichen_dad_build_probe(uint16_t short_addr, uint8_t *out, size_t out_size,
			   size_t *out_len);
int lichen_dad_parse_probe(const uint8_t *packet, size_t packet_len,
			   uint16_t *short_addr);
int lichen_dad_build_conflict(uint16_t short_addr, uint8_t *out, size_t out_size,
			      size_t *out_len);
int lichen_dad_parse_conflict(const uint8_t *packet, size_t packet_len,
			      uint16_t expected_short_addr);

int lichen_dad_conflict_for_probe(const uint8_t *probe, size_t probe_len,
				  uint16_t owned_short_addr,
				  const uint8_t owner_eui64[LICHEN_DAD_EUI64_LEN],
				  const uint8_t sender_eui64[LICHEN_DAD_EUI64_LEN],
				  uint8_t *out, size_t out_size, size_t *out_len);

int lichen_dad_exchange_init(struct lichen_dad_exchange *exchange,
			     const uint8_t challenger_eui64[LICHEN_DAD_EUI64_LEN],
			     uint16_t short_addr);
int lichen_dad_exchange_next_probe(struct lichen_dad_exchange *exchange,
				   uint8_t *out, size_t out_size, size_t *out_len);
int lichen_dad_exchange_record_conflict(
	struct lichen_dad_exchange *exchange, const uint8_t *packet, size_t packet_len,
	const uint8_t owner_eui64[LICHEN_DAD_EUI64_LEN]);
int lichen_dad_exchange_finish(struct lichen_dad_exchange *exchange);
int lichen_dad_exchange_cancel(struct lichen_dad_exchange *exchange);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_L2_DAD_H_ */
