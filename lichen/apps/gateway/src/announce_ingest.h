/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_ANNOUNCE_INGEST_H_
#define LICHEN_GATEWAY_ANNOUNCE_INGEST_H_

#include <stddef.h>
#include <stdint.h>

#define GATEWAY_ANNOUNCE_TYPE 0x01U
#define GATEWAY_ANNOUNCE_MIN_LEN 93U
#define GATEWAY_ANNOUNCE_MAX_HOPS 15U
#define GATEWAY_ANNOUNCE_IID_LEN 8U
#define GATEWAY_ANNOUNCE_PUBKEY_LEN 32U
#define GATEWAY_ANNOUNCE_SIGNATURE_LEN 48U

struct gateway_announce_view {
	uint8_t flags;
	uint8_t hop_count;
	uint16_t seq_num;
	const uint8_t *originator_iid;
	const uint8_t *pubkey;
	const uint8_t *signature;
	const uint8_t *app_data;
	size_t app_data_len;
};

int gateway_announce_parse(const uint8_t *data, size_t len,
			   struct gateway_announce_view *announce);

/* Post-dispatch announce body parser/verifier for unit tests and internal use. */
int gateway_announce_ingest_verified(const uint8_t *data, size_t len);

/* Authenticated L2 ingress boundary: requires 0x15 routing dispatch. */
int gateway_announce_ingest_l2_payload(const uint8_t *data, size_t len);

void gateway_announce_ingest_reset(void);

#endif /* LICHEN_GATEWAY_ANNOUNCE_INGEST_H_ */
