/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_CONFIG_CBOR_H_
#define LICHEN_GATEWAY_CONFIG_CBOR_H_

#include <stddef.h>
#include <stdint.h>

#define LICHEN_GATEWAY_TX_POWER_MIN_DBM -9
#define LICHEN_GATEWAY_TX_POWER_MAX_DBM 22

size_t lichen_gateway_encode_config_cbor(uint8_t *buf, size_t buf_size,
					 int8_t tx_power_dbm);

int lichen_gateway_decode_config_cbor(const uint8_t *buf, size_t len,
				      int8_t *tx_power_dbm);

#endif /* LICHEN_GATEWAY_CONFIG_CBOR_H_ */
