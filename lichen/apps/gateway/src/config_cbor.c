/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "config_cbor.h"

#include <errno.h>
#include <string.h>

#include <zcbor_decode.h>

#define CONFIG_KEY_TX_POWER_DBM "tx_power_dbm"
#define CONFIG_KEY_TX_POWER_DBM_LEN (sizeof(CONFIG_KEY_TX_POWER_DBM) - 1u)

size_t lichen_gateway_encode_config_cbor(uint8_t *buf, size_t buf_size,
					 int8_t tx_power_dbm)
{
	if (buf == NULL || buf_size < 16) {
		return 0;
	}

	buf[0] = 0xa1;
	buf[1] = 0x6c;
	(void)memcpy(&buf[2], CONFIG_KEY_TX_POWER_DBM, CONFIG_KEY_TX_POWER_DBM_LEN);
	if (tx_power_dbm >= 0 && tx_power_dbm <= 23) {
		buf[14] = (uint8_t)tx_power_dbm;
		return 15;
	} else if (tx_power_dbm >= 24) {
		buf[14] = 0x18;
		buf[15] = (uint8_t)tx_power_dbm;
		return 16;
	} else if (tx_power_dbm >= -24) {
		buf[14] = (uint8_t)(0x20u + (uint8_t)(-tx_power_dbm - 1));
		return 15;
	} else {
		buf[14] = 0x38;
		buf[15] = (uint8_t)(-tx_power_dbm - 1);
		return 16;
	}
}

static bool key_is_tx_power_dbm(const struct zcbor_string *key)
{
	return key->len == CONFIG_KEY_TX_POWER_DBM_LEN &&
	       memcmp(key->value, CONFIG_KEY_TX_POWER_DBM,
		      CONFIG_KEY_TX_POWER_DBM_LEN) == 0;
}

int lichen_gateway_decode_config_cbor(const uint8_t *buf, size_t len,
				      int8_t *tx_power_dbm)
{
	bool found_tx_power = false;
	int32_t decoded_tx_power = 0;

	if (buf == NULL || len == 0 || tx_power_dbm == NULL) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;
		zcbor_state_t key_state = *zsd;

		if (zcbor_tstr_decode(zsd, &key) && key_is_tx_power_dbm(&key)) {
			if (!zcbor_int32_decode(zsd, &decoded_tx_power) ||
			    decoded_tx_power < LICHEN_GATEWAY_TX_POWER_MIN_DBM ||
			    decoded_tx_power > LICHEN_GATEWAY_TX_POWER_MAX_DBM) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			found_tx_power = true;
			continue;
		}

		(void)zcbor_pop_error(zsd);
		*zsd = key_state;

		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}
	}

	if (!zcbor_map_end_decode(zsd) || !found_tx_power) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}

	*tx_power_dbm = (int8_t)decoded_tx_power;
	return 0;
}
