/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_CONFIG_APPLY_H_
#define LICHEN_GATEWAY_CONFIG_APPLY_H_

#include <stdint.h>

#include "config_cbor.h"

int lichen_gateway_apply_config_update(
	const struct lichen_gateway_config_update *update,
	int8_t *tx_power_dbm,
	struct lichen_gateway_manual_location_config *manual_location,
	bool *has_manual_location);

#endif /* LICHEN_GATEWAY_CONFIG_APPLY_H_ */
