/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_MESHTASTIC_ADAPTER_H_
#define GATEWAY_MESHTASTIC_ADAPTER_H_

#include <lichen/meshtastic/adapter.h>
#ifdef CONFIG_ZTEST
#include <lichen/hal.h>
#endif

int gateway_meshtastic_adapter_init(void);
int gateway_meshtastic_adapter_emit_text(
	const struct lichen_meshtastic_incoming_text *event);
int gateway_meshtastic_adapter_emit_status(
	const struct lichen_meshtastic_incoming_status *event);

#ifdef CONFIG_ZTEST
void gateway_meshtastic_adapter_test_reset(void);
void gateway_meshtastic_adapter_test_set_power_snapshot(
	const struct lichen_hal_power_snapshot *snapshot);
void gateway_meshtastic_adapter_test_set_location_time_snapshot(
	const struct lichen_hal_location_time_snapshot *snapshot);
int gateway_meshtastic_adapter_test_process_once(void);
#endif

#endif /* GATEWAY_MESHTASTIC_ADAPTER_H_ */
