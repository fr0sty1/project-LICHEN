/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_MESHTASTIC_ADAPTER_H_
#define GATEWAY_MESHTASTIC_ADAPTER_H_

#include <lichen/meshtastic/adapter.h>

int gateway_meshtastic_adapter_init(void);
int gateway_meshtastic_adapter_emit_text(
	const struct lichen_meshtastic_incoming_text *event);
int gateway_meshtastic_adapter_emit_status(
	const struct lichen_meshtastic_incoming_status *event);

#ifdef CONFIG_ZTEST
void gateway_meshtastic_adapter_test_reset(void);
int gateway_meshtastic_adapter_test_process_once(void);
#endif

#endif /* GATEWAY_MESHTASTIC_ADAPTER_H_ */
