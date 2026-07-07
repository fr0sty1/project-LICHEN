/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_MESSAGE_CONTRACT_H_
#define GATEWAY_MESSAGE_CONTRACT_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct gateway_message_contract_text {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint8_t to_iid[8];
	uint8_t payload[CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD];
	size_t payload_len;
	bool has_id;
	bool has_to_iid;
};

/*
 * Local app-ingress message contract.
 *
 * Compatibility surfaces call lichen_app_interface_submit_text() when a phone
 * app asks LICHEN to send text. The gateway owns exactly one submit_text sink:
 * it accepts valid messages into this bounded queue and returns -ENOMEM when
 * the normal LICHEN sender has not drained it. Submit is an at-least-once app
 * ingress boundary, not a BLE acknowledgement boundary: if a compatibility
 * transport session drops after submit but before its OK/status frame is
 * queued, the message remains committed and the dispatcher returns the
 * transport enqueue error. This module does not transmit on BLE or LoRa by
 * itself; a mesh sender must call gateway_message_contract_pop_text() and own
 * the actual RF/network send path.
 */
int gateway_message_contract_init(void);
int gateway_message_contract_pop_text(
	struct gateway_message_contract_text *event);

#ifdef CONFIG_ZTEST
void gateway_message_contract_test_reset(void);
#endif

#endif /* GATEWAY_MESSAGE_CONTRACT_H_ */
