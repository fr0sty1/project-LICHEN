/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_INBOUND_EVENTS_H_
#define GATEWAY_INBOUND_EVENTS_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct gateway_inbound_text_event {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	const uint8_t *payload;
	size_t payload_len;
	bool has_id;
};

struct gateway_inbound_status_event {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_id;
	bool has_error_reason;
};

int gateway_inbound_emit_text(const struct gateway_inbound_text_event *event);
int gateway_inbound_emit_status(const struct gateway_inbound_status_event *event);

#ifdef CONFIG_ZTEST
void gateway_inbound_events_test_reset(void);
#endif

#endif /* GATEWAY_INBOUND_EVENTS_H_ */
