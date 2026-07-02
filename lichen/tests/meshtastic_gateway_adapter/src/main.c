/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap.h>

#include <lichen/app_identity/app_identity.h>
#include <lichen/app_interface/app_interface.h>
#include <lichen/meshtastic/codec.h>

#include "ble_meshtastic.h"
#include "fake_ble_meshtastic.h"
#include "inbound_coap.h"
#include "inbound_events.h"
#include "message_contract.h"
#include "meshtastic_adapter.h"

#define COAP_TEST_BUF_SIZE 64
#define TEST_MESSAGE_CONTRACT_QUEUE_DEPTH 3U

static void reset_gateway(size_t from_radio_cap)
{
	gateway_inbound_events_test_reset();
	lichen_app_identity_test_reset();
	gateway_message_contract_test_reset();
	lichen_app_interface_test_reset();
	fake_ble_meshtastic_reset(from_radio_cap);
	zassert_ok(gateway_message_contract_init());
	gateway_meshtastic_adapter_test_reset();
}

static void expect_from_radio(size_t index, const uint8_t *expected,
			      size_t expected_len)
{
	const uint8_t *actual;
	size_t actual_len;

	actual = fake_ble_meshtastic_from_radio(index, &actual_len);
	zassert_not_null(actual);
	zassert_equal(actual_len, expected_len);
	zassert_mem_equal(actual, expected, expected_len);
}

static void make_post_request(struct coap_packet *request, uint8_t *buf,
			      size_t buf_len, const uint8_t *payload,
			      size_t payload_len)
{
	static const uint8_t token[] = { 0x01 };

	zassert_ok(coap_packet_init(request, buf, buf_len, COAP_VERSION_1,
				    COAP_TYPE_CON, sizeof(token), token,
				    COAP_METHOD_POST, 0x1234));
	if (payload_len > 0U) {
		zassert_ok(coap_packet_append_payload_marker(request));
		zassert_ok(coap_packet_append_payload(request, payload,
						      payload_len));
	}
}

struct queue_status_view {
	uint32_t res;
	uint32_t free;
	uint32_t maxlen;
	uint32_t mesh_packet_id;
	bool has_res;
	bool has_mesh_packet_id;
};

struct from_radio_view {
	uint32_t field;
	const uint8_t *payload;
	size_t payload_len;
	uint32_t value;
};

struct client_packet_view {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t portnum;
	uint32_t request_id;
	const uint8_t *app_payload;
	size_t app_payload_len;
	bool has_from;
	bool has_to;
	bool has_id;
	bool has_portnum;
	bool has_request_id;
};

static int read_varint(const uint8_t *buf, size_t len, size_t *pos,
		       uint32_t *value)
{
	uint32_t out = 0U;
	uint8_t shift = 0U;

	while (*pos < len && shift < 32U) {
		uint8_t byte = buf[(*pos)++];

		out |= (uint32_t)(byte & 0x7fU) << shift;
		if ((byte & 0x80U) == 0U) {
			*value = out;
			return 0;
		}
		shift += 7U;
	}

	return -EINVAL;
}

static size_t put_varint(uint8_t *buf, size_t cap, uint64_t value)
{
	size_t pos = 0U;

	do {
		uint8_t byte = (uint8_t)(value & 0x7fU);

		value >>= 7;
		if (value != 0U) {
			byte |= 0x80U;
		}
		zassert_true(pos < cap);
		buf[pos++] = byte;
	} while (value != 0U);

	return pos;
}

static void put_le32(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)value;
	buf[1] = (uint8_t)(value >> 8);
	buf[2] = (uint8_t)(value >> 16);
	buf[3] = (uint8_t)(value >> 24);
}

static size_t build_text_to_radio_to(uint8_t *buf, size_t cap,
				     const uint8_t *payload,
				     size_t payload_len, uint32_t to,
				     uint32_t id)
{
	static uint8_t data[64];
	static uint8_t packet[128];
	size_t data_len = 0U;
	size_t packet_len = 0U;
	size_t pos = 0U;

	zassert_true(payload_len <= sizeof(data) - 8U);

	data[data_len++] = 0x08; /* Data.portnum */
	data[data_len++] = 0x01; /* TEXT_MESSAGE_APP */
	data[data_len++] = 0x12; /* Data.payload */
	data_len += put_varint(&data[data_len], sizeof(data) - data_len,
			       payload_len);
	memcpy(&data[data_len], payload, payload_len);
	data_len += payload_len;

	packet[packet_len++] = 0x15; /* MeshPacket.to fixed32 */
	put_le32(&packet[packet_len], to);
	packet_len += 4U;
	packet[packet_len++] = 0x22; /* MeshPacket.decoded */
	packet_len += put_varint(&packet[packet_len],
				 sizeof(packet) - packet_len, data_len);
	memcpy(&packet[packet_len], data, data_len);
	packet_len += data_len;
	packet[packet_len++] = 0x35; /* MeshPacket.id fixed32 */
	put_le32(&packet[packet_len], id);
	packet_len += 4U;

	zassert_true(packet_len <= cap - 1U);
	buf[pos++] = 0x0a; /* ToRadio.packet */
	pos += put_varint(&buf[pos], cap - pos, packet_len);
	zassert_true(packet_len <= cap - pos);
	memcpy(&buf[pos], packet, packet_len);
	pos += packet_len;

	return pos;
}

static void decode_queue_status(const uint8_t *buf, size_t len,
				struct queue_status_view *out)
{
	size_t pos = 0U;
	uint32_t key;
	uint32_t inner_len;
	size_t end;

	memset(out, 0, sizeof(*out));
	zassert_equal(read_varint(buf, len, &pos, &key), 0);
	zassert_equal(key, 0x5aU);
	zassert_equal(read_varint(buf, len, &pos, &inner_len), 0);
	zassert_true(inner_len <= len - pos);
	end = pos + inner_len;

	while (pos < end) {
		uint32_t value;

		zassert_equal(read_varint(buf, end, &pos, &key), 0);
		zassert_equal(read_varint(buf, end, &pos, &value), 0);
		switch (key) {
		case 0x08:
			out->res = value;
			out->has_res = true;
			break;
		case 0x10:
			out->free = value;
			break;
		case 0x18:
			out->maxlen = value;
			break;
		case 0x20:
			out->mesh_packet_id = value;
			out->has_mesh_packet_id = true;
			break;
		default:
			zassert_unreachable("unexpected queueStatus key");
		}
	}
}

static void decode_from_radio(const uint8_t *buf, size_t len,
			      struct from_radio_view *out)
{
	size_t pos = 0U;
	uint32_t key;
	uint32_t payload_len;

	memset(out, 0, sizeof(*out));
	zassert_equal(read_varint(buf, len, &pos, &key), 0);
	out->field = key >> 3;
	if ((key & 0x07U) == 2U) {
		zassert_equal(read_varint(buf, len, &pos, &payload_len), 0);
		zassert_true(payload_len <= len - pos);
		out->payload = &buf[pos];
		out->payload_len = payload_len;
	} else {
		zassert_equal(key & 0x07U, 0U);
		zassert_equal(read_varint(buf, len, &pos, &out->value), 0);
	}
}

static bool payload_get_len_field(const uint8_t *buf, size_t len, uint32_t field,
				  const uint8_t **value, size_t *value_len)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 ||
			    n > len - pos) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = &buf[pos];
				*value_len = n;
				return true;
			}
			pos += n;
		} else if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_has_string(const uint8_t *buf, size_t len, uint32_t field,
			       const char *value)
{
	const uint8_t *actual;
	size_t actual_len;
	size_t value_len = strlen(value);

	return payload_get_len_field(buf, len, field, &actual, &actual_len) &&
	       actual_len == value_len &&
	       memcmp(actual, value, value_len) == 0;
}

static bool payload_get_varint_field(const uint8_t *buf, size_t len,
				     uint32_t field, uint32_t *value)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = n;
				return true;
			}
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 ||
			    n > len - pos) {
				return false;
			}
			pos += n;
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_get_fixed32_field(const uint8_t *buf, size_t len,
				      uint32_t field, uint32_t *value)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = (uint32_t)buf[pos] |
					 ((uint32_t)buf[pos + 1U] << 8) |
					 ((uint32_t)buf[pos + 2U] << 16) |
					 ((uint32_t)buf[pos + 3U] << 24);
				return true;
			}
			pos += 4U;
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 ||
			    n > len - pos) {
				return false;
			}
			pos += n;
		} else if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else {
			return false;
		}
	}
	return false;
}

static void decode_client_packet(const uint8_t *buf, size_t len,
				 struct client_packet_view *out)
{
	const uint8_t *mesh = NULL;
	const uint8_t *data = NULL;
	size_t mesh_len = 0U;
	size_t data_len = 0U;
	size_t pos = 0U;
	uint32_t packet_count = 0U;

	memset(out, 0, sizeof(*out));
	while (pos < len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(buf, len, &pos, &key), 0);
		if (key == 0x12U) { /* FromRadio.packet */
			packet_count++;
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
			zassert_true(n <= len - pos);
			mesh = &buf[pos];
			mesh_len = n;
			pos += n;
		} else if ((key & 0x07U) == 0U) {
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
		} else if ((key & 0x07U) == 2U) {
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
			zassert_true(n <= len - pos);
			pos += n;
		} else if ((key & 0x07U) == 5U) {
			zassert_true(len - pos >= 4U);
			pos += 4U;
		} else {
			zassert_unreachable("unexpected FromRadio field");
		}
	}

	zassert_not_null(mesh);
	zassert_equal(packet_count, 1U);
	zassert_true(payload_get_fixed32_field(mesh, mesh_len, 1U, &out->from));
	out->has_from = true;
	zassert_true(payload_get_fixed32_field(mesh, mesh_len, 2U, &out->to));
	out->has_to = true;
	zassert_true(payload_get_fixed32_field(mesh, mesh_len, 6U, &out->id));
	out->has_id = true;
	zassert_true(payload_get_len_field(mesh, mesh_len, 4U, &data,
					   &data_len));
	zassert_true(payload_get_varint_field(data, data_len, 1U,
					      &out->portnum));
	out->has_portnum = true;
	if (payload_get_len_field(data, data_len, 2U, &out->app_payload,
				  &out->app_payload_len)) {
		/* optional application payload */
	}
	if (payload_get_fixed32_field(data, data_len, 6U, &out->request_id)) {
		out->has_request_id = true;
	}
}

ZTEST(meshtastic_gateway_adapter, test_emit_text_uses_current_ble_session)
{
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x17, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x06,
		0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x35, 0x88,
		0x77, 0x66, 0x55
	};
	struct gateway_inbound_text_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_text(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_inbound_text_has_client_visible_view)
{
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct client_packet_view view;
	struct gateway_inbound_text_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_text(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_client_packet(from_radio, from_radio_len, &view);
	zassert_true(view.has_from);
	zassert_equal(view.from, 0x11223344U);
	zassert_true(view.has_to);
	zassert_equal(view.to, 0x01020304U);
	zassert_true(view.has_id);
	zassert_equal(view.id, 0x55667788U);
	zassert_true(view.has_portnum);
	zassert_equal(view.portnum, 1U);
	zassert_not_null(view.app_payload);
	zassert_equal(view.app_payload_len, sizeof(payload));
	zassert_mem_equal(view.app_payload, payload, sizeof(payload));
}

ZTEST(meshtastic_gateway_adapter, test_emit_status_uses_current_ble_session)
{
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x18, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x07,
		0x08, 0x05, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x89, 0x77, 0x66, 0x55
	};
	struct gateway_inbound_status_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_status(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_inbound_status_has_client_visible_view)
{
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct client_packet_view view;
	struct gateway_inbound_status_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_status(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_client_packet(from_radio, from_radio_len, &view);
	zassert_true(view.has_from);
	zassert_equal(view.from, 0x11223344U);
	zassert_true(view.has_to);
	zassert_equal(view.to, 0x01020304U);
	zassert_true(view.has_id);
	zassert_equal(view.id, 0x55667789U);
	zassert_true(view.has_portnum);
	zassert_equal(view.portnum, 5U);
	zassert_true(view.has_request_id);
	zassert_equal(view.request_id, 0x12345678U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_status_backpressure_propagates)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_status_event status = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};

	reset_gateway(1U);
	zassert_equal(gateway_inbound_emit_text(&text), 0);
	zassert_equal(gateway_inbound_emit_status(&status), -ENOMEM);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_text_backpressure_propagates)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event first = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_text_event second = first;

	reset_gateway(1U);
	zassert_equal(gateway_inbound_emit_text(&first), 0);
	zassert_equal(gateway_inbound_emit_text(&second), -ENOMEM);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_rejects_inactive_ble_session)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_status_event status = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};

	reset_gateway(2U);
	fake_ble_meshtastic_set_connected(false);

	zassert_equal(gateway_inbound_emit_text(&text), -ENOTCONN);
	zassert_equal(gateway_inbound_emit_status(&status), -ENOTCONN);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_rejects_disconnect_during_enqueue)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(2U);
	fake_ble_meshtastic_disconnect_on_next_enqueue();

	zassert_equal(gateway_inbound_emit_text(&text), -ENOTCONN);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_inbound_rejects_null_events)
{
	reset_gateway(2U);

	zassert_equal(gateway_inbound_emit_text(NULL), -EINVAL);
	zassert_equal(gateway_inbound_emit_status(NULL), -EINVAL);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_adapter_wrappers_reject_null_events)
{
	reset_gateway(2U);

	zassert_equal(gateway_meshtastic_adapter_emit_text(NULL), -EINVAL);
	zassert_equal(gateway_meshtastic_adapter_emit_status(NULL), -EINVAL);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_coap_text_post_reaches_from_radio)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x17, 0x0d, 0x00, 0x00, 0x00,
		0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22, 0x06,
		0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x35, 0x01,
		0x00, 0x00, 0x00
	};

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), payload,
			  sizeof(payload));

	zassert_equal(gateway_inbound_text_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_coap_status_post_reaches_from_radio)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t payload[] = { 0x12, 0x34, 0x56, 0x78 };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x18, 0x0d, 0x00, 0x00, 0x00,
		0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22, 0x07,
		0x08, 0x05, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x01, 0x00, 0x00, 0x00
	};

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), payload,
			  sizeof(payload));

	zassert_equal(gateway_inbound_status_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_coap_invalid_payloads_are_bad_request)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t bad_status[] = { 0x12, 0x34, 0x56 };

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), NULL, 0U);
	zassert_equal(gateway_inbound_text_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_BAD_REQUEST);

	make_post_request(&request, req_buf, sizeof(req_buf), bad_status,
			  sizeof(bad_status));
	zassert_equal(gateway_inbound_status_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_process_once_dispatches_ble_write)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct queue_status_view status;

	reset_gateway(2U);
	zassert_ok(fake_ble_meshtastic_push_to_radio(heartbeat,
						     sizeof(heartbeat)));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_queue_status(from_radio, from_radio_len, &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_equal(status.free, 1U);
	zassert_equal(status.maxlen, 2U);
}

ZTEST(meshtastic_gateway_adapter,
      test_process_once_direct_text_submits_resolved_peer)
{
	static const uint8_t peer_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN] = {
		1, 2, 3, 4
	};
	const uint8_t expected_iid[] = {
		0x00, 0xaa, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
	};
	struct gateway_message_contract_text submitted;
	struct lichen_app_identity_peer peer = {
		.eui64 = { 0x02, 0xaa, 0, 0, 0x01, 0x02, 0x03, 0x04 },
		.has_public_key = true,
	};
	uint8_t to_radio[128];
	const uint8_t *from_radio;
	size_t to_radio_len;
	size_t from_radio_len;
	struct queue_status_view status;

	reset_gateway(2U);
	memcpy(peer.public_key, peer_key, sizeof(peer.public_key));
	zassert_ok(lichen_app_identity_upsert_peer(&peer));

	to_radio_len = build_text_to_radio_to(to_radio, sizeof(to_radio),
					      (const uint8_t *)"hello", 5U,
					      0x01020304U, 0x12345678U);
	zassert_ok(fake_ble_meshtastic_push_to_radio(to_radio, to_radio_len));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_ok(gateway_message_contract_pop_text(&submitted));
	zassert_equal(submitted.to, UINT32_MAX);
	zassert_true(submitted.has_to_iid);
	zassert_mem_equal(submitted.to_iid, expected_iid,
			  sizeof(expected_iid));
	zassert_mem_equal(submitted.payload, "hello", 5U);
	zassert_equal(submitted.payload_len, 5U);
	zassert_equal(gateway_message_contract_pop_text(&submitted), -ENOENT);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_queue_status(from_radio, from_radio_len, &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
}

ZTEST(meshtastic_gateway_adapter,
      test_process_once_direct_text_backpressure_is_unsupported)
{
	static const uint32_t accepted_ids[] = {
		0x12345678U, 0x12345679U, 0x1234567aU
	};
	BUILD_ASSERT(ARRAY_SIZE(accepted_ids) == TEST_MESSAGE_CONTRACT_QUEUE_DEPTH);
	static const uint8_t peer_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN] = {
		1, 2, 3, 4
	};
	struct gateway_message_contract_text submitted;
	struct lichen_app_identity_peer peer = {
		.eui64 = { 0x02, 0xaa, 0, 0, 0x01, 0x02, 0x03, 0x04 },
		.has_public_key = true,
	};
	uint8_t to_radio[128];
	const uint8_t *from_radio;
	size_t to_radio_len;
	size_t from_radio_len;
	struct queue_status_view status;

	reset_gateway(ARRAY_SIZE(accepted_ids) + 2U);
	memcpy(peer.public_key, peer_key, sizeof(peer.public_key));
	zassert_ok(lichen_app_identity_upsert_peer(&peer));

	for (size_t i = 0U; i < ARRAY_SIZE(accepted_ids); i++) {
		to_radio_len = build_text_to_radio_to(to_radio, sizeof(to_radio),
						      (const uint8_t *)"one",
						      3U, 0x01020304U,
						      accepted_ids[i]);
		zassert_ok(fake_ble_meshtastic_push_to_radio(to_radio,
							     to_radio_len));
		zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	}

	to_radio_len = build_text_to_radio_to(to_radio, sizeof(to_radio),
					      (const uint8_t *)"two", 3U,
					      0x01020304U, 0x1234567cU);
	zassert_ok(fake_ble_meshtastic_push_to_radio(to_radio, to_radio_len));
	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);

	for (size_t i = 0U; i < ARRAY_SIZE(accepted_ids); i++) {
		zassert_ok(gateway_message_contract_pop_text(&submitted));
		zassert_mem_equal(submitted.payload, "one", 3U);
	}
	zassert_equal(gateway_message_contract_pop_text(&submitted), -ENOENT);

	zassert_equal(fake_ble_meshtastic_from_radio_count(),
		      ARRAY_SIZE(accepted_ids) + 1U);
	for (size_t i = 0U; i < ARRAY_SIZE(accepted_ids); i++) {
		from_radio = fake_ble_meshtastic_from_radio(i, &from_radio_len);
		zassert_not_null(from_radio);
		decode_queue_status(from_radio, from_radio_len, &status);
		zassert_true(status.has_res);
		zassert_equal(status.res, 0U);
		zassert_true(status.has_mesh_packet_id);
		zassert_equal(status.mesh_packet_id, accepted_ids[i]);
	}

	from_radio = fake_ble_meshtastic_from_radio(ARRAY_SIZE(accepted_ids),
						    &from_radio_len);
	zassert_not_null(from_radio);
	decode_queue_status(from_radio, from_radio_len, &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x1234567cU);
}

ZTEST(meshtastic_gateway_adapter, test_process_once_without_ble_write_is_idle)
{
	reset_gateway(2U);

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter,
      test_process_once_disconnect_clears_ble_session_queues)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t disconnect[] = { 0x20, 0x01 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshtastic_push_to_radio(heartbeat,
						     sizeof(heartbeat)));
	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);

	zassert_ok(fake_ble_meshtastic_push_to_radio(disconnect,
						     sizeof(disconnect)));
	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_true(ble_meshtastic_session_active());
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 0);
}

ZTEST(meshtastic_gateway_adapter,
      test_want_config_node_info_omits_unknown_power_metrics)
{
	const uint8_t want_config_node_db[] = { 0x18, 0xad, 0x9e, 0x04 };
	const uint8_t *metrics = NULL;
	const uint8_t *position = NULL;
	size_t metrics_len = 0U;
	size_t position_len = 0U;
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct from_radio_view view;
	uint32_t value = 0U;

	reset_gateway(2U);
	zassert_ok(fake_ble_meshtastic_push_to_radio(want_config_node_db,
						     sizeof(want_config_node_db)));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 2U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_from_radio(from_radio, from_radio_len, &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 6U,
					   &metrics, &metrics_len));
	zassert_false(payload_get_varint_field(metrics, metrics_len, 1U,
					       &value));
	zassert_false(payload_get_fixed32_field(metrics, metrics_len, 2U,
					       &value));
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U,
					      &value));
	zassert_false(payload_get_len_field(view.payload, view.payload_len, 3U,
					    &position, &position_len));
}

ZTEST(meshtastic_gateway_adapter,
      test_want_config_node_info_encodes_valid_power_metrics)
{
	const uint8_t want_config_node_db[] = { 0x18, 0xad, 0x9e, 0x04 };
	const struct lichen_hal_power_snapshot power = {
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = true,
		.battery_percent = 77U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = 3700U,
		.external_power_valid = true,
		.external_power = false,
	};
	const struct lichen_hal_location_time_snapshot location_time = {
		.location_provider_available = true,
		.time_provider_available = true,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.fix_source_valid = true,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
	};
	const uint8_t *metrics = NULL;
	const uint8_t *position = NULL;
	size_t metrics_len = 0U;
	size_t position_len = 0U;
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct from_radio_view view;
	uint32_t value = 0U;

	reset_gateway(2U);
	gateway_meshtastic_adapter_test_set_power_snapshot(&power);
	gateway_meshtastic_adapter_test_set_location_time_snapshot(&location_time);
	zassert_ok(fake_ble_meshtastic_push_to_radio(want_config_node_db,
						     sizeof(want_config_node_db)));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 2U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_from_radio(from_radio, from_radio_len, &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 6U,
					   &metrics, &metrics_len));
	zassert_true(payload_get_varint_field(metrics, metrics_len, 1U,
					      &value));
	zassert_equal(value, 77U);
	zassert_true(payload_get_fixed32_field(metrics, metrics_len, 2U,
					       &value));
	zassert_equal(value, 0x406ccccdU);
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U,
					      &value));
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 3U,
					   &position, &position_len));
	zassert_true(payload_get_fixed32_field(position, position_len, 1U,
					       &value));
	zassert_equal(value, 476206130U);
	zassert_true(payload_get_fixed32_field(position, position_len, 2U,
					       &value));
	zassert_equal(value, (uint32_t)-1223493000);
	zassert_true(payload_get_varint_field(position, position_len, 3U,
					      &value));
	zassert_equal(value, 42U);
	zassert_true(payload_get_fixed32_field(position, position_len, 4U,
					       &value));
	zassert_equal(value, 1710000000U);
	zassert_true(payload_get_varint_field(position, position_len, 5U,
					      &value));
	zassert_equal(value, 2U);
	zassert_true(payload_get_varint_field(position, position_len, 19U,
					      &value));
	zassert_equal(value, 9U);
}

ZTEST(meshtastic_gateway_adapter,
      test_want_config_node_info_uses_wall_clock_time_fallback)
{
	const uint8_t want_config_node_db[] = { 0x18, 0xad, 0x9e, 0x04 };
	const struct lichen_hal_location_time_snapshot location_time = {
		.location_provider_available = true,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.fix_source_valid = true,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
	};
	const struct lichen_hal_time_snapshot time = {
		.provider_available = true,
		.wall_clock_valid = true,
		.unix_time_valid = true,
		.unix_time = 1710000200U,
	};
	const uint8_t *position = NULL;
	size_t position_len = 0U;
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct from_radio_view view;
	uint32_t value = 0U;

	reset_gateway(2U);
	gateway_meshtastic_adapter_test_set_location_time_snapshot(&location_time);
	gateway_meshtastic_adapter_test_set_time_snapshot(&time);
	zassert_ok(fake_ble_meshtastic_push_to_radio(want_config_node_db,
						     sizeof(want_config_node_db)));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 2U);
	from_radio = fake_ble_meshtastic_from_radio(0U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_from_radio(from_radio, from_radio_len, &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 3U,
					   &position, &position_len));
	zassert_true(payload_get_fixed32_field(position, position_len, 4U,
					       &value));
	zassert_equal(value, 1710000200U);
}

ZTEST(meshtastic_gateway_adapter,
      test_want_config_node_info_includes_app_identity_peer)
{
	const uint8_t want_config_node_db[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct lichen_app_identity_peer peer = {
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x42 },
		.display_name = "identity-peer",
		.has_public_key = true,
		.hop_distance = 3U,
		.has_hop_distance = true,
	};
	const uint8_t *user = NULL;
	size_t user_len = 0U;
	const uint8_t *from_radio;
	size_t from_radio_len;
	struct from_radio_view view;
	uint32_t value = 0U;

	memset(peer.public_key, 0x42, sizeof(peer.public_key));

	reset_gateway(3U);
	zassert_ok(lichen_app_identity_upsert_peer(&peer));
	zassert_ok(fake_ble_meshtastic_push_to_radio(want_config_node_db,
						     sizeof(want_config_node_db)));

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), 1);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 3U);
	from_radio = fake_ble_meshtastic_from_radio(1U, &from_radio_len);
	zassert_not_null(from_radio);
	decode_from_radio(from_radio, from_radio_len, &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 1U,
					      &value));
	zassert_equal(value, 0x42U);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 2U,
					   &user, &user_len));
	zassert_true(payload_has_string(user, user_len, 2U, "identity-peer"));
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 9U,
					      &value));
	zassert_equal(value, 3U);
}

ZTEST(meshtastic_gateway_adapter, test_process_once_drops_stale_response)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshtastic_push_to_radio(heartbeat,
						     sizeof(heartbeat)));
	fake_ble_meshtastic_disconnect_on_next_enqueue();

	zassert_equal(gateway_meshtastic_adapter_test_process_once(), -ENOTCONN);
	zassert_false(ble_meshtastic_session_active());
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST_SUITE(meshtastic_gateway_adapter, NULL, NULL, NULL, NULL, NULL);
