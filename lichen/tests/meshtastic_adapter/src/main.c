/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/codec.h>

#define GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN \
	CONFIG_LORA_LICHEN_MESHTASTIC_BLE_QUEUE_DEPTH_MIN
#define GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS \
	CONFIG_LICHEN_MESHTASTIC_NODEDB_MAX_PEERS
#define TEST_FROM_RADIO_OUT_CAP GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN

BUILD_ASSERT(GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN >=
	     1U + LICHEN_MESHTASTIC_FULL_SYNC_RECORDS(
		     GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS));

struct test_ctx {
	uint8_t out[TEST_FROM_RADIO_OUT_CAP][LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	size_t out_len[TEST_FROM_RADIO_OUT_CAP];
	size_t out_count;
	size_t out_cap;
	uint32_t reported_queue_free;
	bool has_reported_queue_free;
	struct lichen_meshtastic_peer_snapshot peers[4];
	size_t peer_count;
	uint32_t text_count;
	uint32_t position_count;
	uint32_t last_text_from;
	uint32_t last_text_to;
	uint32_t last_text_id;
	uint32_t last_text_channel;
	uint8_t last_text_to_iid[8];
	size_t last_text_len;
	bool last_text_has_from;
	bool last_text_has_to;
	bool last_text_has_channel;
	bool last_text_has_to_peer;
	bool last_text_want_ack;
	struct lichen_meshtastic_position_snapshot last_position;
	const char *firmware_version;
};

static uint8_t s_last_text_payload[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX];
static uint8_t s_text_packet[LICHEN_MESHTASTIC_TO_RADIO_MAX];

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

struct text_packet_view {
	uint32_t from_radio_id;
	uint32_t from;
	uint32_t to;
	uint32_t id;
	const uint8_t *payload;
	size_t payload_len;
};

struct status_packet_view {
	uint32_t from_radio_id;
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_error_reason;
};

struct admin_metadata_packet_view {
	uint32_t from_radio_id;
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	const uint8_t *metadata;
	size_t metadata_len;
	bool has_request_id;
};

struct node_info_view {
	uint32_t num;
	uint32_t hops_away;
	const uint8_t *user;
	size_t user_len;
	bool has_num;
	bool has_user;
	bool has_hops_away;
};

static int test_enqueue(const uint8_t *from_radio, size_t len, void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (ctx->out_count == ctx->out_cap) {
		return -ENOMEM;
	}
	if (len > sizeof(ctx->out[0])) {
		return -EMSGSIZE;
	}

	memcpy(ctx->out[ctx->out_count], from_radio, len);
	ctx->out_len[ctx->out_count] = len;
	ctx->out_count++;
	return 0;
}

static int test_text(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct test_ctx *ctx = user_data;

	ctx->text_count++;
	ctx->last_text_from = packet->from;
	ctx->last_text_to = packet->to;
	ctx->last_text_id = packet->id;
	ctx->last_text_channel = packet->channel;
	ctx->last_text_len = packet->payload_len;
	ctx->last_text_has_from = packet->has_from;
	ctx->last_text_has_to = packet->has_to;
	ctx->last_text_has_channel = packet->has_channel;
	ctx->last_text_has_to_peer = packet->has_to_peer;
	if (packet->has_to_peer) {
		memcpy(ctx->last_text_to_iid, packet->to_iid,
		       sizeof(ctx->last_text_to_iid));
	}
	ctx->last_text_want_ack = packet->want_ack;
	zassert_true(packet->payload_len <= sizeof(s_last_text_payload));
	memcpy(s_last_text_payload, packet->payload, packet->payload_len);
	return 0;
}

static int test_text_unsupported(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct test_ctx *ctx = user_data;

	ctx->text_count++;
	ctx->last_text_id = packet->id;
	return -ENOTSUP;
}

static int test_location(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct test_ctx *ctx = user_data;

	ctx->position_count++;
	ctx->last_position = packet->position;
	return 0;
}

static int test_location_unsupported(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct test_ctx *ctx = user_data;

	ARG_UNUSED(packet);
	ctx->position_count++;
	return -ENOTSUP;
}

static uint32_t test_queue_free(void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (ctx->has_reported_queue_free) {
		return ctx->reported_queue_free;
	}
	return ctx->out_cap - ctx->out_count;
}

static int test_local_info(struct lichen_meshtastic_local_info *info,
			   void *user_data);
static size_t test_get_peers(struct lichen_meshtastic_peer_snapshot *peers,
			     size_t peer_cap, void *user_data);

static void init_adapter(struct lichen_meshtastic_adapter *adapter,
			 struct test_ctx *ctx, size_t out_cap)
{
	struct lichen_meshtastic_adapter_ops ops = {
			.enqueue_from_radio = test_enqueue,
			.handle_text = test_text,
			.handle_location = test_location,
			.get_local_info = test_local_info,
		.get_peers = test_get_peers,
		.user_data = ctx,
		.queue_maxlen = 8U,
		.heartbeat_queue_status = true,
	};

	memset(ctx, 0, sizeof(*ctx));
	memset(s_last_text_payload, 0, sizeof(s_last_text_payload));
	ctx->out_cap = out_cap;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

static void init_adapter_without_text_hook(struct lichen_meshtastic_adapter *adapter,
					   struct test_ctx *ctx,
					   size_t out_cap)
{
	struct lichen_meshtastic_adapter_ops ops = {
			.enqueue_from_radio = test_enqueue,
			.get_local_info = test_local_info,
		.get_peers = test_get_peers,
		.user_data = ctx,
		.queue_maxlen = 8U,
		.heartbeat_queue_status = true,
	};

	memset(ctx, 0, sizeof(*ctx));
	memset(s_last_text_payload, 0, sizeof(s_last_text_payload));
	ctx->out_cap = out_cap;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

static void init_adapter_with_unsupported_text_hook(
	struct lichen_meshtastic_adapter *adapter,
	struct test_ctx *ctx, size_t out_cap)
{
	struct lichen_meshtastic_adapter_ops ops = {
			.enqueue_from_radio = test_enqueue,
			.handle_text = test_text_unsupported,
			.handle_location = test_location,
			.get_local_info = test_local_info,
		.get_peers = test_get_peers,
		.user_data = ctx,
		.queue_maxlen = 8U,
		.heartbeat_queue_status = true,
	};

	memset(ctx, 0, sizeof(*ctx));
	memset(s_last_text_payload, 0, sizeof(s_last_text_payload));
	ctx->out_cap = out_cap;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

static void init_adapter_with_queue_free(struct lichen_meshtastic_adapter *adapter,
					 struct test_ctx *ctx, size_t out_cap)
{
	struct lichen_meshtastic_adapter_ops ops = {
			.enqueue_from_radio = test_enqueue,
			.handle_text = test_text,
			.handle_location = test_location,
			.queue_free = test_queue_free,
		.get_local_info = test_local_info,
		.get_peers = test_get_peers,
		.user_data = ctx,
		.queue_maxlen = out_cap,
		.heartbeat_queue_status = true,
	};

	memset(ctx, 0, sizeof(*ctx));
	memset(s_last_text_payload, 0, sizeof(s_last_text_payload));
	ctx->out_cap = out_cap;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

static void set_default_max_peers(struct test_ctx *ctx)
{
	ctx->peer_count = GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS;
	for (size_t i = 0U; i < ctx->peer_count; i++) {
		ctx->peers[i] = (struct lichen_meshtastic_peer_snapshot){
			.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0,
				   (uint8_t)(i + 1U) },
		};
	}
}

static void expect_bytes(const uint8_t *actual, size_t actual_len,
			 const uint8_t *expected, size_t expected_len)
{
	zassert_equal(actual_len, expected_len, "unexpected encoded length");
	zassert_mem_equal(actual, expected, expected_len, "unexpected encoded bytes");
}

static void decode_from_radio(const uint8_t *buf, size_t len,
			      struct from_radio_view *out);
static bool payload_has_string(const uint8_t *buf, size_t len, uint32_t field,
			       const char *value);
static bool payload_get_varint_field(const uint8_t *buf, size_t len,
				     uint32_t field, uint32_t *value);
static bool payload_get_len_field(const uint8_t *buf, size_t len,
				  uint32_t field, const uint8_t **value,
				  size_t *value_len);
static size_t put_varint(uint8_t *buf, size_t cap, uint64_t value);
static size_t build_position_payload_with_metadata(
	uint8_t *buf, size_t cap, bool altitude, bool time, uint32_t time_value,
	bool timestamp, uint32_t timestamp_value, bool sats,
	bool location_source, uint32_t location_source_value,
	bool altitude_source, uint32_t altitude_source_value,
	bool gps_accuracy, uint32_t gps_accuracy_value,
	bool precision_bits, uint32_t precision_bits_value);
static size_t build_app_to_radio(uint8_t *buf, size_t cap, uint32_t portnum,
				 const uint8_t *payload, size_t payload_len,
				 uint32_t id);
static size_t build_text_to_radio_to(uint8_t *buf, size_t cap,
				     const uint8_t *payload,
				     size_t payload_len, uint32_t to,
				     uint32_t id);
static size_t build_text_to_radio(uint8_t *buf, size_t cap,
				  const uint8_t *payload, size_t payload_len,
				  uint32_t id);

static int test_local_info(struct lichen_meshtastic_local_info *info,
			   void *user_data)
{
	static const uint8_t device_id[] = {
		0x02, 0x00, 0x00, 0xff, 0xaa, 0xbb, 0xcc, 0xdd
	};
	struct test_ctx *ctx = user_data;

	memset(info, 0, sizeof(*info));
	info->node_num = 0xaabbccddU;
	info->min_app_version = 30200U;
	info->nodedb_count = 1U;
	info->uptime_seconds = 123U;
	info->long_name = "LICHEN native_sim";
	info->short_name = "LICH";
	info->firmware_version = ctx->firmware_version != NULL ?
					 ctx->firmware_version :
					 "LICHEN test 0.0.0";
	info->pio_env = "zephyr-native_sim";
	info->device_id = device_id;
	info->device_id_len = sizeof(device_id);
	info->has_bluetooth = true;
	info->has_lora = true;
	info->has_tx_power_dbm = true;
	info->tx_power_dbm = 14;
	return 0;
}

static size_t test_get_peers(struct lichen_meshtastic_peer_snapshot *peers,
			     size_t peer_cap, void *user_data)
{
	struct test_ctx *ctx = user_data;
	size_t count;

	if (peers == NULL || peer_cap == 0U) {
		return 0U;
	}

	count = MIN(ctx->peer_count, peer_cap);
	memcpy(peers, ctx->peers, count * sizeof(peers[0]));
	return count;
}

ZTEST(meshtastic_adapter, test_unbranded_firmware_version_uses_lichen_default)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	uint32_t excluded_modules = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "LICHEN mEsHtAsTiC 2.7.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_true(ctx.out_count > 1U);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(view.payload, view.payload_len, 1U,
					 "LICHEN mEsHtAsTiC 2.7.0"));
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 9U,
					      &excluded_modules));
	zassert_equal(excluded_modules, 255U);
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 12U,
					      &excluded_modules));
	zassert_equal(excluded_modules, 0x5fff);
}

ZTEST(meshtastic_adapter, test_firmware_version_requires_lichen_prefix)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "NOTLICHEN compat 1.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(view.payload, view.payload_len, 1U,
					 "NOTLICHEN compat 1.0"));

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "LICHEN compat 1.0+board";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN compat 1.0+board"));
}

static void decode_admin_metadata_from_radio(
	const uint8_t *buf, size_t len,
	struct admin_metadata_packet_view *out);

ZTEST(meshtastic_adapter, test_admin_get_device_metadata_returns_metadata_packet)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t get_metadata[] = { 0x60, 0x01 };
	struct admin_metadata_packet_view packet;
	uint32_t value = 0U;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, get_metadata,
					  sizeof(get_metadata), 0x12345690U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(ctx.text_count, 0U);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.from, 0xaabbccddU);
	zassert_equal(packet.to, 0xffffffffU);
	zassert_equal(packet.id, 1U);
	zassert_true(packet.has_request_id);
	zassert_equal(packet.request_id, 0x12345690U);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN test 0.0.0"));
	zassert_true(payload_get_varint_field(packet.metadata, packet.metadata_len,
					      9U, &value));
	zassert_equal(value, 255U);
	zassert_true(payload_get_varint_field(packet.metadata, packet.metadata_len,
					      12U, &value));
	zassert_equal(value, 0x5fff);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->packet_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_admin_metadata_reuses_firmware_brand_policy)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t get_metadata[] = { 0x60, 0x01 };
	struct admin_metadata_packet_view packet;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, get_metadata,
					  sizeof(get_metadata), 0x12345691U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "LICHEN mEsHtAsTiC 2.7.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);
	zassert_equal(ret, 0);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					 "LICHEN mEsHtAsTiC 2.7.0"));

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "NOTLICHEN compat 1.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);
	zassert_equal(ret, 0);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					 "NOTLICHEN compat 1.0"));
}

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
	static uint8_t data[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 16U];
	static uint8_t packet[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	size_t data_len = 0U;
	size_t packet_len = 0U;
	size_t pos = 0U;

	zassert_true(payload_len <= LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U);
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
	packet[packet_len++] = 0x50; /* MeshPacket.want_ack */
	packet[packet_len++] = 0x01;

	zassert_true(packet_len <= cap - 1U);
	buf[pos++] = 0x0a; /* ToRadio.packet */
	pos += put_varint(&buf[pos], cap - pos, packet_len);
	zassert_true(packet_len <= cap - pos);
	memcpy(&buf[pos], packet, packet_len);
	pos += packet_len;

	return pos;
}

static size_t build_text_to_radio(uint8_t *buf, size_t cap,
				  const uint8_t *payload, size_t payload_len,
				  uint32_t id)
{
	return build_text_to_radio_to(buf, cap, payload, payload_len,
				      0xffffffffU, id);
}

static size_t build_position_payload(uint8_t *buf, size_t cap, bool altitude,
				     bool time, bool timestamp, bool sats)
{
	return build_position_payload_with_metadata(buf, cap, altitude, time,
						    1710000000U, timestamp,
						    1710000200U, sats, false,
						    0U, false, 0U, false, 0U,
						    false, 0U);
}

static size_t build_position_payload_with_metadata(
	uint8_t *buf, size_t cap, bool altitude, bool time, uint32_t time_value,
	bool timestamp, uint32_t timestamp_value, bool sats, bool location_source,
	uint32_t location_source_value, bool altitude_source,
	uint32_t altitude_source_value, bool gps_accuracy,
	uint32_t gps_accuracy_value, bool precision_bits,
	uint32_t precision_bits_value)
{
	size_t pos = 0U;

	zassert_true(cap >= 10U);
	buf[pos++] = 0x0d; /* Position.latitude_i fixed32 */
	put_le32(&buf[pos], 476206130U);
	pos += 4U;
	buf[pos++] = 0x15; /* Position.longitude_i fixed32 */
	put_le32(&buf[pos], (uint32_t)-1223493000);
	pos += 4U;
	if (altitude) {
		buf[pos++] = 0x18; /* Position.altitude int32 */
		pos += put_varint(&buf[pos], cap - pos, 42U);
	}
	if (time) {
		buf[pos++] = 0x25; /* Position.time fixed32 */
		put_le32(&buf[pos], time_value);
		pos += 4U;
	}
	if (location_source) {
		buf[pos++] = 0x28; /* Position.location_source */
		pos += put_varint(&buf[pos], cap - pos, location_source_value);
	}
	if (altitude_source) {
		buf[pos++] = 0x30; /* Position.altitude_source */
		pos += put_varint(&buf[pos], cap - pos, altitude_source_value);
	}
	if (timestamp) {
		buf[pos++] = 0x3d; /* Position.timestamp fixed32 */
		put_le32(&buf[pos], timestamp_value);
		pos += 4U;
	}
	if (gps_accuracy) {
		buf[pos++] = 0x70; /* Position.gps_accuracy */
		pos += put_varint(&buf[pos], cap - pos, gps_accuracy_value);
	}
	if (sats) {
		buf[pos++] = 0x98; /* Position.sats_in_view */
		buf[pos++] = 0x01;
		pos += put_varint(&buf[pos], cap - pos, 9U);
	}
	if (precision_bits) {
		buf[pos++] = 0xb8; /* Position.precision_bits */
		buf[pos++] = 0x01;
		pos += put_varint(&buf[pos], cap - pos, precision_bits_value);
	}

	return pos;
}

static size_t build_negative_altitude_position_payload(uint8_t *buf, size_t cap)
{
	size_t pos = build_position_payload(buf, cap, false, false, false, false);

	zassert_true(cap - pos >= 11U);
	buf[pos++] = 0x18; /* Position.altitude int32 */
	pos += put_varint(&buf[pos], cap - pos, (uint64_t)(int64_t)-17);
	return pos;
}

static size_t build_oversized_sats_position_payload(uint8_t *buf, size_t cap)
{
	size_t pos = build_position_payload(buf, cap, false, false, false, false);

	zassert_true(cap - pos >= 4U);
	buf[pos++] = 0x98; /* Position.sats_in_view */
	buf[pos++] = 0x01;
	pos += put_varint(&buf[pos], cap - pos, 300U);
	return pos;
}

static size_t build_app_to_radio(uint8_t *buf, size_t cap, uint32_t portnum,
				 const uint8_t *payload, size_t payload_len,
				 uint32_t id)
{
	static uint8_t data[64];
	static uint8_t packet[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	size_t data_len = 0U;
	size_t packet_len = 0U;
	size_t pos = 0U;

	zassert_true(payload_len <= sizeof(data) - 16U);

	data[data_len++] = 0x08; /* Data.portnum */
	data_len += put_varint(&data[data_len], sizeof(data) - data_len, portnum);
	data[data_len++] = 0x12; /* Data.payload */
	data_len += put_varint(&data[data_len], sizeof(data) - data_len,
			       payload_len);
	memcpy(&data[data_len], payload, payload_len);
	data_len += payload_len;

	packet[packet_len++] = 0x15; /* MeshPacket.to fixed32 */
	put_le32(&packet[packet_len], 0xffffffffU);
	packet_len += 4U;
	packet[packet_len++] = 0x22; /* MeshPacket.decoded */
	packet_len += put_varint(&packet[packet_len],
				 sizeof(packet) - packet_len, data_len);
	memcpy(&packet[packet_len], data, data_len);
	packet_len += data_len;
	packet[packet_len++] = 0x35; /* MeshPacket.id fixed32 */
	put_le32(&packet[packet_len], id);
	packet_len += 4U;
	packet[packet_len++] = 0x50; /* MeshPacket.want_ack */
	packet[packet_len++] = 0x01;

	zassert_true(packet_len <= cap - 1U);
	buf[pos++] = 0x0a; /* ToRadio.packet */
	pos += put_varint(&buf[pos], cap - pos, packet_len);
	zassert_true(packet_len <= cap - pos);
	memcpy(&buf[pos], packet, packet_len);
	pos += packet_len;

	return pos;
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

static bool payload_has_string(const uint8_t *buf, size_t len, uint32_t field,
			       const char *value)
{
	size_t pos = 0U;
	size_t value_len = strlen(value);

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			if ((key >> 3) == field && n == value_len &&
			    memcmp(&buf[pos], value, value_len) == 0) {
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
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
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
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
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

static bool payload_count_fields(const uint8_t *buf, size_t len, uint8_t *counts,
				 size_t counts_len)
{
	size_t pos = 0U;

	memset(counts, 0, counts_len);
	while (pos < len) {
		uint32_t key;
		uint32_t field;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		field = key >> 3;
		if (field == 0U || field >= counts_len ||
		    counts[field] == UINT8_MAX) {
			return false;
		}
		counts[field]++;
		if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
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
	return true;
}

static uint32_t get_le32(const uint8_t *buf);

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
				*value = get_le32(&buf[pos]);
				return true;
			}
			pos += 4U;
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
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

static uint32_t get_le32(const uint8_t *buf)
{
	return (uint32_t)buf[0] |
	       ((uint32_t)buf[1] << 8) |
	       ((uint32_t)buf[2] << 16) |
	       ((uint32_t)buf[3] << 24);
}

static void decode_node_info_payload(const uint8_t *buf, size_t len,
				     struct node_info_view *out)
{
	memset(out, 0, sizeof(*out));
	out->has_num = payload_get_varint_field(buf, len, 1U, &out->num);
	out->has_user = payload_get_len_field(buf, len, 2U, &out->user,
					      &out->user_len);
	out->has_hops_away = payload_get_varint_field(buf, len, 9U,
						      &out->hops_away);
}

static void decode_text_from_radio(const uint8_t *buf, size_t len,
				   struct text_packet_view *out)
{
	const uint8_t *mesh_packet = NULL;
	size_t mesh_packet_len = 0U;
	const uint8_t *data = NULL;
	size_t data_len = 0U;
	size_t pos = 0U;
	uint32_t portnum = 0U;

	memset(out, 0, sizeof(*out));
	while (pos < len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(buf, len, &pos, &key), 0);
		switch (key) {
		case 0x08:
			zassert_equal(read_varint(buf, len, &pos,
						  &out->from_radio_id),
				      0);
			break;
		case 0x12:
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
			zassert_true(n <= len - pos);
			mesh_packet = &buf[pos];
			mesh_packet_len = n;
			pos += n;
			break;
		default:
			zassert_unreachable("unexpected FromRadio field");
		}
	}

	zassert_not_null(mesh_packet);
	pos = 0U;
	while (pos < mesh_packet_len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(mesh_packet, mesh_packet_len, &pos,
					  &key), 0);
		switch (key) {
		case 0x0d:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->from = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x15:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->to = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x22:
			zassert_equal(read_varint(mesh_packet, mesh_packet_len,
						  &pos, &n), 0);
			zassert_true(n <= mesh_packet_len - pos);
			data = &mesh_packet[pos];
			data_len = n;
			pos += n;
			break;
		case 0x35:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->id = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		default:
			zassert_unreachable("unexpected MeshPacket field");
		}
	}

	zassert_not_null(data);
	zassert_true(payload_get_varint_field(data, data_len, 1U, &portnum));
	zassert_equal(portnum, 1U);
	zassert_true(payload_get_len_field(data, data_len, 2U, &out->payload,
					   &out->payload_len));
}

static void decode_status_from_radio(const uint8_t *buf, size_t len,
				     struct status_packet_view *out)
{
	const uint8_t *mesh_packet = NULL;
	size_t mesh_packet_len = 0U;
	const uint8_t *data = NULL;
	size_t data_len = 0U;
	const uint8_t *routing = NULL;
	size_t routing_len = 0U;
	size_t pos = 0U;
	uint32_t portnum = 0U;

	memset(out, 0, sizeof(*out));
	while (pos < len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(buf, len, &pos, &key), 0);
		switch (key) {
		case 0x08:
			zassert_equal(read_varint(buf, len, &pos,
						  &out->from_radio_id),
				      0);
			break;
		case 0x12:
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
			zassert_true(n <= len - pos);
			mesh_packet = &buf[pos];
			mesh_packet_len = n;
			pos += n;
			break;
		default:
			zassert_unreachable("unexpected FromRadio field");
		}
	}

	zassert_not_null(mesh_packet);
	pos = 0U;
	while (pos < mesh_packet_len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(mesh_packet, mesh_packet_len, &pos,
					  &key), 0);
		switch (key) {
		case 0x0d:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->from = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x15:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->to = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x22:
			zassert_equal(read_varint(mesh_packet, mesh_packet_len,
						  &pos, &n), 0);
			zassert_true(n <= mesh_packet_len - pos);
			data = &mesh_packet[pos];
			data_len = n;
			pos += n;
			break;
		case 0x35:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->id = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		default:
			zassert_unreachable("unexpected MeshPacket field");
		}
	}

	zassert_not_null(data);
	zassert_true(payload_get_varint_field(data, data_len, 1U, &portnum));
	zassert_equal(portnum, 5U);
	zassert_true(payload_get_fixed32_field(data, data_len, 6U,
					       &out->request_id));
	if (payload_get_len_field(data, data_len, 2U, &routing, &routing_len)) {
		out->has_error_reason = true;
		zassert_true(payload_get_varint_field(routing, routing_len, 3U,
						      &out->error_reason));
	}
}

static void decode_admin_metadata_from_radio(
	const uint8_t *buf, size_t len,
	struct admin_metadata_packet_view *out)
{
	const uint8_t *mesh_packet = NULL;
	size_t mesh_packet_len = 0U;
	const uint8_t *data = NULL;
	size_t data_len = 0U;
	const uint8_t *admin = NULL;
	size_t admin_len = 0U;
	size_t pos = 0U;
	uint32_t portnum = 0U;

	memset(out, 0, sizeof(*out));
	while (pos < len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(buf, len, &pos, &key), 0);
		switch (key) {
		case 0x08:
			zassert_equal(read_varint(buf, len, &pos,
						  &out->from_radio_id),
				      0);
			break;
		case 0x12:
			zassert_equal(read_varint(buf, len, &pos, &n), 0);
			zassert_true(n <= len - pos);
			mesh_packet = &buf[pos];
			mesh_packet_len = n;
			pos += n;
			break;
		default:
			zassert_unreachable("unexpected FromRadio field");
		}
	}

	zassert_not_null(mesh_packet);
	pos = 0U;
	while (pos < mesh_packet_len) {
		uint32_t key;
		uint32_t n;

		zassert_equal(read_varint(mesh_packet, mesh_packet_len, &pos,
					  &key), 0);
		switch (key) {
		case 0x0d:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->from = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x15:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->to = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		case 0x22:
			zassert_equal(read_varint(mesh_packet, mesh_packet_len,
						  &pos, &n), 0);
			zassert_true(n <= mesh_packet_len - pos);
			data = &mesh_packet[pos];
			data_len = n;
			pos += n;
			break;
		case 0x35:
			zassert_true(mesh_packet_len - pos >= 4U);
			out->id = get_le32(&mesh_packet[pos]);
			pos += 4U;
			break;
		default:
			zassert_unreachable("unexpected MeshPacket field");
		}
	}

	zassert_not_null(data);
	zassert_true(payload_get_varint_field(data, data_len, 1U, &portnum));
	zassert_equal(portnum, 6U);
	if (payload_get_fixed32_field(data, data_len, 6U, &out->request_id)) {
		out->has_request_id = true;
	}
	zassert_true(payload_get_len_field(data, data_len, 2U, &admin,
					   &admin_len));
	zassert_true(payload_get_len_field(admin, admin_len, 13U,
					   &out->metadata, &out->metadata_len));
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

ZTEST(meshtastic_adapter, test_heartbeat_queues_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_equal(status.free, 7U);
	zassert_equal(status.maxlen, 8U);
	zassert_false(status.has_mesh_packet_id);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_69420_queues_stage1_sequence)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xac, 0x9e, 0x04 };
	const uint32_t fields[] = {
		LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO,
		LICHEN_MESHTASTIC_FROM_RADIO_METADATA,
		LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS,
		LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG,
		7U,
	};
	const uint32_t config_fields[] = {
		1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 10U,
	};
	uint8_t counts[12];
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, ARRAY_SIZE(fields));
	for (size_t i = 0U; i < ARRAY_SIZE(fields); i++) {
		struct from_radio_view view;

		decode_from_radio(ctx.out[i], ctx.out_len[i], &view);
		zassert_equal(view.field, fields[i], "field[%u]", (uint32_t)i);
		if (i >= 4U && i < 4U + ARRAY_SIZE(config_fields)) {
			zassert_true(payload_count_fields(view.payload,
							  view.payload_len,
							  counts,
							  ARRAY_SIZE(counts)));
			for (size_t field = 1U; field < ARRAY_SIZE(counts); field++) {
				zassert_equal(
					counts[field],
					field == config_fields[i - 4U] ? 1U : 0U,
					"config[%u] field %u count %u",
					(uint32_t)(i - 4U), (uint32_t)field,
					counts[field]);
			}
		}
	}
	expect_bytes(ctx.out[ARRAY_SIZE(fields) - 1U],
		     ctx.out_len[ARRAY_SIZE(fields) - 1U], complete,
		     sizeof(complete));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->want_config_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_my_info_nodedb_count_tracks_peer_snapshot)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	uint32_t value = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = ARRAY_SIZE(ctx.peers);
	for (size_t i = 0U; i < ctx.peer_count; i++) {
		ctx.peers[i] = (struct lichen_meshtastic_peer_snapshot){
			.eui64 = {
				0x02, 0xaa, 0, 0, 0, 0, 0, (uint8_t)(i + 1U),
			},
		};
	}

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO);
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 15U,
					      &value));
	zassert_equal(value, 1U + GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS);
}

ZTEST(meshtastic_adapter, test_want_config_69420_preflights_queue_free)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint32_t expected_count = LICHEN_MESHTASTIC_STATIC_SYNC_RECORDS +
				  LICHEN_MESHTASTIC_CONFIG_COMPLETE_RECORDS;
	struct from_radio_view view;
	int ret;

	init_adapter_with_queue_free(&adapter, &ctx, expected_count);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, expected_count);
	decode_from_radio(ctx.out[expected_count - 1U],
			  ctx.out_len[expected_count - 1U], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[expected_count - 1U],
		     ctx.out_len[expected_count - 1U], complete, sizeof(complete));

	init_adapter_with_queue_free(&adapter, &ctx, expected_count);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_69421_queues_node_db_sequence)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 2U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_true(node.has_num);
	zassert_equal(node.num, 0xaabbccddU);
	zassert_true(node.has_user);
	zassert_true(payload_has_string(node.user, node.user_len, 2U,
					"LICHEN native_sim"));
	zassert_true(payload_has_string(node.user, node.user_len, 3U, "LICH"));
	zassert_true(node.has_hops_away);
	zassert_equal(node.hops_away, 0U);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[1], ctx.out_len[1], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_69421_queues_self_then_peers)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	uint32_t expected_nums[] = {
		0xaabbccddU, 0x00000011U, 0x00000022U,
	};
	const char *expected_names[] = {
		"LICHEN native_sim", "peer-a", "peer-b",
	};
	uint32_t expected_hops[] = { 0U, 1U, 2U };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x22 },
		.long_name = "peer-b",
		.hop_distance = 2U,
		.has_long_name = true,
		.has_hop_distance = true,
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x11 },
		.long_name = "peer-a",
		.hop_distance = 1U,
		.has_long_name = true,
		.has_hop_distance = true,
	};

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 4U);
	for (size_t i = 0U; i < ARRAY_SIZE(expected_nums); i++) {
		decode_from_radio(ctx.out[i], ctx.out_len[i], &view);
		zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
		decode_node_info_payload(view.payload, view.payload_len, &node);
		zassert_true(node.has_num);
		zassert_equal(node.num, expected_nums[i], "node[%u]",
			      (uint32_t)i);
		zassert_true(node.has_user);
		zassert_true(payload_has_string(node.user, node.user_len, 2U,
						expected_names[i]));
		zassert_true(node.has_hops_away);
		zassert_equal(node.hops_away, expected_hops[i], "hops[%u]",
			      (uint32_t)i);
	}
	decode_from_radio(ctx.out[3], ctx.out_len[3], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[3], ctx.out_len[3], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_peer_link_metrics_are_not_emitted_in_node_info)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	const uint8_t *metrics = NULL;
	size_t metrics_len = 0U;
	uint8_t counts[12];
	uint8_t metric_counts[8];
	uint32_t value = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 1U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x42 },
		.long_name = "metric-peer",
		.last_heard_seconds_ago = 321U,
		.rssi_dbm = -73,
		.snr_db = 9,
		.hop_distance = 3U,
		.has_long_name = true,
		.has_last_heard_seconds_ago = true,
		.has_rssi_dbm = true,
		.has_snr_db = true,
		.has_hop_distance = true,
	};

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 3U);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_true(node.has_num);
	zassert_equal(node.num, 0x42U);
	zassert_true(node.has_user);
	zassert_true(payload_has_string(node.user, node.user_len, 2U,
					"metric-peer"));
	zassert_true(node.has_hops_away);
	zassert_equal(node.hops_away, 3U);
	zassert_true(payload_count_fields(view.payload, view.payload_len,
					  counts, sizeof(counts)));
	zassert_equal(counts[1], 1U);
	zassert_equal(counts[2], 1U);
	zassert_equal(counts[3], 0U);
	zassert_equal(counts[4], 0U);
	zassert_equal(counts[5], 0U);
	zassert_equal(counts[6], 1U);
	zassert_equal(counts[7], 1U);
	zassert_equal(counts[9], 1U);
	zassert_false(payload_get_fixed32_field(view.payload, view.payload_len, 4U,
						&value));
	zassert_false(payload_get_fixed32_field(view.payload, view.payload_len, 5U,
						&value));
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 7U,
					      &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 6U,
					   &metrics, &metrics_len));
	zassert_true(payload_count_fields(metrics, metrics_len, metric_counts,
					  sizeof(metric_counts)));
	zassert_equal(metric_counts[1], 0U);
	zassert_equal(metric_counts[2], 0U);
	zassert_equal(metric_counts[3], 0U);
	zassert_equal(metric_counts[4], 0U);
	zassert_equal(metric_counts[5], 1U);
	zassert_false(payload_get_fixed32_field(metrics, metrics_len, 3U,
						&value));
	zassert_false(payload_get_fixed32_field(metrics, metrics_len, 4U,
						&value));
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U,
					      &value));
	zassert_equal(value, 0U);
}

ZTEST(meshtastic_adapter, test_peer_long_name_is_bounded)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	char expected_name[LICHEN_MESHTASTIC_NODE_NAME_MAX];
	int ret;

	memset(expected_name, 'x', sizeof(expected_name) - 1U);
	expected_name[sizeof(expected_name) - 1U] = '\0';
	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 1U;
	memset(ctx.peers[0].long_name, 'x', sizeof(ctx.peers[0].long_name));
	ctx.peers[0].eui64[7] = 0x42U;
	ctx.peers[0].has_long_name = true;

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 3U);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_true(node.has_user);
	zassert_true(payload_has_string(node.user, node.user_len, 2U,
					expected_name));
}

ZTEST(meshtastic_adapter, test_want_config_69421_preflights_queue_for_peers)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter_with_queue_free(&adapter, &ctx, 4U);
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 1 },
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 2 },
	};
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 4U);
	decode_from_radio(ctx.out[2], ctx.out_len[2], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_from_radio(ctx.out[3], ctx.out_len[3], &view);
	zassert_equal(view.field, 7U);

	init_adapter_with_queue_free(&adapter, &ctx, 4U);
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 1 },
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 2 },
	};
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter,
      test_want_config_69421_without_queue_free_allows_partial_backpressure)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	int ret;

	init_adapter(&adapter, &ctx, 2U);
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 1 },
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 2 },
	};

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 2U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 0xaabbccddU);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_node_number_collisions_are_omitted_and_tracked)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	struct node_info_view node;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 3U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xbb, 0, 0, 0, 0, 0, 0x55 },
		.long_name = "peer-b",
		.has_long_name = true,
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x55 },
		.long_name = "peer-a",
		.has_long_name = true,
	};
	ctx.peers[2] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xcc, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd },
		.long_name = "self-collision",
		.has_long_name = true,
	};

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 3U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 0xaabbccddU);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 0x00000055U);
	zassert_true(payload_has_string(node.user, node.user_len, 2U, "peer-a"));
	zassert_false(payload_has_string(node.user, node.user_len, 2U, "peer-b"));
	zassert_false(payload_has_string(node.user, node.user_len, 2U,
					 "self-collision"));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      nodedb_peer_collision_count,
		      2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      nodedb_peer_omitted_count,
		      2U);
}

ZTEST(meshtastic_adapter, test_want_config_unknown_nonce_queues_full_sync)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	const uint8_t complete[] = { 0x38, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 16U);
	decode_from_radio(ctx.out[14], ctx.out_len[14], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_from_radio(ctx.out[15], ctx.out_len[15], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[15], ctx.out_len[15], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_unknown_nonce_includes_peers)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	const uint8_t complete[] = { 0x38, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	struct node_info_view node;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 1 },
		.long_name = "peer-1",
		.has_long_name = true,
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 2 },
		.long_name = "peer-2",
		.has_long_name = true,
	};

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 18U);
	decode_from_radio(ctx.out[14], ctx.out_len[14], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 0xaabbccddU);
	decode_from_radio(ctx.out[15], ctx.out_len[15], &view);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 1U);
	zassert_true(payload_has_string(node.user, node.user_len, 2U, "peer-1"));
	decode_from_radio(ctx.out[16], ctx.out_len[16], &view);
	decode_node_info_payload(view.payload, view.payload_len, &node);
	zassert_equal(node.num, 2U);
	zassert_true(payload_has_string(node.user, node.user_len, 2U, "peer-2"));
	decode_from_radio(ctx.out[17], ctx.out_len[17], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[17], ctx.out_len[17], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_full_sync_fits_gateway_default_queue)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	const uint8_t complete[] = { 0x38, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	size_t expected_count = 1U + LICHEN_MESHTASTIC_FULL_SYNC_RECORDS(
					     GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS);
	int ret;

	zassert_true(GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN >= expected_count);

	init_adapter(&adapter, &ctx, GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN);
	set_default_max_peers(&ctx);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, expected_count);
	decode_from_radio(ctx.out[expected_count - 2U],
			  ctx.out_len[expected_count - 2U], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_from_radio(ctx.out[expected_count - 1U],
			  ctx.out_len[expected_count - 1U], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[expected_count - 1U],
		     ctx.out_len[expected_count - 1U], complete,
		     sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_full_sync_preflights_queue_free)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	const uint8_t complete[] = { 0x38, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	size_t expected_count = 1U + LICHEN_MESHTASTIC_FULL_SYNC_RECORDS(
					     GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS);
	int ret;

	init_adapter_with_queue_free(&adapter, &ctx,
				     GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN);
	set_default_max_peers(&ctx);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, expected_count);
	decode_from_radio(ctx.out[expected_count - 1U],
			  ctx.out_len[expected_count - 1U], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[expected_count - 1U],
		     ctx.out_len[expected_count - 1U], complete,
		     sizeof(complete));

	init_adapter_with_queue_free(&adapter, &ctx,
				     GATEWAY_MESHTASTIC_BLE_QUEUE_DEPTH_MIN);
	set_default_max_peers(&ctx);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 2U);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
			      1U);
}

ZTEST(meshtastic_adapter,
      test_want_config_full_sync_stale_queue_free_can_still_partially_enqueue)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	uint32_t expected_count = LICHEN_MESHTASTIC_FULL_SYNC_RECORDS(
		GATEWAY_MESHTASTIC_NODEDB_DEFAULT_MAX_PEERS);
	int ret;

	init_adapter_with_queue_free(&adapter, &ctx, 3U);
	ctx.has_reported_queue_free = true;
	ctx.reported_queue_free = expected_count;
	set_default_max_peers(&ctx);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 3U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	decode_from_radio(ctx.out[2], ctx.out_len[2], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter,
      test_want_config_full_sync_without_queue_free_allows_partial_backpressure)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, 3U);
	set_default_max_peers(&ctx);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 3U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	decode_from_radio(ctx.out[2], ctx.out_len[2], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_synthetic_node_and_channel_fields_are_stable)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_static[] = { 0x18, 0xac, 0x9e, 0x04 };
	const uint8_t want_nodes[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	const uint8_t *channel_payload;
	const uint8_t *settings_payload;
	const uint8_t *user_payload;
	size_t channel_len;
	size_t settings_len;
	size_t user_len;
	uint32_t hw_model = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_static,
						    sizeof(want_static));
	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[3], ctx.out_len[3], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL);
	channel_payload = view.payload;
	channel_len = view.payload_len;
	zassert_true(payload_get_len_field(channel_payload, channel_len, 2U,
					   &settings_payload, &settings_len));
	zassert_true(payload_has_string(settings_payload, settings_len, 3U,
					"LICHEN"));

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_nodes,
						    sizeof(want_nodes));
	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(view.payload_len > 0U);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 2U,
					   &user_payload, &user_len));
	zassert_true(payload_has_string(user_payload, user_len, 2U,
					"LICHEN native_sim"));
	zassert_true(payload_get_varint_field(user_payload, user_len, 5U,
					      &hw_model));
	zassert_equal(hw_model, 255U);
}

ZTEST(meshtastic_adapter, test_disconnect_marks_session_only)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t disconnect[] = { 0x20, 0x01 };
	const uint8_t disconnect_false[] = { 0x20, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect_false,
						    sizeof(disconnect_false));
	zassert_equal(ret, 0);
	zassert_false(lichen_meshtastic_adapter_disconnected(&adapter));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->disconnect_count,
		      0U);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect,
						    sizeof(disconnect));

	zassert_equal(ret, 0);
	zassert_true(lichen_meshtastic_adapter_disconnected(&adapter));
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->disconnect_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_text_packet_routes_to_stub_and_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x17, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x09, 0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x35, 0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_equal(ctx.last_text_id, 0x12345678U);
	zassert_equal(ctx.last_text_len, 5U);
	zassert_false(ctx.last_text_has_from);
	zassert_true(ctx.last_text_has_to);
	zassert_equal(ctx.last_text_to, 0xffffffffU);
	zassert_false(ctx.last_text_has_channel);
	zassert_true(ctx.last_text_want_ack);
	zassert_mem_equal(s_last_text_payload, "hello", 5U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->text_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_text_packet_with_from_and_primary_channel_routes)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x1e, 0x0d, 0x04, 0x03, 0x02, 0x01, 0x15,
		0xff, 0xff, 0xff, 0xff, 0x18, 0x00, 0x22, 0x09,
		0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c, 0x6c,
		0x6f, 0x35, 0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_true(ctx.last_text_has_from);
	zassert_equal(ctx.last_text_from, 0x01020304U);
	zassert_true(ctx.last_text_has_to);
	zassert_equal(ctx.last_text_to, 0xffffffffU);
	zassert_false(ctx.last_text_has_to_peer);
	zassert_true(ctx.last_text_has_channel);
	zassert_equal(ctx.last_text_channel, 0U);
	zassert_true(ctx.last_text_want_ack);
	zassert_mem_equal(s_last_text_payload, "hello", 5U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
}

ZTEST(meshtastic_adapter, test_text_packet_without_hook_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x17, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x09, 0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x35, 0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter_without_text_hook(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
						    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_text_hook_error_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x17, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x09, 0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x35, 0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter_with_unsupported_text_hook(&adapter, &ctx,
						ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
						    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_position_packet_routes_to_stub_and_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	struct queue_status_view status;
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload(position, sizeof(position), true,
					      true, true, true);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345679U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.latitude_e7_valid);
	zassert_equal(ctx.last_position.latitude_e7, 476206130);
	zassert_true(ctx.last_position.longitude_e7_valid);
	zassert_equal(ctx.last_position.longitude_e7, -1223493000);
	zassert_true(ctx.last_position.altitude_m_valid);
	zassert_equal(ctx.last_position.altitude_m, 42);
	zassert_true(ctx.last_position.fix_time_unix_valid);
	zassert_equal(ctx.last_position.fix_time_unix, 1710000200U);
	zassert_false(ctx.last_position.fix_time_rejected_future);
	zassert_true(ctx.last_position.satellites_valid);
	zassert_equal(ctx.last_position.satellites, 9U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345679U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      position_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_position_time_timestamp_policy_is_deterministic)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), false, true, 1710000000U, false,
		0U, false, false, 0U, false, 0U, false, 0U, false, 0U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345670U);
	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);
	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.fix_time_unix_valid);
	zassert_equal(ctx.last_position.fix_time_unix, 1710000000U);
	zassert_false(ctx.last_position.fix_time_rejected_future);

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), false, false, 0U, true,
		1710000300U, false, false, 0U, false, 0U, false, 0U,
		false, 0U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345671U);
	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);
	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.fix_time_unix_valid);
	zassert_equal(ctx.last_position.fix_time_unix, 1710000300U);
	zassert_false(ctx.last_position.fix_time_rejected_future);

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), false, true, 1710000000U, true,
		1710000400U, false, false, 0U, false, 0U, false, 0U,
		false, 0U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345672U);
	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);
	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.fix_time_unix_valid);
	zassert_equal(ctx.last_position.fix_time_unix, 1710000400U);
	zassert_false(ctx.last_position.fix_time_rejected_future);
}

ZTEST(meshtastic_adapter, test_position_below_build_epoch_strips_fix_time_only)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), false, true,
		(uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX + 10U,
		true,
		(uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX - 1U,
		false,
		false, 0U, false, 0U, false, 0U, false, 0U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345673U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.latitude_e7_valid);
	zassert_true(ctx.last_position.longitude_e7_valid);
	zassert_false(ctx.last_position.fix_time_unix_valid);
	zassert_true(ctx.last_position.fix_time_rejected_below_epoch_floor);
	zassert_false(ctx.last_position.fix_time_rejected_future);
	zassert_equal(ctx.last_position.effective_epoch_floor,
		      (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX);
}

ZTEST(meshtastic_adapter,
      test_position_timestamp_before_time_still_wins_epoch_floor)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	uint8_t to_radio[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	size_t pos = 0U;
	size_t to_radio_len;
	int ret;

	position[pos++] = 0x0d; /* Position.latitude_i fixed32 */
	put_le32(&position[pos], 476206130U);
	pos += 4U;
	position[pos++] = 0x15; /* Position.longitude_i fixed32 */
	put_le32(&position[pos], (uint32_t)-1223493000);
	pos += 4U;
	position[pos++] = 0x3d; /* Position.timestamp fixed32 */
	put_le32(&position[pos],
		 (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX - 1U);
	pos += 4U;
	position[pos++] = 0x25; /* Position.time fixed32 */
	put_le32(&position[pos],
		 (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX + 10U);
	pos += 4U;

	to_radio_len = build_app_to_radio(to_radio, sizeof(to_radio), 3U,
					  position, pos, 0x12345676U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, to_radio,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.timestamp_field_valid);
	zassert_false(ctx.last_position.fix_time_unix_valid);
	zassert_true(ctx.last_position.fix_time_rejected_below_epoch_floor);
	zassert_false(ctx.last_position.fix_time_rejected_future);
	zassert_equal(ctx.last_position.effective_epoch_floor,
		      (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX);
}

ZTEST(meshtastic_adapter,
      test_position_duplicate_time_uses_last_value_when_timestamp_absent)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	uint8_t to_radio[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	size_t pos = 0U;
	size_t to_radio_len;
	int ret;

	position[pos++] = 0x0d; /* Position.latitude_i fixed32 */
	put_le32(&position[pos], 476206130U);
	pos += 4U;
	position[pos++] = 0x15; /* Position.longitude_i fixed32 */
	put_le32(&position[pos], (uint32_t)-1223493000);
	pos += 4U;
	position[pos++] = 0x25; /* Position.time fixed32 */
	put_le32(&position[pos],
		 (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX + 10U);
	pos += 4U;
	position[pos++] = 0x25; /* Position.time fixed32 */
	put_le32(&position[pos],
		 (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX - 1U);
	pos += 4U;

	to_radio_len = build_app_to_radio(to_radio, sizeof(to_radio), 3U,
					  position, pos, 0x12345677U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, to_radio,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_false(ctx.last_position.timestamp_field_valid);
	zassert_false(ctx.last_position.fix_time_unix_valid);
	zassert_true(ctx.last_position.fix_time_rejected_below_epoch_floor);
	zassert_false(ctx.last_position.fix_time_rejected_future);
	zassert_equal(ctx.last_position.effective_epoch_floor,
		      (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX);
}

ZTEST(meshtastic_adapter, test_position_preserves_source_accuracy_and_precision)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[48];
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), true, false, 0U, true,
		1710000200U, true, true, 3U, true, 4U, true, 2500U,
		true, 24U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345674U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.location_source_valid);
	zassert_equal(ctx.last_position.location_source, 3U);
	zassert_true(ctx.last_position.altitude_source_valid);
	zassert_equal(ctx.last_position.altitude_source, 4U);
	zassert_true(ctx.last_position.gps_accuracy_mm_valid);
	zassert_equal(ctx.last_position.gps_accuracy_mm, 2500U);
	zassert_true(ctx.last_position.precision_bits_valid);
	zassert_equal(ctx.last_position.precision_bits, 24U);
}

ZTEST(meshtastic_adapter, test_position_oversized_precision_is_ignored)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[48];
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload_with_metadata(
		position, sizeof(position), false, false, 0U, false, 0U,
		false, false, 0U, false, 0U, false, 0U, true, 300U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x12345675U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 0U);
	zassert_false(ctx.last_position.precision_bits_valid);
}

ZTEST(meshtastic_adapter, test_position_negative_altitude_routes_to_stub)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	struct queue_status_view status;
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_negative_altitude_position_payload(position,
							       sizeof(position));
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x1234567cU);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.altitude_m_valid);
	zassert_equal(ctx.last_position.altitude_m, -17);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_equal(status.mesh_packet_id, 0x1234567cU);
}

ZTEST(meshtastic_adapter, test_position_oversized_satellites_are_ignored)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	struct queue_status_view status;
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_oversized_sats_position_payload(position,
							     sizeof(position));
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x1234567dU);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 0U);
	zassert_false(ctx.last_position.satellites_valid);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 3U);
	zassert_equal(status.mesh_packet_id, 0x1234567dU);
}

ZTEST(meshtastic_adapter, test_position_without_location_hook_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[16];
	struct queue_status_view status;
	size_t position_len;
	size_t to_radio_len;
	int ret;

	position_len = build_position_payload(position, sizeof(position), false,
					      false, false, false);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x1234567aU);

	init_adapter_without_text_hook(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x1234567aU);
}

ZTEST(meshtastic_adapter, test_position_hook_error_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct lichen_meshtastic_adapter_ops ops = {
		.enqueue_from_radio = test_enqueue,
		.handle_text = test_text,
		.handle_location = test_location_unsupported,
		.get_local_info = test_local_info,
		.get_peers = test_get_peers,
		.user_data = &ctx,
		.queue_maxlen = 8U,
		.heartbeat_queue_status = true,
	};
	uint8_t position[16];
	struct queue_status_view status;
	size_t position_len;
	size_t to_radio_len;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.out_cap = ARRAY_SIZE(ctx.out);
	lichen_meshtastic_adapter_init(&adapter, &ops);
	position_len = build_position_payload(position, sizeof(position), false,
					      false, false, false);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  3U, position, position_len,
					  0x1234567bU);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x1234567bU);
}

ZTEST(meshtastic_adapter, test_position_invalid_payloads_are_malformed)
{
	static const uint8_t missing_lon[] = {
		0x0d, 0x32, 0x23, 0x62, 0x1c,
	};
	static const uint8_t bad_lat_wire_type[] = {
		0x08, 0x01, 0x15, 0xf8, 0x4f, 0x12, 0xb7,
	};
	static const uint8_t truncated_lon[] = {
		0x0d, 0x32, 0x23, 0x62, 0x1c,
		0x15, 0xf8, 0x4f,
	};
	static const uint8_t empty[] = { 0 };
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t *cases[] = {
		empty,
		missing_lon,
		bad_lat_wire_type,
		truncated_lon,
	};
	const size_t lens[] = {
		0U,
		sizeof(missing_lon),
		sizeof(bad_lat_wire_type),
		sizeof(truncated_lon),
	};

	for (size_t i = 0U; i < ARRAY_SIZE(cases); i++) {
		struct queue_status_view status;
		size_t to_radio_len;
		int ret;

		to_radio_len = build_app_to_radio(s_text_packet,
						  sizeof(s_text_packet), 3U,
						  cases[i], lens[i],
						  0x12345680U + (uint32_t)i);

		init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
		ret = lichen_meshtastic_adapter_process_raw(&adapter,
							    s_text_packet,
							    to_radio_len);

		zassert_equal(ret, 0);
		zassert_equal(ctx.position_count, 0U);
		zassert_equal(ctx.out_count, 1U);
		decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
		zassert_true(status.has_res);
		zassert_equal(status.res, 3U);
		zassert_true(status.has_mesh_packet_id);
		zassert_equal(status.mesh_packet_id,
			      0x12345680U + (uint32_t)i);
		zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
				      malformed_count,
			      1U);
	}
}

ZTEST(meshtastic_adapter, test_meshpacket_with_both_decoded_and_encrypted_is_malformed)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t both_fields_packet[] = {
		0x0a, 0x1b, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x09, 0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x2a, 0x02, 0xaa, 0xbb, 0x35, 0x78,
		0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter,
						    both_fields_packet,
						    sizeof(both_fields_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 3U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_direct_text_known_peer_routes_to_stub)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t expected_iid[] = {
		0x00, 0xaa, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04
	};
	struct queue_status_view status;
	size_t len;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 1U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0x01, 0x02, 0x03, 0x04 },
	};
	len = build_text_to_radio_to(s_text_packet, sizeof(s_text_packet),
				     (const uint8_t *)"hello", 5U,
				     0x01020304U, 0x12345678U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet, len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_true(ctx.last_text_has_to);
	zassert_equal(ctx.last_text_to, 0x01020304U);
	zassert_true(ctx.last_text_has_to_peer);
	zassert_mem_equal(ctx.last_text_to_iid, expected_iid,
			  sizeof(expected_iid));
	zassert_mem_equal(s_last_text_payload, "hello", 5U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
}

ZTEST(meshtastic_adapter, test_direct_text_unknown_peer_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct queue_status_view status;
	size_t len;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	len = build_text_to_radio_to(s_text_packet, sizeof(s_text_packet),
				     (const uint8_t *)"hello", 5U,
				     0x01020304U, 0x12345678U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet, len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->text_packet_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_direct_text_self_node_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct queue_status_view status;
	size_t len;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	len = build_text_to_radio_to(s_text_packet, sizeof(s_text_packet),
				     (const uint8_t *)"hello", 5U,
				     0xaabbccddU, 0x12345678U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet, len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_direct_text_colliding_peer_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct queue_status_view status;
	size_t len;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.peer_count = 2U;
	ctx.peers[0] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xaa, 0, 0, 0, 0, 0, 0x55 },
	};
	ctx.peers[1] = (struct lichen_meshtastic_peer_snapshot){
		.eui64 = { 0x02, 0xbb, 0, 0, 0, 0, 0, 0x55 },
	};
	len = build_text_to_radio_to(s_text_packet, sizeof(s_text_packet),
				     (const uint8_t *)"hello", 5U,
				     0x00000055U, 0x12345678U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet, len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_text_packet_without_destination_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x12, 0x22, 0x09, 0x08, 0x01, 0x12, 0x05,
		0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x35, 0x78, 0x56,
		0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_secondary_channel_text_packet_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x19, 0x15, 0xff, 0xff, 0xff, 0xff, 0x18,
		0x01, 0x22, 0x09, 0x08, 0x01, 0x12, 0x05, 0x68,
		0x65, 0x6c, 0x6c, 0x6f, 0x35, 0x78, 0x56, 0x34,
		0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_empty_text_payload_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x12, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x04, 0x08, 0x01, 0x12, 0x00, 0x35, 0x78, 0x56,
		0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_invalid_utf8_text_payload_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x14, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x06, 0x08, 0x01, 0x12, 0x02, 0xff, 0xff, 0x35,
		0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
                                                    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_multibyte_utf8_text_payload_routes)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	static const uint8_t payload[] = {
		'H', 'e', 'l', 'l', 'o', ' ',
		0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c, ' ',
		0xf0, 0x9f, 0x8c, 0x8d
	};
	size_t text_packet_len;
	struct queue_status_view status;
	int ret;

	text_packet_len = build_text_to_radio(s_text_packet, sizeof(s_text_packet),
					      payload, sizeof(payload),
					      0x12345682U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    text_packet_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_equal(ctx.last_text_len, sizeof(payload));
	zassert_mem_equal(s_last_text_payload, payload, sizeof(payload));
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
}

ZTEST(meshtastic_adapter, test_malformed_utf8_text_payloads_are_unsupported)
{
	static const uint8_t overlong_nul[] = { 0xc0, 0x80 };
	static const uint8_t truncated_three_byte[] = { 0xe2, 0x82 };
	static const uint8_t surrogate[] = { 0xed, 0xa0, 0x80 };
	const struct {
		const uint8_t *payload;
		size_t len;
		uint32_t id;
	} cases[] = {
		{ overlong_nul, sizeof(overlong_nul), 0x12345683U },
		{ truncated_three_byte, sizeof(truncated_three_byte), 0x12345684U },
		{ surrogate, sizeof(surrogate), 0x12345685U },
	};

	for (size_t i = 0U; i < ARRAY_SIZE(cases); i++) {
		struct lichen_meshtastic_adapter adapter;
		struct test_ctx ctx;
		size_t text_packet_len;
		struct queue_status_view status;
		int ret;

		text_packet_len = build_text_to_radio(
			s_text_packet, sizeof(s_text_packet), cases[i].payload,
			cases[i].len, cases[i].id);

		init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
		ret = lichen_meshtastic_adapter_process_raw(&adapter,
							    s_text_packet,
							    text_packet_len);

		zassert_equal(ret, 0);
		zassert_equal(ctx.text_count, 0U);
		zassert_equal(ctx.out_count, 1U);
		decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
		zassert_true(status.has_res);
		zassert_equal(status.res, 2U);
		zassert_true(status.has_mesh_packet_id);
		zassert_equal(status.mesh_packet_id, cases[i].id);
	}
}

ZTEST(meshtastic_adapter, test_max_text_payload_routes_to_stub)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t payload[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX];
	size_t text_packet_len;
	struct queue_status_view status;
	int ret;

	memset(payload, 'x', sizeof(payload));
	text_packet_len = build_text_to_radio(s_text_packet, sizeof(s_text_packet),
					      payload, sizeof(payload),
					      0x12345680U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    text_packet_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_equal(ctx.last_text_len, sizeof(payload));
	zassert_mem_equal(s_last_text_payload, payload, sizeof(payload));
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345680U);
}

ZTEST(meshtastic_adapter, test_over_limit_text_payload_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t payload[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U];
	size_t text_packet_len;
	struct queue_status_view status;
	int ret;

	memset(payload, 'x', sizeof(payload));
	text_packet_len = build_text_to_radio(s_text_packet, sizeof(s_text_packet),
					      payload, sizeof(payload),
					      0x12345681U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    text_packet_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345681U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_unsupported_packet_is_deterministic_noop)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t private_packet[] = {
		0x0a, 0x1c, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x10, 0x08, 0x80, 0x02, 0x12, 0x0b, 0x75, 0x6e,
		0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
		0x64, 0x35, 0x79, 0x56, 0x34, 0x12
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, private_packet,
						    sizeof(private_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345679U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_admin_write_is_deterministic_noop)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t set_owner_empty[] = { 0x82, 0x02, 0x00 };
	struct queue_status_view status;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, set_owner_empty,
					  sizeof(set_owner_empty), 0x12345692U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345692U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_admin_mixed_read_and_write_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x60, 0x01,       /* get_device_metadata_request = true */
		0x82, 0x02, 0x00 /* set_owner = empty User */
	};
	struct queue_status_view status;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345693U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345693U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_admin_later_current_read_oneof_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x60, 0x01, /* get_device_metadata_request = true */
		0x70, 0x01  /* get_ringtone_request = true */
	};
	struct queue_status_view status;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345697U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345697U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_admin_later_current_command_oneof_is_unsupported)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x60, 0x01,       /* get_device_metadata_request = true */
		0x88, 0x06, 0x01 /* reboot_seconds = 1 */
	};
	struct queue_status_view status;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345698U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345698U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_admin_later_metadata_request_wins_oneof)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x82, 0x02, 0x00, /* set_owner = empty User */
		0x60, 0x01        /* get_device_metadata_request = true */
	};
	struct admin_metadata_packet_view packet;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345695U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_true(packet.has_request_id);
	zassert_equal(packet.request_id, 0x12345695U);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN test 0.0.0"));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_admin_unknown_future_field_does_not_override_metadata)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x60, 0x01,       /* get_device_metadata_request = true */
		0x90, 0x03, 0x01 /* unknown field 50, varint true */
	};
	struct admin_metadata_packet_view packet;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345696U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_true(packet.has_request_id);
	zassert_equal(packet.request_id, 0x12345696U);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN test 0.0.0"));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_admin_session_passkey_does_not_override_metadata)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t mixed_payload[] = {
		0x60, 0x01,       /* get_device_metadata_request = true */
		0xaa, 0x06, 0x00 /* session_passkey = empty bytes */
	};
	struct admin_metadata_packet_view packet;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, mixed_payload,
					  sizeof(mixed_payload), 0x12345699U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_admin_metadata_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_true(packet.has_request_id);
	zassert_equal(packet.request_id, 0x12345699U);
	zassert_true(payload_has_string(packet.metadata, packet.metadata_len, 1U,
					"LICHEN test 0.0.0"));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_admin_malformed_payload_returns_malformed_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t malformed_payload[] = {
		0x60, /* get_device_metadata_request missing bool value */
	};
	struct queue_status_view status;
	size_t to_radio_len;
	int ret;

	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
					  6U, malformed_payload,
					  sizeof(malformed_payload), 0x12345694U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet,
						    to_radio_len);

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 3U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345694U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_unsupported_operation_table_is_recorded)
{
	static const struct {
		enum lichen_meshtastic_adapter_unsupported_operation_id id;
		uint32_t portnum;
		bool has_portnum;
	} expected[] = {
		{ LICHEN_MESHTASTIC_UNSUPPORTED_RADIO_CONFIG_WRITE, 0U, false },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_CHANNEL_CONFIG_WRITE, 0U, false },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_UNKNOWN_APP, 0U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ADMIN_COMMAND, 6U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_NODEINFO_UPDATE, 4U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ROUTING_APP_TO_NODE, 5U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_COMPRESSED_TEXT, 7U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_WAYPOINT, 8U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_AUDIO, 9U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_DETECTION_SENSOR, 10U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ALERT, 11U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_KEY_VERIFICATION, 12U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_SHELL, 13U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_REPLY, 32U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_IP_TUNNEL, 33U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_PAXCOUNTER, 34U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD_PLUSPLUS, 35U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_NODE_STATUS, 36U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_MESH_BEACON, 37U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_SERIAL, 64U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_HARDWARE, 2U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_TELEMETRY_MODULE, 67U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ZPS, 68U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_SIMULATOR, 69U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_NEIGHBORINFO, 71U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN, 72U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_CANNED_MESSAGE_MODULE, 0U, false },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD, 65U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_TRACEROUTE, 70U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_RANGE_TEST, 66U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_MAP_REPORT, 73U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_POWERSTRESS, 74U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_LORAWAN_BRIDGE, 75U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_RETICULUM_TUNNEL, 76U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_CAYENNE, 77U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN_V2, 78U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_LORA_OTA, 79U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_GROUPALARM, 112U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_PRIVATE_APP, 256U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_FORWARDER, 257U, true },
		{ LICHEN_MESHTASTIC_UNSUPPORTED_MAX_SENTINEL, 511U, true },
	};
	const struct lichen_meshtastic_adapter_unsupported_operation *ops;
	size_t count = lichen_meshtastic_adapter_unsupported_operations(&ops);

	zassert_not_null(ops);
	zassert_equal(count, ARRAY_SIZE(expected));

	for (size_t i = 0U; i < count; i++) {
		zassert_equal(ops[i].id, expected[i].id);
		zassert_equal(ops[i].has_portnum, expected[i].has_portnum);
		zassert_equal(ops[i].portnum, expected[i].portnum);
	}

	zassert_equal(lichen_meshtastic_adapter_unsupported_operations(NULL),
		      count);
}

ZTEST(meshtastic_adapter, test_unsupported_operation_portnums_queue_errors)
{
	static const uint32_t unsupported_portnums[] = {
		0U,  2U,  4U,  5U,  7U,  8U,  9U,
		10U, 11U, 12U, 13U, 32U, 33U, 34U, 35U,
		36U, 37U, 64U, 65U, 66U, 67U, 68U, 69U,
		70U, 71U, 72U, 73U, 74U, 75U, 76U, 77U,
		78U, 79U, 112U, 256U, 257U, 511U,
	};
	static const uint8_t payload[] = { 0x75, 0x6e, 0x73, 0x75 };
	uint32_t id = 0x22330000U;

	for (size_t i = 0U; i < ARRAY_SIZE(unsupported_portnums); i++) {
		struct lichen_meshtastic_adapter adapter;
		struct test_ctx ctx;
		struct queue_status_view status;
		size_t to_radio_len;
		int ret;

		id++;
		to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet),
						  unsupported_portnums[i],
						  payload, sizeof(payload), id);

		init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
		ret = lichen_meshtastic_adapter_process_raw(&adapter,
							    s_text_packet,
							    to_radio_len);

		zassert_equal(ret, 0, "portnum %u", unsupported_portnums[i]);
		zassert_equal(ctx.text_count, 0U, "portnum %u",
			      unsupported_portnums[i]);
		zassert_equal(ctx.out_count, 1U, "portnum %u",
			      unsupported_portnums[i]);
		decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
		zassert_true(status.has_res, "portnum %u",
			     unsupported_portnums[i]);
		zassert_equal(status.res, 2U, "portnum %u",
			      unsupported_portnums[i]);
		zassert_true(status.has_mesh_packet_id, "portnum %u",
			     unsupported_portnums[i]);
		zassert_equal(status.mesh_packet_id, id, "portnum %u",
			      unsupported_portnums[i]);
		zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
				      packet_count,
			      1U, "portnum %u", unsupported_portnums[i]);
		zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
				      unsupported_packet_count,
			      1U, "portnum %u", unsupported_portnums[i]);
	}
}

ZTEST(meshtastic_adapter, test_stream_valid_and_split_frames)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t frame[] = { 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, frame, 3U);
	zassert_equal(ret, LICHEN_MESHTASTIC_ADAPTER_NEED_MORE);
	zassert_equal(ctx.out_count, 0U);

	ret = lichen_meshtastic_adapter_feed_stream(&adapter, &frame[3],
						   sizeof(frame) - 3U);
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_stream_rejects_malformed_and_resyncs)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t bad_magic[] = { 0x94, 0x00, 0x00, 0x02 };
	const uint8_t zero_len[] = { 0x94, 0xc3, 0x00, 0x00 };
	const uint8_t oversize[] = { 0x94, 0xc3, 0x01, 0xf9 };
	const uint8_t good[] = { 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, bad_magic,
							    sizeof(bad_magic)),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, zero_len,
							    sizeof(zero_len)),
		      -EMSGSIZE);
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, oversize,
							    sizeof(oversize)),
		      -EMSGSIZE);

	ret = lichen_meshtastic_adapter_feed_stream(&adapter, good, sizeof(good));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
}

ZTEST(meshtastic_adapter, test_stream_resyncs_within_same_buffer)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t noisy_good[] = {
		0x00, 0x94, 0x00, 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, noisy_good,
						   sizeof(noisy_good));
	zassert_equal(ret, 0, "ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_true(lichen_meshtastic_adapter_get_stats(&adapter)->
			     malformed_count >= 2U);
}

ZTEST(meshtastic_adapter, test_stream_resyncs_after_bad_frame_in_same_buffer)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t zero_len_good[] = {
		0x94, 0xc3, 0x00, 0x00, 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	const uint8_t malformed_payload_good[] = {
		0x94, 0xc3, 0x00, 0x02, 0x18, 0x80,
		0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, zero_len_good,
						   sizeof(zero_len_good));
	zassert_equal(ret, 0, "zero_len ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter,
						   malformed_payload_good,
						   sizeof(malformed_payload_good));
	zassert_equal(ret, 0, "malformed ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_stage1_stops_on_backpressure)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, 2U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 2U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_emit_text_queues_meshtastic_packet)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_incoming_text event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};
	struct text_packet_view packet;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_text_count,
		      1U);
	decode_text_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.from, 0x11223344U);
	zassert_equal(packet.to, 0x01020304U);
	zassert_equal(packet.id, 0x55667788U);
	zassert_equal(packet.payload_len, sizeof(payload));
	zassert_mem_equal(packet.payload, payload, sizeof(payload));
}

ZTEST(meshtastic_adapter, test_emit_text_generates_stable_ids)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t payload[] = { 'o', 'k' };
	struct lichen_meshtastic_incoming_text event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct text_packet_view packet;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);
	zassert_equal(ret, 0);

	zassert_equal(ctx.out_count, 2U);
	decode_text_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.id, 1U);
	decode_text_from_radio(ctx.out[1], ctx.out_len[1], &packet);
	zassert_equal(packet.from_radio_id, 2U);
	zassert_equal(packet.id, 2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_text_count,
		      2U);
}

ZTEST(meshtastic_adapter, test_emit_text_backpressure_is_deterministic)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_incoming_text event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	int ret;

	init_adapter(&adapter, &ctx, 1U);
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);
	zassert_equal(ret, -ENOMEM);

	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_text_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_emit_text_rejects_disconnected_session)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t disconnect[] = { 0x20, 0x01 };
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_incoming_text event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect,
						    sizeof(disconnect));
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);

	zassert_equal(ret, -ENOTCONN);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_text_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_emit_text_requires_valid_payload)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t invalid_payload[] = { 0xff, 0xff };
	struct lichen_meshtastic_incoming_text event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = invalid_payload,
		.payload_len = sizeof(invalid_payload),
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_text(&adapter, &event);

	zassert_equal(ret, -EMSGSIZE);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_text_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_emit_status_ack_queues_routing_packet)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct lichen_meshtastic_incoming_status event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
		.has_id = true,
	};
	struct status_packet_view packet;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_status_count,
		      1U);
	decode_status_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.from, 0x11223344U);
	zassert_equal(packet.to, 0x01020304U);
	zassert_equal(packet.id, 0x55667789U);
	zassert_equal(packet.request_id, 0x12345678U);
	zassert_false(packet.has_error_reason);
}

ZTEST(meshtastic_adapter, test_emit_status_nak_queues_routing_error)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct lichen_meshtastic_incoming_status event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x5566778aU,
		.request_id = 0x12345678U,
		.error_reason = 1U,
		.has_id = true,
		.has_error_reason = true,
	};
	struct status_packet_view packet;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	decode_status_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.id, 0x5566778aU);
	zassert_equal(packet.request_id, 0x12345678U);
	zassert_true(packet.has_error_reason);
	zassert_equal(packet.error_reason, 1U);
}

ZTEST(meshtastic_adapter, test_emit_status_generates_stable_ids)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct lichen_meshtastic_incoming_status event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};
	struct status_packet_view packet;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);
	zassert_equal(ret, 0);

	zassert_equal(ctx.out_count, 2U);
	decode_status_from_radio(ctx.out[0], ctx.out_len[0], &packet);
	zassert_equal(packet.from_radio_id, 1U);
	zassert_equal(packet.id, 1U);
	decode_status_from_radio(ctx.out[1], ctx.out_len[1], &packet);
	zassert_equal(packet.from_radio_id, 2U);
	zassert_equal(packet.id, 2U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_status_count,
		      2U);
}

ZTEST(meshtastic_adapter, test_emit_status_backpressure_is_deterministic)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	struct lichen_meshtastic_incoming_status event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};
	int ret;

	init_adapter(&adapter, &ctx, 1U);
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);
	zassert_equal(ret, -ENOMEM);

	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_status_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_emit_status_rejects_disconnected_session)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t disconnect[] = { 0x20, 0x01 };
	struct lichen_meshtastic_incoming_status event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect,
						    sizeof(disconnect));
	zassert_equal(ret, 0);
	ret = lichen_meshtastic_adapter_emit_status(&adapter, &event);

	zassert_equal(ret, -ENOTCONN);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      incoming_status_count,
		      0U);
}

ZTEST(meshtastic_adapter, test_unknown_raw_gets_unsupported_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t unknown_only[] = { 0x28, 0x01 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, unknown_only,
						    sizeof(unknown_only));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_empty_raw_gets_unsupported_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t empty = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, &empty, 0U);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
			      1U);
}

ZTEST(meshtastic_adapter, test_malformed_raw_is_rejected)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t truncated_varint[] = { 0x18, 0x80 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, truncated_varint,
						    sizeof(truncated_varint));

	zassert_equal(ret, -EINVAL);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_oversized_raw_is_rejected)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t oversize[LICHEN_MESHTASTIC_TO_RADIO_MAX + 1U] = { 0 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, oversize,
						    sizeof(oversize));

	zassert_equal(ret, -EMSGSIZE);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_position_future_timestamp_rejected)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t position[32];
	size_t position_len;
	size_t to_radio_len;
	int ret;
	position_len = build_position_payload_with_metadata(position, sizeof(position), false, false, 0U, true, 4000000000U, false, false, 0U, false, 0U, false, 0U, false, 0U);
	to_radio_len = build_app_to_radio(s_text_packet, sizeof(s_text_packet), 3U, position, position_len, 0x12345674U);
	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, s_text_packet, to_radio_len);
	zassert_equal(ret, 0);
	zassert_equal(ctx.position_count, 1U);
	zassert_true(ctx.last_position.latitude_e7_valid);
	zassert_true(ctx.last_position.longitude_e7_valid);
	zassert_false(ctx.last_position.fix_time_unix_valid);
	zassert_true(ctx.last_position.fix_time_rejected_future);
	zassert_false(ctx.last_position.fix_time_rejected_below_epoch_floor);
	zassert_equal(ctx.last_position.effective_epoch_floor, (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX);
}
ZTEST_SUITE(meshtastic_adapter, NULL, NULL, NULL, NULL, NULL);
