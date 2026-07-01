/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <lichen/meshcore/adapter.h>

#define LICHEN_MESHCORE_SELF_INFO_LEN 64U
#define LICHEN_MESHCORE_DEVICE_INFO_LEN 82U
#define LICHEN_MESHCORE_CHANNEL_INFO_LEN 50U

BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD <=
	     LICHEN_MESHCORE_FRAME_MAX,
	     "MeshCore serial payload cannot exceed inner frame buffer");

static int enqueue(struct lichen_meshcore_adapter *adapter,
		   const uint8_t *frame, size_t len)
{
	int ret;

	if (adapter->ops.enqueue_tx == NULL) {
		adapter->stats.enqueue_fail_count++;
		return -ENOSYS;
	}

	ret = adapter->ops.enqueue_tx(frame, len, adapter->ops.user_data);
	if (ret < 0) {
		adapter->stats.enqueue_fail_count++;
	}
	return ret;
}

static int enqueue_error(struct lichen_meshcore_adapter *adapter, uint8_t err)
{
	uint8_t out[2];
	int ret = lichen_meshcore_encode_error(err, out, sizeof(out));

	if (ret < 0) {
		return ret;
	}
	return enqueue(adapter, out, (size_t)ret);
}

static int enqueue_contacts_empty(struct lichen_meshcore_adapter *adapter)
{
	uint8_t start[5] = { LICHEN_MESHCORE_RESP_CONTACTS_START };
	uint8_t end[5] = { LICHEN_MESHCORE_RESP_END_OF_CONTACTS };
	int ret;

	if (adapter->ops.tx_free == NULL) {
		adapter->stats.enqueue_fail_count++;
		return -ENOSYS;
	}
	if (adapter->ops.tx_free(adapter->ops.user_data) < 2U) {
		adapter->stats.enqueue_fail_count++;
		return -ENOMEM;
	}

	sys_put_le32(0U, &start[1]);
	sys_put_le32(0U, &end[1]);
	ret = enqueue(adapter, start, sizeof(start));
	if (ret < 0) {
		return ret;
	}
	return enqueue(adapter, end, sizeof(end));
}

static int enqueue_self_info(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[LICHEN_MESHCORE_SELF_INFO_LEN] = {
		LICHEN_MESHCORE_RESP_SELF_INFO,
	};
	const char name[] = "LICHEN";

	out[1] = 0x01U; /* chat advert placeholder */
	out[2] = 14U;   /* tx power dBm placeholder */
	out[3] = 22U;   /* max tx power placeholder */
	out[44] = 0U;   /* multi ACKs */
	out[45] = 0U;   /* location policy */
	out[46] = 0U;   /* telemetry modes */
	out[47] = 0U;   /* manual add contacts */
	sys_put_le32(868000000U, &out[48]);
	sys_put_le32(125000U, &out[52]);
	out[56] = 10U;  /* SF10 */
	out[57] = 5U;   /* CR 4/5 representation */
	memcpy(&out[58], name, sizeof(name) - 1U);
	return enqueue(adapter, out, sizeof(out));
}

static int enqueue_device_info(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[LICHEN_MESHCORE_DEVICE_INFO_LEN] = {
		LICHEN_MESHCORE_RESP_DEVICE_INFO,
	};
	const char build[] = "LICHEN";
	const char model[] = "LICHEN";
	const char version[] = "0.0.0";

	out[1] = LICHEN_MESHCORE_APP_PROTOCOL_VERSION;
	out[2] = 0U; /* max contacts / 2 */
	out[3] = 1U; /* one placeholder public channel */
	memcpy(&out[8], build, sizeof(build) - 1U);
	memcpy(&out[20], model, sizeof(model) - 1U);
	memcpy(&out[60], version, sizeof(version) - 1U);
	out[80] = 0U; /* client repeat disabled */
	out[81] = 0U; /* path hash disabled */
	return enqueue(adapter, out, sizeof(out));
}

static int enqueue_batt_storage(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[11] = { LICHEN_MESHCORE_RESP_BATT_AND_STORAGE };

	sys_put_le16(0U, &out[1]);
	sys_put_le32(0U, &out[3]);
	sys_put_le32(0U, &out[7]);
	return enqueue(adapter, out, sizeof(out));
}

static int enqueue_time(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[5] = { LICHEN_MESHCORE_RESP_CURR_TIME };

	sys_put_le32((uint32_t)(k_uptime_get() / 1000), &out[1]);
	return enqueue(adapter, out, sizeof(out));
}

static int enqueue_channel(struct lichen_meshcore_adapter *adapter,
			   const struct lichen_meshcore_frame_view *view)
{
	uint8_t out[LICHEN_MESHCORE_CHANNEL_INFO_LEN] = {
		LICHEN_MESHCORE_RESP_CHANNEL_INFO,
	};
	const char name[] = "Public";

	if (view->payload_len < 1U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (view->payload[0] != 0U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}

	out[1] = 0U;
	memcpy(&out[2], name, sizeof(name) - 1U);
	return enqueue(adapter, out, sizeof(out));
}

static int dispatch_supported(struct lichen_meshcore_adapter *adapter,
			      const struct lichen_meshcore_frame_view *view)
{
	switch (view->type) {
	case LICHEN_MESHCORE_CMD_APP_START:
		return view->payload_len >= 7U ?
			enqueue_self_info(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	case LICHEN_MESHCORE_CMD_DEVICE_QUERY:
		return view->payload_len >= 1U ?
			enqueue_device_info(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	case LICHEN_MESHCORE_CMD_GET_CONTACTS:
		return (view->payload_len == 0U || view->payload_len == 4U) ?
			enqueue_contacts_empty(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	case LICHEN_MESHCORE_CMD_GET_CHANNEL:
		return enqueue_channel(adapter, view);
	case LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE: {
		uint8_t out = LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES;
		return view->payload_len == 0U ?
			enqueue(adapter, &out, sizeof(out)) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	case LICHEN_MESHCORE_CMD_GET_BATT_AND_STORAGE:
		return view->payload_len == 0U ?
			enqueue_batt_storage(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	case LICHEN_MESHCORE_CMD_GET_DEVICE_TIME:
		return view->payload_len == 0U ?
			enqueue_time(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	case LICHEN_MESHCORE_CMD_GET_CUSTOM_VARS: {
		uint8_t out = LICHEN_MESHCORE_RESP_CUSTOM_VARS;
		return view->payload_len == 0U ?
			enqueue(adapter, &out, sizeof(out)) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	case LICHEN_MESHCORE_CMD_GET_AUTOADD_CONFIG: {
		const uint8_t out[] = { LICHEN_MESHCORE_RESP_AUTOADD_CONFIG, 0U, 0U };
		return view->payload_len == 0U ?
			enqueue(adapter, out, sizeof(out)) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	case LICHEN_MESHCORE_CMD_GET_DEFAULT_FLOOD_SCOPE: {
		uint8_t out = LICHEN_MESHCORE_RESP_DEFAULT_FLOOD_SCOPE;
		return view->payload_len == 0U ?
			enqueue(adapter, &out, sizeof(out)) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	default:
		return -ENOTSUP;
	}
}

void lichen_meshcore_adapter_init(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_adapter_ops *ops)
{
	if (adapter == NULL) {
		return;
	}

	memset(adapter, 0, sizeof(*adapter));
	if (ops != NULL) {
		adapter->ops = *ops;
	}
}

void lichen_meshcore_adapter_reset(struct lichen_meshcore_adapter *adapter)
{
	struct lichen_meshcore_adapter_ops ops;

	if (adapter == NULL) {
		return;
	}

	ops = adapter->ops;
	lichen_meshcore_adapter_init(adapter, &ops);
}

int lichen_meshcore_adapter_process_raw(
	struct lichen_meshcore_adapter *adapter,
	const uint8_t *frame, size_t len)
{
	struct lichen_meshcore_frame_view view;
	int ret;

	if (adapter == NULL) {
		return -EINVAL;
	}

	adapter->stats.raw_count++;
	ret = lichen_meshcore_decode_frame(frame, len, &view);
	if (ret < 0) {
		adapter->stats.malformed_count++;
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}

	ret = dispatch_supported(adapter, &view);
	if (ret == -ENOTSUP) {
		adapter->stats.unsupported_count++;
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	if (ret < 0) {
		return ret;
	}

	adapter->stats.supported_count++;
	return ret;
}

static int process_complete_stream(struct lichen_meshcore_adapter *adapter)
{
	int ret = lichen_meshcore_adapter_process_raw(adapter, adapter->stream_buf,
						     adapter->stream_len);

	adapter->stats.stream_frame_count++;
	adapter->stream_len = 0U;
	adapter->stream_expected = 0U;
	adapter->stream_in_frame = false;
	return ret;
}

int lichen_meshcore_adapter_feed_stream(
	struct lichen_meshcore_adapter *adapter,
	const uint8_t *data, size_t len)
{
	int last = 0;

	if (adapter == NULL || (data == NULL && len > 0U)) {
		return -EINVAL;
	}

	for (size_t pos = 0U; pos < len; pos++) {
		uint8_t byte = data[pos];

		if (!adapter->stream_in_frame) {
			if (adapter->stream_header_len == 0U) {
				if (byte != LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE) {
					adapter->stats.malformed_count++;
					continue;
				}
				adapter->stream_header[adapter->stream_header_len++] = byte;
				continue;
			}

			adapter->stream_header[adapter->stream_header_len++] = byte;
			if (adapter->stream_header_len < sizeof(adapter->stream_header)) {
				continue;
			}

			adapter->stream_expected =
				sys_get_le16(&adapter->stream_header[1]);
			adapter->stream_header_len = 0U;
			adapter->stream_len = 0U;
			if (adapter->stream_expected == 0U ||
			    adapter->stream_expected >
			    CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD) {
				adapter->stats.malformed_count++;
				adapter->stream_expected = 0U;
				continue;
			}
			adapter->stream_in_frame = true;
			continue;
		}

		adapter->stream_buf[adapter->stream_len++] = byte;
		if (adapter->stream_len == adapter->stream_expected) {
			last = process_complete_stream(adapter);
		}
	}

	return last;
}

const struct lichen_meshcore_adapter_stats *
lichen_meshcore_adapter_get_stats(
	const struct lichen_meshcore_adapter *adapter)
{
	return adapter == NULL ? NULL : &adapter->stats;
}
