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

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
#include <lichen/app_identity/app_identity.h>
#endif
#include <lichen/meshcore/adapter.h>

#define LICHEN_MESHCORE_SELF_INFO_LEN 64U
#define LICHEN_MESHCORE_DEVICE_INFO_LEN 82U
#define LICHEN_MESHCORE_CHANNEL_INFO_LEN 50U
#define LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN 11U
#define LICHEN_MESHCORE_STATUS_ACK_LEN 7U
#define LICHEN_MESHCORE_SELF_INFO_PUBLIC_KEY_OFF 4U
#define LICHEN_MESHCORE_SELF_INFO_PUBLIC_KEY_LEN 32U
#define LICHEN_MESHCORE_SELF_INFO_NAME_OFF 58U
#define LICHEN_MESHCORE_SELF_INFO_NAME_LEN \
	(LICHEN_MESHCORE_SELF_INFO_LEN - LICHEN_MESHCORE_SELF_INFO_NAME_OFF)
#define LICHEN_MESHCORE_DEVICE_INFO_BUILD_OFF 8U
#define LICHEN_MESHCORE_DEVICE_INFO_BUILD_LEN 12U
#define LICHEN_MESHCORE_DEVICE_INFO_MODEL_OFF 20U
#define LICHEN_MESHCORE_DEVICE_INFO_MODEL_LEN 40U
#define LICHEN_MESHCORE_DEVICE_INFO_VERSION_OFF 60U
#define LICHEN_MESHCORE_DEVICE_INFO_VERSION_LEN 20U
#define LICHEN_MESHCORE_AUTOADD_CONFIG_LEN 2U
#define LICHEN_MESHCORE_CHANNEL_SECRET_OFF 33U
#define LICHEN_MESHCORE_DEFAULT_FLOOD_PAYLOAD_LEN \
	(LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN + \
	 LICHEN_MESHCORE_DEFAULT_FLOOD_KEY_LEN)

BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD <=
	     LICHEN_MESHCORE_FRAME_MAX,
	     "MeshCore serial payload cannot exceed inner frame buffer");
BUILD_ASSERT(LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN <
	     LICHEN_MESHCORE_FRAME_MAX,
	     "MeshCore channel V3 header must fit in a frame");
BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_PENDING_EVENTS <= UINT8_MAX,
	     "Pending event queue indices are uint8_t");
BUILD_ASSERT(LICHEN_MESHCORE_PENDING_MAX <= UINT8_MAX,
	     "Pending event kind must fit in uint8_t");
BUILD_ASSERT(LICHEN_MESHCORE_FRAME_MAX <= UINT16_MAX,
	     "Frame max exceeds uint16_t limit for length fields");

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

static int enqueue_ok(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[1];
	int ret = lichen_meshcore_encode_ok(out, sizeof(out));

	if (ret < 0) {
		return ret;
	}
	return enqueue(adapter, out, (size_t)ret);
}

void lichen_meshcore_compat_settings_reset(
	struct lichen_meshcore_compat_settings *_Nonnull settings)
{
	memset(settings, 0, sizeof(*settings));
}

static struct lichen_meshcore_compat_settings *_Nonnull
compat_settings(struct lichen_meshcore_adapter *_Nonnull adapter)
{
	return adapter->ops.compat_settings;
}

static const struct lichen_meshcore_compat_settings *_Nonnull
compat_settings_const(const struct lichen_meshcore_adapter *_Nonnull adapter)
{
	return adapter->ops.compat_settings;
}

static void copy_fixed_string(uint8_t *dst, size_t dst_len,
			      const char *fallback, const char *preferred)
{
	const char *src = (preferred != NULL && preferred[0] != '\0') ?
			  preferred : fallback;
	size_t len;

	if (dst == NULL || dst_len == 0U || src == NULL) {
		return;
	}

	len = strlen(src);
	if (len > dst_len) {
		len = dst_len;
	}
	memcpy(dst, src, len);
	if (len < dst_len) {
		memset(dst + len, 0, dst_len - len);
	}
}

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
static bool copy_self_identity(struct lichen_app_identity_self *identity)
{
	return identity != NULL &&
	       lichen_app_identity_copy_self(identity) == 0 &&
	       identity->has_public_key;
}
#endif

static int enqueue_contacts_empty(struct lichen_meshcore_adapter *adapter)
{
	uint8_t start[5] = { LICHEN_MESHCORE_RESP_CONTACTS_START };
	uint8_t end[5] = { LICHEN_MESHCORE_RESP_END_OF_CONTACTS };
	int ret;

	if (adapter->ops.tx_free == NULL) {
		adapter->stats.enqueue_fail_count++;
		return -ENOSYS;
	}
	if (preflight_tx_slots(adapter, 2U) < 0) {
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
	const char *name = "LICHEN";
	const struct lichen_meshcore_compat_settings *settings =
		compat_settings_const(adapter);
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	struct lichen_app_identity_self identity;
#endif

	out[1] = 0x01U; /* chat advert placeholder */
	out[2] = 14U;   /* tx power dBm placeholder */
	out[3] = 22U;   /* max tx power placeholder */
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	if (copy_self_identity(&identity)) {
		memcpy(&out[LICHEN_MESHCORE_SELF_INFO_PUBLIC_KEY_OFF],
		       identity.public_key,
		       LICHEN_MESHCORE_SELF_INFO_PUBLIC_KEY_LEN);
		if (identity.display_name[0] != '\0') {
			name = identity.display_name;
		}
	}
#endif
	if (settings->advert_name_valid) {
		name = settings->advert_name;
	}
	out[44] = 0U;   /* multi ACKs */
	out[45] = 0U;   /* location policy */
	out[46] = 0U;   /* telemetry modes */
	out[47] = 0U;   /* manual add contacts */
	sys_put_le32(868000000U, &out[48]);
	sys_put_le32(125000U, &out[52]);
	out[56] = 10U;  /* SF10 */
	out[57] = 5U;   /* CR 4/5 representation */
	copy_fixed_string(&out[LICHEN_MESHCORE_SELF_INFO_NAME_OFF],
			  LICHEN_MESHCORE_SELF_INFO_NAME_LEN, "LICHEN", name);
	return enqueue(adapter, out, sizeof(out));
}

static int enqueue_device_info(struct lichen_meshcore_adapter *adapter)
{
	uint8_t out[LICHEN_MESHCORE_DEVICE_INFO_LEN] = {
		LICHEN_MESHCORE_RESP_DEVICE_INFO,
	};
	const char *build = "LICHEN";
	const char *model = "LICHEN";
	const char *version = "0.0.0";
	const struct lichen_meshcore_compat_settings *settings =
		compat_settings_const(adapter);
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	struct lichen_app_identity_self identity;

	if (copy_self_identity(&identity)) {
		if (identity.firmware_name[0] != '\0') {
			build = identity.firmware_name;
			version = identity.firmware_name;
		}
		if (identity.display_name[0] != '\0') {
			model = identity.display_name;
		}
	}
#endif
	if (settings->advert_name_valid) {
		model = settings->advert_name;
	}

	out[1] = LICHEN_MESHCORE_APP_PROTOCOL_VERSION;
	out[2] = 0U; /* max contacts / 2 */
	out[3] = 1U; /* one placeholder public channel */
	if (settings->device_pin_valid) {
		sys_put_le32(settings->device_pin, &out[4]);
	}
	copy_fixed_string(&out[LICHEN_MESHCORE_DEVICE_INFO_BUILD_OFF],
			  LICHEN_MESHCORE_DEVICE_INFO_BUILD_LEN, "LICHEN",
			  build);
	copy_fixed_string(&out[LICHEN_MESHCORE_DEVICE_INFO_MODEL_OFF],
			  LICHEN_MESHCORE_DEVICE_INFO_MODEL_LEN, "LICHEN",
			  model);
	copy_fixed_string(&out[LICHEN_MESHCORE_DEVICE_INFO_VERSION_OFF],
			  LICHEN_MESHCORE_DEVICE_INFO_VERSION_LEN, "0.0.0",
			  version);
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

static struct lichen_meshcore_pending_event *
pending_tail(struct lichen_meshcore_adapter *adapter)
{
	__ASSERT_NO_MSG(adapter->pending_tail < ARRAY_SIZE(adapter->pending));
	return &adapter->pending[adapter->pending_tail];
}

static const struct lichen_meshcore_pending_event *
pending_head(const struct lichen_meshcore_adapter *adapter)
{
	__ASSERT_NO_MSG(adapter->pending_head < ARRAY_SIZE(adapter->pending));
	return &adapter->pending[adapter->pending_head];
}

static void pending_push(struct lichen_meshcore_adapter *adapter)
{
	adapter->pending_tail =
		(adapter->pending_tail + 1U) %
		ARRAY_SIZE(adapter->pending);
	adapter->pending_count++;
}

static void pending_pop(struct lichen_meshcore_adapter *adapter)
{
	if (adapter->pending_count == 0U) {
		return;
	}

	memset(&adapter->pending[adapter->pending_head], 0,
	       sizeof(adapter->pending[adapter->pending_head]));
	adapter->pending_head =
		(adapter->pending_head + 1U) %
		ARRAY_SIZE(adapter->pending);
	adapter->pending_count--;
}

static void pending_drop_tail(struct lichen_meshcore_adapter *adapter)
{
	/* Reentrancy requirement: Must not be called from interrupt context
	 * (or must be protected by irq_lock/irq_unlock) because the
	 * tail update + memset + count decrement sequence is not atomic.
	 * pending_count == 0U guard prevents uint8_t underflow wrap.
	 * Python (link/tx_queue.py) and Rust (lichen-core/tx_queue.rs)
	 * now model equivalent non-atomic expire/preempt/rebuild ops
	 * with matching documentation and external-sync requirement.
	 */
	if (adapter->pending_count == 0U) {
		return;
	}

	adapter->pending_tail =
		(adapter->pending_tail + ARRAY_SIZE(adapter->pending) - 1U) %
		ARRAY_SIZE(adapter->pending);
	memset(&adapter->pending[adapter->pending_tail], 0,
	       sizeof(adapter->pending[adapter->pending_tail]));
	adapter->pending_count--;
}

static int encode_pending_text(const struct lichen_meshcore_pending_event *event,
			       uint8_t *out, size_t out_len)
{
	size_t len;

	if (event->payload_len > LICHEN_MESHCORE_FRAME_MAX -
				 LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN) {
		return -EINVAL;
	}
	len = LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN + event->payload_len;

	/* SECURITY: Guard against corrupted payload_len reading beyond buffer */
	if (event->payload_len > LICHEN_MESHCORE_FRAME_MAX) {
		return -EINVAL;
	}
	if (out == NULL || out_len < len) {
		return -ENOMEM;
	}

	out[0] = LICHEN_MESHCORE_RESP_CHANNEL_MSG_RECV_V3;
	out[1] = 0U; /* unknown RSSI/SNR */
	out[2] = 0U;
	out[3] = 0U;
	out[4] = 0U; /* compatibility public channel */
	out[5] = 0xffU; /* path unavailable */
	out[6] = 0U; /* plain text */
	sys_put_le32(event->has_id ? event->id : 0U, &out[7]);
	if (event->payload_len > 0U) {
		memcpy(&out[LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN],
		       event->payload, event->payload_len);
	}
	return (int)len;
}

static int encode_pending_status(
	const struct lichen_meshcore_pending_event *event,
	uint8_t *out, size_t out_len)
{
	uint32_t ack_id = event->request_id != 0U ?
			  event->request_id : event->id;

	if (out == NULL || out_len < LICHEN_MESHCORE_STATUS_ACK_LEN) {
		return -ENOMEM;
	}

	out[0] = LICHEN_MESHCORE_PUSH_SEND_CONFIRMED;
	sys_put_le32(ack_id, &out[1]);
	out[5] = (uint8_t)event->error_reason;
	out[6] = event->has_error_reason ? 1U : 0U;
	return LICHEN_MESHCORE_STATUS_ACK_LEN;
}

static int enqueue_next_pending(struct lichen_meshcore_adapter *adapter)
{
	const struct lichen_meshcore_pending_event *event;
	int ret;

	if (adapter->pending_count == 0U) {
		uint8_t none = LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES;
		return enqueue(adapter, &none, sizeof(none));
	}

	event = pending_head(adapter);
	switch (event->kind) {
	case LICHEN_MESHCORE_PENDING_TEXT:
		ret = encode_pending_text(event, adapter->tx_buf,
					  sizeof(adapter->tx_buf));
		break;
	case LICHEN_MESHCORE_PENDING_STATUS:
		ret = encode_pending_status(event, adapter->tx_buf,
					    sizeof(adapter->tx_buf));
		break;
	default:
		adapter->stats.pending_drop_count++;
		pending_pop(adapter);
		return -EINVAL;
	}
	if (ret < 0) {
		return ret;
	}

	ret = enqueue(adapter, adapter->tx_buf, (size_t)ret);
	if (ret >= 0) {
		pending_pop(adapter);
	}
	return ret;
}

static int enqueue_channel(struct lichen_meshcore_adapter *adapter,
			   const struct lichen_meshcore_frame_view *view)
{
	uint8_t out[LICHEN_MESHCORE_CHANNEL_INFO_LEN] = {
		LICHEN_MESHCORE_RESP_CHANNEL_INFO,
	};
	const char name[] = "Public";
	const struct lichen_meshcore_compat_settings *settings =
		compat_settings_const(adapter);

	if (view->payload_len < 1U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (view->payload[0] != 0U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}

	if (settings->channel0_valid) {
		memcpy(&out[1], settings->channel0_body,
		       sizeof(settings->channel0_body));
		return enqueue(adapter, out, sizeof(out));
	}

	out[1] = 0U;
	memcpy(&out[2], name, sizeof(name) - 1U);
	return enqueue(adapter, out, sizeof(out));
}

static uint8_t meshcore_error_from_errno(int err)
{
	switch (err) {
	case -ENOENT:
	case -ENODEV:
	case -ENOTCONN:
		return LICHEN_MESHCORE_ERR_NOT_FOUND;
	case -ENOMEM:
	case -ENOSPC:
		return LICHEN_MESHCORE_ERR_TABLE_FULL;
	case -EAGAIN:
	case -EBUSY:
	case -EALREADY:
		return LICHEN_MESHCORE_ERR_BAD_STATE;
	case -EINVAL:
	case -EMSGSIZE:
	case -ERANGE:
		return LICHEN_MESHCORE_ERR_ILLEGAL_ARG;
	default:
		return LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD;
	}
}

static bool valid_utf8_text(const uint8_t *payload, size_t payload_len)
{
	size_t i = 0U;

	while (i < payload_len) {
		uint8_t c = payload[i];

		if (c < 0x80U) {
			i++;
		} else if (c >= 0xc2U && c <= 0xdfU) {
			if (i + 1U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 2U;
		} else if (c == 0xe0U) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0xa0U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if ((c >= 0xe1U && c <= 0xecU) ||
			   (c >= 0xeeU && c <= 0xefU)) {
			if (i + 2U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xedU) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x9fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xf0U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x90U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c >= 0xf1U && c <= 0xf3U) {
			if (i + 3U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c == 0xf4U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x8fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else {
			return false;
		}
	}
	return true;
}

static bool valid_decimal_pin(uint32_t pin)
{
	return pin == 0U || (pin >= 100000U && pin <= 999999U);
}

static bool valid_name_text(const uint8_t *payload, size_t payload_len)
{
	if (!valid_utf8_text(payload, payload_len)) {
		return false;
	}
	for (size_t i = 0U; i < payload_len; i++) {
		if (payload[i] == 0U) {
			return false;
		}
	}
	return true;
}

static bool valid_default_flood_name(const uint8_t *payload)
{
	size_t len = strnlen((const char *)payload,
			     LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN);
	if (len == 0U || len == LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN) {
		return false;
	}
	return valid_name_text(payload, len);
}

static bool channel_body_has_secret(const uint8_t *payload)
{
	for (size_t i = LICHEN_MESHCORE_CHANNEL_SECRET_OFF;
	     i < LICHEN_MESHCORE_CHANNEL_BODY_LEN; i++) {
		if (payload[i] != 0U) {
			return true;
		}
	}
	return false;
}

static int preflight_tx_slots(struct lichen_meshcore_adapter *adapter,
			      uint32_t needed);

static int persist_settings_or_error(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_compat_settings *old_settings)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	int ret;

	if (adapter->ops.persist_settings == NULL) {
		return 0;
	}

	ret = adapter->ops.persist_settings(settings, adapter->ops.user_data);
	if (ret < 0) {
		*settings = *old_settings;
		return enqueue_error(adapter, meshcore_error_from_errno(ret));
	}
	return 0;
}

static int commit_settings_with_ok(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_compat_settings *old_settings)
{
	int ret = persist_settings_or_error(adapter, old_settings);

	if (ret < 0) {
		return ret;
	}

	ret = enqueue_ok(adapter);
	return ret;
}

static int reset_compat_settings(struct lichen_meshcore_adapter *adapter,
				 const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;
	int ret;

	if (view->payload_len != 0U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}

	old_settings = *settings;
	lichen_meshcore_compat_settings_reset(settings);
	if (adapter->ops.apply_pin != NULL &&
	    adapter->ops.apply_pin(0U, adapter->ops.user_data) < 0) {
		*settings = old_settings;
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_BAD_STATE);
	}

	ret = persist_settings_or_error(adapter, &old_settings);
	if (ret < 0) {
		if (adapter->ops.apply_pin != NULL) {
			(void)adapter->ops.apply_pin(
				old_settings.device_pin_valid ?
					old_settings.device_pin : 0U,
				adapter->ops.user_data);
		}
		return ret;
	}

	ret = enqueue_ok(adapter);
	return ret;
}

static int store_advert_name(struct lichen_meshcore_adapter *adapter,
			     const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;
	uint8_t len;

	if (view->payload_len == 0U ||
	    view->payload_len >= LICHEN_MESHCORE_ADVERT_NAME_MAX ||
	    !valid_name_text(view->payload, view->payload_len)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}

	old_settings = *settings;
	len = (uint8_t)view->payload_len;
	memset(settings->advert_name, 0, sizeof(settings->advert_name));
	memcpy(settings->advert_name, view->payload, len);
	settings->advert_name_len = len;
	settings->advert_name_valid = true;
	return commit_settings_with_ok(adapter, &old_settings);
}

static int store_channel(struct lichen_meshcore_adapter *adapter,
			 const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;

	if (view->payload_len == 65U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	if (view->payload_len != LICHEN_MESHCORE_CHANNEL_BODY_LEN) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (view->payload[0] != 0U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}
	if (channel_body_has_secret(view->payload)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}

	old_settings = *settings;
	memcpy(settings->channel0_body, view->payload,
	       sizeof(settings->channel0_body));
	settings->channel0_valid = true;
	return commit_settings_with_ok(adapter, &old_settings);
}

static int store_device_pin(struct lichen_meshcore_adapter *adapter,
			    const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;
	uint32_t pin;
	int ret;

	if (view->payload_len != sizeof(uint32_t)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}

	pin = sys_get_le32(view->payload);
	if (!valid_decimal_pin(pin)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (adapter->ops.apply_pin == NULL) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}
	if (adapter->ops.apply_pin(pin, adapter->ops.user_data) < 0) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_BAD_STATE);
	}

	old_settings = *settings;
	settings->device_pin = pin;
	settings->device_pin_valid = true;
	ret = persist_settings_or_error(adapter, &old_settings);
	if (ret < 0) {
		(void)adapter->ops.apply_pin(old_settings.device_pin_valid ?
						     old_settings.device_pin : 0U,
					     adapter->ops.user_data);
		return ret;
	}

	ret = enqueue_ok(adapter);
	return ret;
}

static int store_autoadd_config(struct lichen_meshcore_adapter *adapter,
				const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;

	if (view->payload_len != LICHEN_MESHCORE_AUTOADD_CONFIG_LEN) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}

	old_settings = *settings;
	memcpy(settings->autoadd_config, view->payload,
	       sizeof(settings->autoadd_config));
	settings->autoadd_config_valid = true;
	return commit_settings_with_ok(adapter, &old_settings);
}

static int store_default_flood_scope(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_frame_view *view)
{
	struct lichen_meshcore_compat_settings *settings =
		compat_settings(adapter);
	struct lichen_meshcore_compat_settings old_settings;

	if (view->payload_len != 0U &&
	    view->payload_len != LICHEN_MESHCORE_DEFAULT_FLOOD_PAYLOAD_LEN) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (view->payload_len == LICHEN_MESHCORE_DEFAULT_FLOOD_PAYLOAD_LEN &&
	    !valid_default_flood_name(view->payload)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (preflight_tx_slots(adapter, 1U) < 0) {
		return -ENOMEM;
	}

	old_settings = *settings;
	if (view->payload_len == 0U) {
		memset(settings->default_flood_name, 0,
		       sizeof(settings->default_flood_name));
		memset(settings->default_flood_key, 0,
		       sizeof(settings->default_flood_key));
		settings->default_flood_scope_valid = false;
		return commit_settings_with_ok(adapter, &old_settings);
	}

	memcpy(settings->default_flood_name, view->payload,
	       sizeof(settings->default_flood_name));
	memcpy(settings->default_flood_key,
	       &view->payload[LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN],
	       sizeof(settings->default_flood_key));
	settings->default_flood_scope_valid = true;
	return commit_settings_with_ok(adapter, &old_settings);
}

static int preflight_tx_slots(struct lichen_meshcore_adapter *adapter,
			      uint32_t needed)
{
	if (adapter->ops.tx_free == NULL ||
	    adapter->ops.tx_free(adapter->ops.user_data) < needed) {
		adapter->stats.enqueue_fail_count++;
		return -ENOMEM;
	}
	return 0;
}

static int enqueue_channel_text_send(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_frame_view *view)
{
	uint8_t out[1];
	uint8_t channel;
	uint8_t text_type;
	const uint8_t *payload;
	size_t payload_len;
	int ret;

	if (view->payload_len < 2U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (adapter->ops.submit_text == NULL) {
		return enqueue_error(adapter,
				     LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}

	channel = view->payload[0];
	text_type = view->payload[1];
	payload = &view->payload[2];
	payload_len = view->payload_len - 2U;
	if (channel != 0U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}
	if (text_type != 0U) {
		return enqueue_error(adapter,
				     LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	if (!valid_utf8_text(payload, payload_len)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}

	ret = preflight_tx_slots(adapter, 1U);
	if (ret < 0) {
		return ret;
	}

	ret = adapter->ops.submit_text(channel, text_type, NULL, payload,
				       payload_len, adapter->ops.user_data);
	if (ret < 0) {
		return enqueue_error(adapter, meshcore_error_from_errno(ret));
	}

	ret = lichen_meshcore_encode_ok(out, sizeof(out));
	if (ret < 0) {
		return ret;
	}
	adapter->stats.submitted_text_count++;
	return enqueue(adapter, out, (size_t)ret);
}

static int enqueue_direct_text_send(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_frame_view *view)
{
	uint8_t out[1];
	uint8_t to_iid[8];
	const uint8_t *payload;
	size_t payload_len;
	int ret;

	if (view->payload_len < 6U) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	payload = &view->payload[6];
	payload_len = view->payload_len - 6U;
	if (!valid_utf8_text(payload, payload_len)) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	if (adapter->ops.resolve_peer_prefix == NULL) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}
	ret = adapter->ops.resolve_peer_prefix(view->payload, to_iid,
					       adapter->ops.user_data);
	if (ret < 0) {
		return enqueue_error(adapter, LICHEN_MESHCORE_ERR_NOT_FOUND);
	}
	if (adapter->ops.submit_text == NULL) {
		return enqueue_error(adapter,
				     LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	ret = preflight_tx_slots(adapter, 1U);
	if (ret < 0) {
		return ret;
	}

	ret = adapter->ops.submit_text(0U, 0U, to_iid, payload, payload_len,
				       adapter->ops.user_data);
	if (ret < 0) {
		return enqueue_error(adapter, meshcore_error_from_errno(ret));
	}

	ret = lichen_meshcore_encode_ok(out, sizeof(out));
	if (ret < 0) {
		return ret;
	}
	adapter->stats.submitted_text_count++;
	return enqueue(adapter, out, (size_t)ret);
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
	case LICHEN_MESHCORE_CMD_SEND_TXT_MSG:
		return enqueue_direct_text_send(adapter, view);
	case LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG:
		return enqueue_channel_text_send(adapter, view);
	case LICHEN_MESHCORE_CMD_SET_ADVERT_NAME:
		return store_advert_name(adapter, view);
	case LICHEN_MESHCORE_CMD_SET_CHANNEL:
		return store_channel(adapter, view);
	case LICHEN_MESHCORE_CMD_SET_DEVICE_PIN:
		return store_device_pin(adapter, view);
	case LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE:
		return view->payload_len == 0U ?
			enqueue_next_pending(adapter) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
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
		uint8_t out[] = { LICHEN_MESHCORE_RESP_AUTOADD_CONFIG, 0U, 0U };
		const struct lichen_meshcore_compat_settings *settings =
			compat_settings_const(adapter);

		if (settings->autoadd_config_valid) {
			memcpy(&out[1], settings->autoadd_config,
			       sizeof(settings->autoadd_config));
		}
		return view->payload_len == 0U ?
			enqueue(adapter, out, sizeof(out)) :
			enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	}
	case LICHEN_MESHCORE_CMD_SET_AUTOADD_CONFIG:
		return store_autoadd_config(adapter, view);
	case LICHEN_MESHCORE_CMD_GET_DEFAULT_FLOOD_SCOPE: {
		uint8_t out[1U + LICHEN_MESHCORE_DEFAULT_FLOOD_PAYLOAD_LEN] = {
			LICHEN_MESHCORE_RESP_DEFAULT_FLOOD_SCOPE,
		};
		const struct lichen_meshcore_compat_settings *settings =
			compat_settings_const(adapter);

		if (view->payload_len != 0U) {
			return enqueue_error(adapter, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
		}
		if (settings->default_flood_scope_valid) {
			memcpy(&out[1], settings->default_flood_name,
			       sizeof(settings->default_flood_name));
			memcpy(&out[1U + LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN],
			       settings->default_flood_key,
			       sizeof(settings->default_flood_key));
			return enqueue(adapter, out, sizeof(out));
		}
		return enqueue(adapter, out, 1U);
	}
	case LICHEN_MESHCORE_CMD_SET_DEFAULT_FLOOD_SCOPE:
		return store_default_flood_scope(adapter, view);
	case LICHEN_MESHCORE_CMD_FACTORY_RESET:
		return reset_compat_settings(adapter, view);
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
	adapter->ops = *ops;
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

	if (adapter == NULL || data == NULL) {
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

int lichen_meshcore_adapter_emit_text(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_incoming_text *event)
{
	struct lichen_meshcore_pending_event *pending;
	const uint8_t waiting = LICHEN_MESHCORE_PUSH_MSG_WAITING;
	int ret;

	if (adapter == NULL || event == NULL ||
	    (event->payload == NULL && event->payload_len > 0U)) {
		return -EINVAL;
	}
	if (event->payload_len >
	    LICHEN_MESHCORE_FRAME_MAX -
	    LICHEN_MESHCORE_CHANNEL_MSG_V3_HEADER_LEN) {
		return -EMSGSIZE;
	}
	if (adapter->pending_count == ARRAY_SIZE(adapter->pending)) {
		adapter->stats.pending_full_count++;
		return -ENOMEM;
	}

	pending = pending_tail(adapter);
	memset(pending, 0, sizeof(*pending));
	pending->kind = LICHEN_MESHCORE_PENDING_TEXT;
	pending->from = event->from;
	pending->to = event->to;
	pending->id = event->id;
	pending->has_id = event->has_id;
	pending->payload_len = (uint16_t)event->payload_len;
	if (event->payload_len > 0U) {
		memcpy(pending->payload, event->payload, event->payload_len);
	}
	pending_push(adapter);
	adapter->stats.incoming_text_count++;

	ret = enqueue(adapter, &waiting, sizeof(waiting));
	if (ret < 0) {
		adapter->stats.waiting_push_fail_count++;
		pending_drop_tail(adapter);
		return ret;
	}
	return 0;
}

int lichen_meshcore_adapter_emit_status(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_incoming_status *event)
{
	struct lichen_meshcore_pending_event *pending;
	const uint8_t waiting = LICHEN_MESHCORE_PUSH_MSG_WAITING;
	int ret;

	if (adapter == NULL || event == NULL) {
		return -EINVAL;
	}
	if (!event->has_id && event->request_id == 0U) {
		return -ENOTSUP;
	}
	if (event->has_error_reason && event->error_reason > UINT8_MAX) {
		return -ERANGE;
	}
	if (adapter->pending_count == ARRAY_SIZE(adapter->pending)) {
		adapter->stats.pending_full_count++;
		return -ENOMEM;
	}

	pending = pending_tail(adapter);
	memset(pending, 0, sizeof(*pending));
	pending->kind = LICHEN_MESHCORE_PENDING_STATUS;
	pending->from = event->from;
	pending->to = event->to;
	pending->id = event->id;
	pending->request_id = event->request_id;
	pending->error_reason = event->error_reason;
	pending->has_id = event->has_id;
	pending->has_error_reason = event->has_error_reason;
	pending_push(adapter);
	adapter->stats.incoming_status_count++;

	ret = enqueue(adapter, &waiting, sizeof(waiting));
	if (ret < 0) {
		adapter->stats.waiting_push_fail_count++;
		pending_drop_tail(adapter);
		return ret;
	}
	return 0;
}

const struct lichen_meshcore_adapter_stats *_Nonnull
lichen_meshcore_adapter_get_stats(
	const struct lichen_meshcore_adapter *_Nonnull adapter)
{
	/* _Nonnull on return and param: stats is embedded struct; never NULL. */
	return &adapter->stats;
}
