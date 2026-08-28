/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_alert.c
 * @brief Keyed authenticated operator events for TOFU mismatches
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <monocypher.h>
#include <lichen/coap_keys_alert.h>

#define ALERT_MAGIC 0x414d4b4cU /* "LKMA" on the wire */
#define ALERT_VERSION 1U
#define ALERT_FLAGS_AUTHENTICATED 0x01U
#define ALERT_TAG_OFFSET 104U
#define ALERT_TAG_LEN 32U

struct alert_sink_state {
	uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN];
	lichen_key_alert_transport_cb transport;
	void *user;
	bool initialized;
};

K_MUTEX_DEFINE(s_alert_sink_mutex);
static struct alert_sink_state s_sink;
static uint8_t s_payload[LICHEN_KEY_ALERT_WIRE_LEN];

static bool auth_key_valid(const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN])
{
	uint8_t any = 0;

	for (size_t i = 0; i < LICHEN_KEY_ALERT_AUTH_KEY_LEN; i++) {
		any |= auth_key[i];
	}
	return any != 0;
}

static void put_le32(uint8_t out[4], uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_le32(const uint8_t in[4])
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
	       ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_le64(uint8_t out[8], uint64_t value)
{
	for (size_t i = 0; i < 8; i++) {
		out[i] = (uint8_t)(value >> (i * 8U));
	}
}

static uint64_t get_le64(const uint8_t in[8])
{
	uint64_t value = 0;

	for (size_t i = 0; i < 8; i++) {
		value |= (uint64_t)in[i] << (i * 8U);
	}
	return value;
}

static void make_tag(const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
		     const uint8_t payload[ALERT_TAG_OFFSET],
		     uint8_t tag[ALERT_TAG_LEN])
{
	static const uint8_t domain[] = "LICHEN-TOFU-OPERATOR-ALERT-v1";
	crypto_blake2b_ctx hash;

	crypto_blake2b_keyed_init(&hash, ALERT_TAG_LEN, auth_key,
				  LICHEN_KEY_ALERT_AUTH_KEY_LEN);
	crypto_blake2b_update(&hash, domain, sizeof(domain) - 1U);
	crypto_blake2b_update(&hash, payload, ALERT_TAG_OFFSET);
	crypto_blake2b_final(&hash, tag);
}

static int encode_event(
	const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
	const struct lichen_key_mismatch_audit *event,
	uint8_t payload[LICHEN_KEY_ALERT_WIRE_LEN])
{
	if (event == NULL || !event->valid || event->sequence == 0 ||
	    event->attempts == 0 || event->last_delivery_error > 0) {
		return -EINVAL;
	}
	memset(payload, 0, LICHEN_KEY_ALERT_WIRE_LEN);
	put_le32(payload, ALERT_MAGIC);
	payload[4] = ALERT_VERSION;
	payload[5] = ALERT_FLAGS_AUTHENTICATED;
	payload[6] = (uint8_t)LICHEN_KEY_ALERT_WIRE_LEN;
	payload[7] = (uint8_t)(LICHEN_KEY_ALERT_WIRE_LEN >> 8);
	put_le64(&payload[8], event->sequence);
	put_le32(&payload[16], event->first_seen);
	put_le32(&payload[20], event->last_seen);
	put_le32(&payload[24], event->attempts);
	put_le32(&payload[28], (uint32_t)event->last_delivery_error);
	memcpy(&payload[32], event->iid, LICHEN_KEY_IID_LEN);
	memcpy(&payload[40], event->pinned_pubkey, LICHEN_KEY_PUBKEY_LEN);
	memcpy(&payload[72], event->presented_pubkey, LICHEN_KEY_PUBKEY_LEN);
	make_tag(auth_key, payload, &payload[ALERT_TAG_OFFSET]);
	return 0;
}

static int deliver_event(void *user,
			 const struct lichen_key_mismatch_audit *event)
{
	int ret;

	ARG_UNUSED(user);
	k_mutex_lock(&s_alert_sink_mutex, K_FOREVER);
	if (!s_sink.initialized || s_sink.transport == NULL) {
		k_mutex_unlock(&s_alert_sink_mutex);
		return -ENOTCONN;
	}
	ret = encode_event(s_sink.auth_key, event, s_payload);
	if (ret == 0) {
		ret = s_sink.transport(s_sink.user, s_payload, sizeof(s_payload));
		if (ret > 0) {
			ret = -EPROTO;
		}
	}
	crypto_wipe(s_payload, sizeof(s_payload));
	k_mutex_unlock(&s_alert_sink_mutex);
	return ret;
}

int lichen_key_alert_sink_init(
	const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
	lichen_key_alert_transport_cb transport, void *user)
{
	if (auth_key == NULL || transport == NULL) {
		return -EINVAL;
	}
	if (!auth_key_valid(auth_key)) {
		return -EKEYREJECTED;
	}
	k_mutex_lock(&s_alert_sink_mutex, K_FOREVER);
	crypto_wipe(&s_sink, sizeof(s_sink));
	memcpy(s_sink.auth_key, auth_key, sizeof(s_sink.auth_key));
	s_sink.transport = transport;
	s_sink.user = user;
	s_sink.initialized = true;
	k_mutex_unlock(&s_alert_sink_mutex);
	return lichen_key_store_set_mismatch_alert_cb(deliver_event, NULL);
}

int lichen_key_alert_sink_retry(void)
{
	bool initialized;

	k_mutex_lock(&s_alert_sink_mutex, K_FOREVER);
	initialized = s_sink.initialized;
	k_mutex_unlock(&s_alert_sink_mutex);
	if (!initialized) {
		return -EACCES;
	}
	return lichen_key_store_set_mismatch_alert_cb(deliver_event, NULL);
}

void lichen_key_alert_sink_deinit(void)
{
	bool initialized;

	k_mutex_lock(&s_alert_sink_mutex, K_FOREVER);
	initialized = s_sink.initialized;
	k_mutex_unlock(&s_alert_sink_mutex);
	if (!initialized) {
		return;
	}
	(void)lichen_key_store_set_mismatch_alert_cb(NULL, NULL);
	k_mutex_lock(&s_alert_sink_mutex, K_FOREVER);
	crypto_wipe(&s_sink, sizeof(s_sink));
	crypto_wipe(s_payload, sizeof(s_payload));
	k_mutex_unlock(&s_alert_sink_mutex);
}

int lichen_key_alert_decode(
	const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
	const uint8_t *payload, size_t len,
	struct lichen_key_mismatch_audit *event)
{
	struct lichen_key_mismatch_audit decoded = { 0 };
	uint8_t expected_tag[ALERT_TAG_LEN];
	uint32_t error_wire;
	int64_t signed_error;

	if (auth_key == NULL || payload == NULL || event == NULL) {
		return -EINVAL;
	}
	if (!auth_key_valid(auth_key)) {
		return -EKEYREJECTED;
	}
	if (len != LICHEN_KEY_ALERT_WIRE_LEN) {
		return -EMSGSIZE;
	}
	if (get_le32(payload) != ALERT_MAGIC || payload[4] != ALERT_VERSION ||
	    payload[5] != ALERT_FLAGS_AUTHENTICATED ||
	    ((size_t)payload[6] | ((size_t)payload[7] << 8)) != len) {
		return -EBADMSG;
	}
	make_tag(auth_key, payload, expected_tag);
	if (crypto_verify32(expected_tag, &payload[ALERT_TAG_OFFSET]) != 0) {
		crypto_wipe(expected_tag, sizeof(expected_tag));
		return -EKEYREJECTED;
	}
	crypto_wipe(expected_tag, sizeof(expected_tag));
	decoded.sequence = get_le64(&payload[8]);
	decoded.first_seen = get_le32(&payload[16]);
	decoded.last_seen = get_le32(&payload[20]);
	decoded.attempts = get_le32(&payload[24]);
	error_wire = get_le32(&payload[28]);
	signed_error = error_wire;
	if ((error_wire & 0x80000000U) != 0) {
		signed_error -= (int64_t)UINT32_MAX + 1;
	}
	if (signed_error < INT_MIN || signed_error > 0 ||
	    decoded.sequence == 0 || decoded.attempts == 0 ||
	    decoded.last_seen < decoded.first_seen) {
		return -EBADMSG;
	}
	decoded.last_delivery_error = (int)signed_error;
	memcpy(decoded.iid, &payload[32], LICHEN_KEY_IID_LEN);
	memcpy(decoded.pinned_pubkey, &payload[40], LICHEN_KEY_PUBKEY_LEN);
	memcpy(decoded.presented_pubkey, &payload[72], LICHEN_KEY_PUBKEY_LEN);
	decoded.valid = true;
	*event = decoded;
	return 0;
}
