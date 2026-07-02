/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "announce_ingest.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/l2_payload.h>
#include <lichen/schnorr48.h>

#include "ipv6_addr.h"
#include "network_location.h"

#define ANNOUNCE_SIGNED_PREFIX_LEN \
	(GATEWAY_ANNOUNCE_IID_LEN + GATEWAY_ANNOUNCE_PUBKEY_LEN + 2U)
#define ANNOUNCE_SIGNED_MAX_LEN 256U
#define ANNOUNCE_APP_DATA_MAX_LEN \
	(ANNOUNCE_SIGNED_MAX_LEN - ANNOUNCE_SIGNED_PREFIX_LEN)

struct announce_peer_pin {
	bool active;
	uint8_t iid[GATEWAY_ANNOUNCE_IID_LEN];
	uint8_t pubkey[GATEWAY_ANNOUNCE_PUBKEY_LEN];
	uint16_t seq_num;
	uint32_t location_seq_num;
	uint32_t last_seen_uptime_s;
};

static K_MUTEX_DEFINE(announce_peer_mutex);
static struct announce_peer_pin announce_peers[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];

static bool announce_seq_newer(uint16_t seq_num, uint16_t previous_seq_num)
{
	return seq_num != previous_seq_num &&
	       (uint16_t)(seq_num - previous_seq_num) < 0x8000U;
}

static bool uptime_newer_or_equal(uint32_t now_uptime_s,
				  uint32_t observed_uptime_s,
				  uint32_t *age_s)
{
	uint32_t delta;

	if (now_uptime_s == observed_uptime_s) {
		*age_s = 0U;
		return true;
	}

	delta = now_uptime_s - observed_uptime_s;
	if (delta == 0U || delta >= 0x80000000U) {
		return false;
	}

	*age_s = delta;
	return true;
}

static bool downstream_record_expired(
	uint32_t now_uptime_s,
	const struct gateway_network_location_announce_record *record)
{
	uint32_t age_s;

	return uptime_newer_or_equal(now_uptime_s,
				     record->observed_uptime_s, &age_s) &&
	       age_s > CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S;
}

static uint32_t extend_location_seq(uint16_t seq_num,
				    uint32_t previous_location_seq_num)
{
	uint16_t previous_seq_num = (uint16_t)previous_location_seq_num;
	uint32_t location_seq_num =
		(previous_location_seq_num & 0xffff0000U) | seq_num;

	if (seq_num < previous_seq_num) {
		location_seq_num += 0x10000U;
	}

	return location_seq_num;
}

static void restore_peer_slot(struct announce_peer_pin *peer,
			      bool old_peer_valid,
			      const struct announce_peer_pin *old_peer)
{
	if (old_peer_valid) {
		*peer = *old_peer;
	} else {
		memset(peer, 0, sizeof(*peer));
	}
}

static struct announce_peer_pin *find_peer_locked(const uint8_t iid[8])
{
	for (size_t i = 0U; i < ARRAY_SIZE(announce_peers); i++) {
		if (announce_peers[i].active &&
		    memcmp(announce_peers[i].iid, iid, GATEWAY_ANNOUNCE_IID_LEN) == 0) {
			return &announce_peers[i];
		}
	}

	return NULL;
}

static struct announce_peer_pin *allocate_peer_locked(uint32_t observed_uptime_s)
{
	struct announce_peer_pin *oldest = NULL;

	for (size_t i = 0U; i < ARRAY_SIZE(announce_peers); i++) {
		if (!announce_peers[i].active) {
			return &announce_peers[i];
		}
		if (oldest == NULL ||
		    (int32_t)(announce_peers[i].last_seen_uptime_s -
			      oldest->last_seen_uptime_s) < 0) {
			oldest = &announce_peers[i];
		}
	}

	return oldest;
}

static int build_signed_data(const struct gateway_announce_view *announce,
			     uint8_t *buf, size_t buf_len, size_t *out_len)
{
	size_t len;

	if (announce == NULL || buf == NULL || out_len == NULL) {
		return -EINVAL;
	}
	if (announce->app_data_len > ANNOUNCE_APP_DATA_MAX_LEN) {
		return -EMSGSIZE;
	}

	len = ANNOUNCE_SIGNED_PREFIX_LEN + announce->app_data_len;
	if (buf_len < len) {
		return -ENOMEM;
	}

	memcpy(&buf[0], announce->originator_iid, GATEWAY_ANNOUNCE_IID_LEN);
	memcpy(&buf[GATEWAY_ANNOUNCE_IID_LEN], announce->pubkey,
	       GATEWAY_ANNOUNCE_PUBKEY_LEN);
	buf[GATEWAY_ANNOUNCE_IID_LEN + GATEWAY_ANNOUNCE_PUBKEY_LEN] =
		(uint8_t)(announce->seq_num >> 8);
	buf[GATEWAY_ANNOUNCE_IID_LEN + GATEWAY_ANNOUNCE_PUBKEY_LEN + 1U] =
		(uint8_t)announce->seq_num;
	memcpy(&buf[ANNOUNCE_SIGNED_PREFIX_LEN], announce->app_data,
	       announce->app_data_len);
	*out_len = len;
	return 0;
}

int gateway_announce_parse(const uint8_t *data, size_t len,
			   struct gateway_announce_view *announce)
{
	if (data == NULL || announce == NULL) {
		return -EINVAL;
	}
	if (len < GATEWAY_ANNOUNCE_MIN_LEN) {
		return -EMSGSIZE;
	}
	if (data[0] != GATEWAY_ANNOUNCE_TYPE) {
		return -EPROTONOSUPPORT;
	}
	if (data[1] != 0U) {
		return -EINVAL;
	}
	if (data[2] > GATEWAY_ANNOUNCE_MAX_HOPS) {
		return -EINVAL;
	}
	if (len - GATEWAY_ANNOUNCE_MIN_LEN > ANNOUNCE_APP_DATA_MAX_LEN) {
		return -EMSGSIZE;
	}

	announce->flags = data[1];
	announce->hop_count = data[2];
	announce->seq_num = ((uint16_t)data[3] << 8) | data[4];
	announce->originator_iid = &data[5];
	announce->pubkey = &data[13];
	announce->signature = &data[45];
	announce->app_data = &data[GATEWAY_ANNOUNCE_MIN_LEN];
	announce->app_data_len = len - GATEWAY_ANNOUNCE_MIN_LEN;
	return 0;
}

int gateway_announce_ingest_verified(const uint8_t *data, size_t len)
{
	struct gateway_announce_view announce;
	uint8_t expected_iid[GATEWAY_ANNOUNCE_IID_LEN];
	uint8_t signed_data[ANNOUNCE_SIGNED_MAX_LEN];
	size_t signed_data_len = 0U;
	uint32_t now_s = k_uptime_get_32() / 1000U;
	struct announce_peer_pin *peer;
	struct gateway_network_location_announce_sample sample;
	bool new_peer = false;
	bool old_peer_valid = false;
	struct announce_peer_pin old_peer;
	uint32_t location_seq_num;
	struct gateway_network_location_announce_record existing_record;
	int ret;

	ret = gateway_announce_parse(data, len, &announce);
	if (ret < 0) {
		return ret;
	}

	ret = lichen_pubkey_to_iid(announce.pubkey, expected_iid);
	if (ret < 0) {
		return ret;
	}
	if (memcmp(announce.originator_iid, expected_iid,
		   GATEWAY_ANNOUNCE_IID_LEN) != 0) {
		return -EACCES;
	}

	ret = build_signed_data(&announce, signed_data, sizeof(signed_data),
				&signed_data_len);
	if (ret < 0) {
		return ret;
	}
	if (!schnorr48_verify(announce.pubkey, signed_data, signed_data_len,
			      announce.signature)) {
		return -EACCES;
	}

	k_mutex_lock(&announce_peer_mutex, K_FOREVER);
	peer = find_peer_locked(announce.originator_iid);
	if (peer != NULL) {
		if (memcmp(peer->pubkey, announce.pubkey,
			   GATEWAY_ANNOUNCE_PUBKEY_LEN) != 0) {
			k_mutex_unlock(&announce_peer_mutex);
			return -EKEYREJECTED;
		}
		if (!announce_seq_newer(announce.seq_num, peer->seq_num)) {
			k_mutex_unlock(&announce_peer_mutex);
			return -EALREADY;
		}
		location_seq_num = extend_location_seq(announce.seq_num,
						       peer->location_seq_num);
	} else {
		peer = allocate_peer_locked(now_s);
		if (peer == NULL) {
			k_mutex_unlock(&announce_peer_mutex);
			return -ENOMEM;
		}
		old_peer_valid = peer->active;
		if (old_peer_valid) {
			old_peer = *peer;
		}
		memset(peer, 0, sizeof(*peer));
		peer->active = true;
		memcpy(peer->iid, announce.originator_iid,
		       GATEWAY_ANNOUNCE_IID_LEN);
		memcpy(peer->pubkey, announce.pubkey,
		       GATEWAY_ANNOUNCE_PUBKEY_LEN);
		new_peer = true;
		ret = gateway_network_location_announce_get(
			announce.originator_iid, GATEWAY_ANNOUNCE_IID_LEN,
			&existing_record);
		if (ret == 0) {
			if (!announce_seq_newer(announce.seq_num,
						(uint16_t)existing_record.seq_num) &&
			    !downstream_record_expired(now_s, &existing_record)) {
				restore_peer_slot(peer, old_peer_valid, &old_peer);
				k_mutex_unlock(&announce_peer_mutex);
				return -EALREADY;
			}
			location_seq_num = extend_location_seq(
				announce.seq_num, existing_record.seq_num);
		} else if (ret == -ENOENT) {
			location_seq_num = announce.seq_num;
		} else {
			restore_peer_slot(peer, old_peer_valid, &old_peer);
			k_mutex_unlock(&announce_peer_mutex);
			return ret;
		}
	}

	sample.peer_id = announce.originator_iid;
	sample.peer_id_len = GATEWAY_ANNOUNCE_IID_LEN;
	sample.seq_num = location_seq_num;
	sample.observed_uptime_s = now_s;
	sample.app_data = announce.app_data;
	sample.app_data_len = announce.app_data_len;
	ret = gateway_network_location_submit_announce(&sample);
	if (ret < 0) {
		if (new_peer) {
			restore_peer_slot(peer, old_peer_valid, &old_peer);
		}
		k_mutex_unlock(&announce_peer_mutex);
		return ret;
	}

	peer->seq_num = announce.seq_num;
	peer->location_seq_num = location_seq_num;
	peer->last_seen_uptime_s = now_s;
	k_mutex_unlock(&announce_peer_mutex);
	return 0;
}

int gateway_announce_ingest_l2_payload(const uint8_t *data, size_t len)
{
	const uint8_t *body;
	size_t body_len;

	if (data == NULL) {
		return -EINVAL;
	}
	if (lichen_l2_payload_classify(data, len) != LICHEN_L2_PAYLOAD_ROUTING) {
		return -EPROTONOSUPPORT;
	}

	body = lichen_l2_payload_body(data, len, &body_len);
	if (body == NULL || body_len == 0U) {
		return -EMSGSIZE;
	}
	if (body[0] != GATEWAY_ANNOUNCE_TYPE) {
		return -EPROTONOSUPPORT;
	}

	return gateway_announce_ingest_verified(body, body_len);
}

void gateway_announce_ingest_reset(void)
{
	k_mutex_lock(&announce_peer_mutex, K_FOREVER);
	memset(announce_peers, 0, sizeof(announce_peers));
	k_mutex_unlock(&announce_peer_mutex);
}
