/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/routing/announce.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <tinycrypt/sha256.h>

#include <lichen/l2_payload.h>
#include <lichen/schnorr48.h>

#define ANNOUNCE_SIGNED_PREFIX_LEN \
	(LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 2U)
#define ANNOUNCE_SIGNED_MAX_LEN 256U
#define ANNOUNCE_APP_DATA_MAX_LEN \
	(ANNOUNCE_SIGNED_MAX_LEN - ANNOUNCE_SIGNED_PREFIX_LEN)

struct announce_peer_pin {
	bool active;
	uint8_t iid[LICHEN_ANNOUNCE_IID_LEN];
	uint8_t pubkey[LICHEN_ANNOUNCE_PUBKEY_LEN];
	uint16_t seq_num;
	uint32_t location_seq_num;
	uint32_t last_seen_uptime_s;
};

struct announce_observer {
	bool active;
	uint8_t flags;
	lichen_announce_app_data_fn cb;
	void *user_data;
};

static K_MUTEX_DEFINE(announce_mutex);
static K_MUTEX_DEFINE(ingest_mutex);
static K_MUTEX_DEFINE(observer_mutex);
static struct announce_peer_pin announce_peers[CONFIG_LICHEN_ROUTING_MAX_PEERS];
static struct announce_observer
	announce_observers[CONFIG_LICHEN_ROUTING_MAX_APP_DATA_OBSERVERS];

static bool announce_seq_newer(uint16_t seq_num, uint16_t previous_seq_num)
{
	return seq_num != previous_seq_num &&
	       (uint16_t)(seq_num - previous_seq_num) < 0x8000U;
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

static int pubkey_to_iid(const uint8_t pubkey[LICHEN_ANNOUNCE_PUBKEY_LEN],
			 uint8_t iid[LICHEN_ANNOUNCE_IID_LEN])
{
	struct tc_sha256_state_struct sha_state;
	uint8_t hash[TC_SHA256_DIGEST_SIZE];

	if (pubkey == NULL || iid == NULL) {
		return -EINVAL;
	}

	(void)tc_sha256_init(&sha_state);
	(void)tc_sha256_update(&sha_state, pubkey, LICHEN_ANNOUNCE_PUBKEY_LEN);
	(void)tc_sha256_final(hash, &sha_state);
	memcpy(iid, hash, LICHEN_ANNOUNCE_IID_LEN);
	iid[0] &= (uint8_t)~0x02U;
	memset(hash, 0, sizeof(hash));
	return 0;
}

static int build_signed_data(const struct lichen_announce_view *announce,
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

	memcpy(&buf[0], announce->originator_iid, LICHEN_ANNOUNCE_IID_LEN);
	memcpy(&buf[LICHEN_ANNOUNCE_IID_LEN], announce->pubkey,
	       LICHEN_ANNOUNCE_PUBKEY_LEN);
	buf[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN] =
		(uint8_t)(announce->wire_seq_num >> 8);
	buf[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 1U] =
		(uint8_t)announce->wire_seq_num;
	memcpy(&buf[ANNOUNCE_SIGNED_PREFIX_LEN], announce->app_data,
	       announce->app_data_len);
	*out_len = len;
	return 0;
}

static struct announce_peer_pin *find_peer_locked(const uint8_t iid[8])
{
	for (size_t i = 0U; i < ARRAY_SIZE(announce_peers); i++) {
		if (announce_peers[i].active &&
		    memcmp(announce_peers[i].iid, iid,
			   LICHEN_ANNOUNCE_IID_LEN) == 0) {
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

static size_t snapshot_observers(struct announce_observer *observers,
				 size_t cap, bool seq_stale_for_pin)
{
	size_t count = 0U;

	k_mutex_lock(&observer_mutex, K_FOREVER);
	for (size_t i = 0U; i < ARRAY_SIZE(announce_observers) && count < cap; i++) {
		if (!announce_observers[i].active) {
			continue;
		}
		if (seq_stale_for_pin &&
		    (announce_observers[i].flags &
		     LICHEN_ANNOUNCE_OBSERVER_F_ALLOW_SEQ_RESET) == 0U) {
			continue;
		}
		observers[count++] = announce_observers[i];
	}
	k_mutex_unlock(&observer_mutex);

	return count;
}

static int notify_observers(const struct lichen_announce_view *announce,
			    const struct lichen_announce_rx_meta *meta,
			    bool seq_stale_for_pin)
{
	struct announce_observer observers[CONFIG_LICHEN_ROUTING_MAX_APP_DATA_OBSERVERS];
	size_t count;
	bool accepted_reset = false;

	count = snapshot_observers(observers, ARRAY_SIZE(observers),
				   seq_stale_for_pin);
	if (seq_stale_for_pin && count == 0U) {
		return -EALREADY;
	}

	for (size_t i = 0U; i < count; i++) {
		int ret = observers[i].cb(announce, meta, observers[i].user_data);

		if (ret < 0) {
			return ret;
		}
		if (seq_stale_for_pin &&
		    ret == LICHEN_ANNOUNCE_ACCEPT_SEQ_RESET) {
			accepted_reset = true;
		}
	}

	if (seq_stale_for_pin && !accepted_reset) {
		return -EALREADY;
	}

	return 0;
}

int lichen_announce_parse(const uint8_t *data, size_t len,
			  struct lichen_announce_view *announce)
{
	if (data == NULL || announce == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_ANNOUNCE_MIN_LEN) {
		return -EMSGSIZE;
	}
	if (data[0] != LICHEN_ANNOUNCE_TYPE) {
		return -EPROTONOSUPPORT;
	}
	if (data[1] != 0U) {
		return -EINVAL;
	}
	if (data[2] > LICHEN_ANNOUNCE_MAX_HOPS) {
		return -EINVAL;
	}
	if (len - LICHEN_ANNOUNCE_MIN_LEN > ANNOUNCE_APP_DATA_MAX_LEN) {
		return -EMSGSIZE;
	}

	announce->flags = data[1];
	announce->hop_count = data[2];
	announce->wire_seq_num = ((uint16_t)data[3] << 8) | data[4];
	announce->seq_num = announce->wire_seq_num;
	announce->seq_stale = false;
	announce->originator_iid = &data[5];
	announce->pubkey = &data[13];
	announce->signature = &data[45];
	announce->app_data = &data[LICHEN_ANNOUNCE_MIN_LEN];
	announce->app_data_len = len - LICHEN_ANNOUNCE_MIN_LEN;
	return 0;
}

int lichen_announce_ingest_authenticated(
	const uint8_t *data, size_t len,
	const struct lichen_announce_rx_meta *meta)
{
	struct lichen_announce_view announce;
	struct lichen_announce_rx_meta default_meta = { 0 };
	uint8_t expected_iid[LICHEN_ANNOUNCE_IID_LEN];
	uint8_t signed_data[ANNOUNCE_SIGNED_MAX_LEN];
	size_t signed_data_len = 0U;
	struct announce_peer_pin *peer;
	uint32_t observed_uptime_s;
	uint32_t location_seq_num;
	bool seq_stale_for_pin = false;
	int ret;

	if (meta == NULL) {
		default_meta.observed_uptime_s = k_uptime_get_32() / 1000U;
		meta = &default_meta;
	}
	observed_uptime_s = meta->observed_uptime_s != 0U ?
			    meta->observed_uptime_s : k_uptime_get_32() / 1000U;

	ret = lichen_announce_parse(data, len, &announce);
	if (ret < 0) {
		return ret;
	}

	ret = pubkey_to_iid(announce.pubkey, expected_iid);
	if (ret < 0) {
		return ret;
	}
	if (memcmp(announce.originator_iid, expected_iid,
		   LICHEN_ANNOUNCE_IID_LEN) != 0) {
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

	k_mutex_lock(&ingest_mutex, K_FOREVER);
	k_mutex_lock(&announce_mutex, K_FOREVER);
	peer = find_peer_locked(announce.originator_iid);
	if (peer != NULL) {
		if (memcmp(peer->pubkey, announce.pubkey,
			   LICHEN_ANNOUNCE_PUBKEY_LEN) != 0) {
			k_mutex_unlock(&announce_mutex);
			k_mutex_unlock(&ingest_mutex);
			return -EKEYREJECTED;
		}
		if (!announce_seq_newer(announce.wire_seq_num, peer->seq_num)) {
			seq_stale_for_pin = true;
		}
		location_seq_num = extend_location_seq(announce.wire_seq_num,
						       peer->location_seq_num);
	} else {
		location_seq_num = announce.wire_seq_num;
	}
	k_mutex_unlock(&announce_mutex);

	announce.seq_num = location_seq_num;
	announce.seq_stale = seq_stale_for_pin;
	ret = notify_observers(&announce, meta, seq_stale_for_pin);
	if (ret < 0) {
		k_mutex_unlock(&ingest_mutex);
		return ret;
	}

	k_mutex_lock(&announce_mutex, K_FOREVER);
	peer = find_peer_locked(announce.originator_iid);
	if (peer != NULL) {
		if (memcmp(peer->pubkey, announce.pubkey,
			   LICHEN_ANNOUNCE_PUBKEY_LEN) != 0) {
			k_mutex_unlock(&announce_mutex);
			k_mutex_unlock(&ingest_mutex);
			return -EKEYREJECTED;
		}
	} else {
		peer = allocate_peer_locked(observed_uptime_s);
		if (peer == NULL) {
			k_mutex_unlock(&announce_mutex);
			k_mutex_unlock(&ingest_mutex);
			return -ENOMEM;
		}
		memset(peer, 0, sizeof(*peer));
		peer->active = true;
		memcpy(peer->iid, announce.originator_iid, LICHEN_ANNOUNCE_IID_LEN);
		memcpy(peer->pubkey, announce.pubkey, LICHEN_ANNOUNCE_PUBKEY_LEN);
	}
	peer->seq_num = announce.wire_seq_num;
	peer->location_seq_num = location_seq_num;
	peer->last_seen_uptime_s = observed_uptime_s;
	k_mutex_unlock(&announce_mutex);
	k_mutex_unlock(&ingest_mutex);
	return 0;
}

int lichen_announce_ingest_l2_payload(
	const uint8_t *data, size_t len,
	const struct lichen_announce_rx_meta *meta)
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
	if (body[0] != LICHEN_ANNOUNCE_TYPE) {
		return -EPROTONOSUPPORT;
	}

	return lichen_announce_ingest_authenticated(body, body_len, meta);
}

int lichen_announce_register_app_data_observer(
	lichen_announce_app_data_fn cb, void *user_data)
{
	return lichen_announce_register_app_data_observer_ex(cb, user_data, 0U);
}

int lichen_announce_register_app_data_observer_ex(
	lichen_announce_app_data_fn cb, void *user_data, uint8_t flags)
{
	struct announce_observer *free_slot = NULL;

	k_mutex_lock(&observer_mutex, K_FOREVER);
	if (cb == NULL) {
		memset(announce_observers, 0, sizeof(announce_observers));
		k_mutex_unlock(&observer_mutex);
		return 0;
	}

	for (size_t i = 0U; i < ARRAY_SIZE(announce_observers); i++) {
		if (!announce_observers[i].active) {
			if (free_slot == NULL) {
				free_slot = &announce_observers[i];
			}
			continue;
		}
		if (announce_observers[i].cb == cb &&
		    announce_observers[i].user_data == user_data) {
			announce_observers[i].flags = flags;
			k_mutex_unlock(&observer_mutex);
			return 0;
		}
	}

	if (free_slot == NULL) {
		k_mutex_unlock(&observer_mutex);
		return -ENOMEM;
	}

	*free_slot = (struct announce_observer){
		.active = true,
		.flags = flags,
		.cb = cb,
		.user_data = user_data,
	};
	k_mutex_unlock(&observer_mutex);
	return 0;
}

void lichen_announce_reset(void)
{
	k_mutex_lock(&announce_mutex, K_FOREVER);
	memset(announce_peers, 0, sizeof(announce_peers));
	k_mutex_unlock(&announce_mutex);
	k_mutex_lock(&observer_mutex, K_FOREVER);
	memset(announce_observers, 0, sizeof(announce_observers));
	k_mutex_unlock(&observer_mutex);
}
