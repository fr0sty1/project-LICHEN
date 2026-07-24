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
#include <monocypher.h>

#define ANNOUNCE_SIGNED_PREFIX_LEN \
	(LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 2U + 1U)
#define ANNOUNCE_SIGNED_MAX_LEN 256U
#define ANNOUNCE_APP_DATA_MAX_LEN \
	(ANNOUNCE_SIGNED_MAX_LEN - ANNOUNCE_SIGNED_PREFIX_LEN)

/*
 * LOCK ORDERING:
 *
 * When acquiring multiple mutexes, the following order MUST be respected
 * to prevent deadlock:
 *
 *   1. ingest_mutex   (outermost - serializes ingest operations)
 *   2. announce_mutex (protects announce_peers[])
 *   3. observer_mutex (protects announce_observers[])
 *
 * Rules:
 * - ingest_mutex and announce_mutex may be held together (ingest first)
 * - observer_mutex is always acquired and released independently
 * - Never acquire ingest_mutex while holding announce_mutex
 * - Never acquire announce_mutex while holding observer_mutex
 */

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
	buf[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 2U] =
		announce->rx_channel;
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
	if (data[1] >= 8U) {
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
	announce->rx_channel = data[1];
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
		if (crypto_verify32(peer->pubkey, announce.pubkey) != 0) {
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
	if (peer == NULL) {
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

	announce.seq_num = location_seq_num;
	announce.seq_stale = seq_stale_for_pin;
	ret = notify_observers(&announce, meta, seq_stale_for_pin);
	if (ret < 0) {
		k_mutex_unlock(&ingest_mutex);
		return ret;
	}

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

	if (cb == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&observer_mutex, K_FOREVER);
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

/* =========================================================================
 * Announce Scheduler (Periodic TX) - Spec 9.4
 * ========================================================================= */

#ifdef CONFIG_LICHEN_ANNOUNCE_SCHEDULER

#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <lichen/link_ctx.h>

/* ENOKEY may not be defined on all platforms */
#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

LOG_MODULE_REGISTER(announce_sched, LOG_LEVEL_INF);

/* L2 routing/control dispatch byte (spec 9.2) */
#define L2_ROUTING_DISPATCH 0x15U

/* Maximum app data that fits in an announce (see ANNOUNCE_APP_DATA_MAX_LEN) */
#define SCHED_APP_DATA_MAX_LEN (ANNOUNCE_SIGNED_MAX_LEN - ANNOUNCE_SIGNED_PREFIX_LEN)

/* Announce frame buffer: dispatch(0x15) + type(0x01) + flags(rx_channel) + hop(0) +
 * seq(2) + iid(8) + pubkey(32) + sig(48) + app_data (93 + app) */
#define ANNOUNCE_FRAME_MAX_LEN (1U + LICHEN_ANNOUNCE_MIN_LEN + SCHED_APP_DATA_MAX_LEN)

struct announce_scheduler {
	bool running;
	bool dodag_joined;
	uint16_t seq_num;
	struct k_work_delayable work;
	struct k_work_delayable dodag_loss_work;
	struct k_mutex mutex;

	/* Configuration (copied at start) */
	struct lichen_link_ctx *link_ctx;
	lichen_announce_tx_fn tx_fn;
	void *tx_user_data;
	lichen_announce_seq_change_fn seq_change_fn;
	void *seq_user_data;
	uint8_t app_data[SCHED_APP_DATA_MAX_LEN];
	size_t app_data_len;
	uint8_t rx_channel;
};

static struct announce_scheduler sched;

static void sched_work_handler(struct k_work *work);

static uint32_t random_range(uint32_t min_ms, uint32_t max_ms)
{
	uint32_t range;
	uint32_t rand_val;

	if (max_ms <= min_ms) {
		return min_ms;
	}
	range = max_ms - min_ms + 1;
	sys_csrand_get(&rand_val, sizeof(rand_val));
	return min_ms + (rand_val % range);
}

static uint16_t increment_seq_locked(void)
{
	sched.seq_num = (sched.seq_num + 1U) & 0xFFFFU;

	if (sched.seq_change_fn != NULL) {
		sched.seq_change_fn(sched.seq_num, sched.seq_user_data);
	}

	return sched.seq_num;
}

static int build_announce_frame(uint8_t *buf, size_t buf_len, size_t *out_len)
{
	uint8_t signed_data[ANNOUNCE_SIGNED_MAX_LEN];
	size_t signed_len;
	uint8_t signature[LICHEN_ANNOUNCE_SIGNATURE_LEN];
	struct lichen_link_keypair_snapshot keypair = { 0 };
	size_t pos = 0;
	uint16_t seq;
	size_t app_data_len_snapshot;
	int ret;

	k_mutex_lock(&sched.mutex, K_FOREVER);

	if (sched.link_ctx == NULL) {
		k_mutex_unlock(&sched.mutex);
		return -ENOKEY;
	}
	ret = lichen_link_snapshot_keypair(sched.link_ctx, &keypair);
	if (ret < 0) {
		k_mutex_unlock(&sched.mutex);
		return ret;
	}

	/* Increment and get sequence number */
	seq = increment_seq_locked();

	/* Build signed data: iid || pubkey || seq_num || rx_channel || app_data (CCP-9) */
	/* SECURITY: IID is derived from pubkey hash to bind identity to the
	 * cryptographic key material. Must match RX path (pubkey_to_iid).
	 * Resolves bead 796f (EUI-64 vs pubkey IID mismatch). */
	uint8_t iid[LICHEN_ANNOUNCE_IID_LEN];

	ret = pubkey_to_iid(sched.link_ctx->ed25519_pk, iid);
	if (ret < 0) {
		k_mutex_unlock(&sched.mutex);
		return ret;
	}

	/* SECURITY: Capture app_data_len while holding the lock to prevent race
	 * condition with lichen_announce_sched_set_app_data(). Using this snapshot
	 * consistently prevents buffer overflow if app_data_len increases after
	 * we release the lock. */
	app_data_len_snapshot = sched.app_data_len;
	uint8_t channel_snapshot = sched.rx_channel;
	signed_len = ANNOUNCE_SIGNED_PREFIX_LEN + app_data_len_snapshot;
	if (signed_len > sizeof(signed_data)) {
		lichen_link_clear_keypair_snapshot(&keypair);
		k_mutex_unlock(&sched.mutex);
		return -EMSGSIZE;
	}

	memcpy(&signed_data[0], iid, LICHEN_ANNOUNCE_IID_LEN);
	memcpy(&signed_data[LICHEN_ANNOUNCE_IID_LEN], keypair.pk,
	       LICHEN_ANNOUNCE_PUBKEY_LEN);
	signed_data[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN] =
		(uint8_t)(seq >> 8);
	signed_data[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 1U] =
		(uint8_t)seq;
	signed_data[LICHEN_ANNOUNCE_IID_LEN + LICHEN_ANNOUNCE_PUBKEY_LEN + 2U] =
		channel_snapshot;
	if (app_data_len_snapshot > 0) {
		memcpy(&signed_data[ANNOUNCE_SIGNED_PREFIX_LEN],
		       sched.app_data, app_data_len_snapshot);
	}

	/* Sign the announce */
	ret = schnorr48_sign(keypair.sk, keypair.pk,
			     signed_data, signed_len, signature);
	lichen_link_clear_keypair_snapshot(&keypair);

	if (ret < 0) {
		memset(signature, 0, sizeof(signature));
		k_mutex_unlock(&sched.mutex);
		return ret;
	}

	k_mutex_unlock(&sched.mutex);

	/* Build frame: dispatch(0x15) || type(0x01) || rx_channel(flags) || hop(0) ||
	 * seq(2B) || iid(8) || pubkey(32) || sig(48) || [app_data]
	 * (MIN_LEN=93 per CCP-9 + dispatch; matches ccp9.json oracle) */
	size_t frame_len = 1U + LICHEN_ANNOUNCE_MIN_LEN + app_data_len_snapshot;

	if (buf_len < frame_len) {
		memset(signature, 0, sizeof(signature));
		return -ENOMEM;
	}

	buf[pos++] = L2_ROUTING_DISPATCH;
	buf[pos++] = LICHEN_ANNOUNCE_TYPE;
	buf[pos++] = channel_snapshot; /* flags = rx_channel (0-7) per CCP-9 */
	buf[pos++] = 0U; /* hop_count: 0 since originator */
	buf[pos++] = (uint8_t)(seq >> 8);
	buf[pos++] = (uint8_t)seq;
	memcpy(&buf[pos], iid, LICHEN_ANNOUNCE_IID_LEN);
	pos += LICHEN_ANNOUNCE_IID_LEN;
	/* SECURITY: Use pubkey copy from signed_data (captured under lock) rather
	 * than re-reading sched.link_ctx->ed25519_pk. This prevents a race if
	 * the link context changes after we release the mutex. */
	memcpy(&buf[pos], &signed_data[LICHEN_ANNOUNCE_IID_LEN],
	       LICHEN_ANNOUNCE_PUBKEY_LEN);
	pos += LICHEN_ANNOUNCE_PUBKEY_LEN;
	memcpy(&buf[pos], signature, LICHEN_ANNOUNCE_SIGNATURE_LEN);
	pos += LICHEN_ANNOUNCE_SIGNATURE_LEN;
	memset(signature, 0, sizeof(signature));
		if (app_data_len_snapshot > 0) {
		/* SECURITY: Copy from signed_data (captured under lock) rather than
		 * re-reading sched.app_data. This ensures consistency: the app_data
		 * in the frame matches exactly what was signed, and we use the same
		 * length that was used for buffer sizing. */
		memcpy(&buf[pos], &signed_data[ANNOUNCE_SIGNED_PREFIX_LEN],
		       app_data_len_snapshot);
		pos += app_data_len_snapshot;
	}

	memset(signed_data, 0, sizeof(signed_data));
	*out_len = pos;
	return 0;
}


static int send_announce(void)
{
	uint8_t frame[ANNOUNCE_FRAME_MAX_LEN];
	size_t frame_len;
	int ret;

	ret = build_announce_frame(frame, sizeof(frame), &frame_len);
	if (ret < 0) {
		LOG_WRN("failed to build announce: %d", ret);
		return ret;
	}

	k_mutex_lock(&sched.mutex, K_FOREVER);
	lichen_announce_tx_fn tx_fn = sched.tx_fn;
	void *tx_user_data = sched.tx_user_data;
	uint16_t seq = sched.seq_num;

	k_mutex_unlock(&sched.mutex);

	if (tx_fn == NULL) {
		return -EINVAL;
	}

	ret = tx_fn(frame, frame_len, tx_user_data);
	if (ret == 0) {
		LOG_INF("sent announce seq=%u", seq);
	} else {
		LOG_WRN("failed to send announce seq=%u: %d", seq, ret);
	}

	return ret;
}

static void dodag_loss_resume_handler(struct k_work *work);

static void schedule_next(void)
{
	k_mutex_lock(&sched.mutex, K_FOREVER);
	uint32_t interval_ms = CONFIG_LICHEN_ANNOUNCE_INTERVAL_MS;
	uint32_t jitter_ms = random_range(0, CONFIG_LICHEN_ANNOUNCE_JITTER_MS);
	uint32_t delay_ms = interval_ms + jitter_ms;

	/* SECURITY: Read dodag_joined under lock to make a single atomic decision
	 * about the announce interval. If dodag_joined is set, the announce interval
	 * is suppressed (longer delay) because the DODAG provides routing info.
	 * The dodag_loss_resume_handler will clear dodag_joined and trigger a
	 * schedule_next() with the normal interval when the loss timer expires. */
	if (sched.dodag_joined) {
		delay_ms += CONFIG_LICHEN_DODAG_LOSS_RESUME_TIMEOUT_MS;
	}
	k_mutex_unlock(&sched.mutex);

	k_work_schedule(&sched.work, K_MSEC(delay_ms));
	LOG_DBG("next announce in %u ms (interval=%u, jitter=%u)",
		delay_ms, interval_ms, jitter_ms);
}

static void dodag_loss_resume_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&sched.mutex, K_FOREVER);
	bool was_joined = sched.dodag_joined;
	sched.dodag_joined = false;
	k_mutex_unlock(&sched.mutex);

	if (was_joined) {
		LOG_INF("DODAG loss timer expired, reverting to normal announce interval");
	}
	schedule_next();
}

void lichen_announce_sched_set_dodag_state(bool joined)
{
	k_mutex_lock(&sched.mutex, K_FOREVER);
	bool prev = sched.dodag_joined;
	sched.dodag_joined = joined;
	if (joined && !prev) {
		/* Just joined: cancel any pending loss-resume timer */
		(void)k_work_cancel_delayable(&sched.dodag_loss_work);
	}
	k_mutex_unlock(&sched.mutex);

	if (joined && !prev) {
		LOG_DBG("DODAG joined, announce interval suppressed");
	} else if (!joined && prev) {
		/* Just left: schedule loss-resume timer */
		uint32_t timeout_ms = CONFIG_LICHEN_DODAG_LOSS_RESUME_TIMEOUT_MS;

		if (timeout_ms > 0) {
			k_work_schedule(&sched.dodag_loss_work, K_MSEC(timeout_ms));
			LOG_INF("DODAG left, loss-resume timer for %u ms", timeout_ms);
		} else {
			LOG_INF("DODAG left, immediate reversion (timeout=0)");
			(void)k_work_cancel_delayable(&sched.dodag_loss_work);
			dodag_loss_resume_handler(&sched.dodag_loss_work);
		}
	}
}

static void sched_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&sched.mutex, K_FOREVER);
	bool running = sched.running;

	k_mutex_unlock(&sched.mutex);

	if (!running) {
		return;
	}

	(void)send_announce();
	schedule_next();
}

int lichen_announce_sched_start(
	const struct lichen_announce_sched_config *config)
{
	if (config == NULL || config->link_ctx == NULL || config->tx_fn == NULL) {
		return -EINVAL;
	}
	if (config->app_data_len > SCHED_APP_DATA_MAX_LEN) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&sched.mutex, K_FOREVER);
	if (sched.running) {
		k_mutex_unlock(&sched.mutex);
		return -EALREADY;
	}

	sched.link_ctx = config->link_ctx;
	sched.tx_fn = config->tx_fn;
	sched.tx_user_data = config->tx_user_data;
	sched.seq_change_fn = config->seq_change_fn;
	sched.seq_user_data = config->seq_user_data;
	if (config->app_data != NULL && config->app_data_len > 0) {
		memcpy(sched.app_data, config->app_data, config->app_data_len);
		sched.app_data_len = config->app_data_len;
	} else {
		sched.app_data_len = 0;
	}
	sched.rx_channel = config->rx_channel;
	sched.running = true;
	k_mutex_unlock(&sched.mutex);

	/* Schedule first announce with initial delay.
	 * Random delay (1-jitter_ms) prevents thundering herd on mass power-on. */
	uint32_t initial_delay_ms = CONFIG_LICHEN_ANNOUNCE_INITIAL_DELAY_MS;

	if (initial_delay_ms == 0) {
		uint32_t jitter_max = CONFIG_LICHEN_ANNOUNCE_JITTER_MS;

		initial_delay_ms = random_range(1000, (jitter_max > 1000) ? jitter_max : 1000);
	}

	k_work_schedule(&sched.work, K_MSEC(initial_delay_ms));
	LOG_INF("announce scheduler started, first announce in %u ms", initial_delay_ms);

	return 0;
}

void lichen_announce_sched_stop(void)
{
	k_mutex_lock(&sched.mutex, K_FOREVER);
	if (!sched.running) {
		k_mutex_unlock(&sched.mutex);
		return;
	}
	sched.running = false;
	k_mutex_unlock(&sched.mutex);

	(void)k_work_cancel_delayable(&sched.work);
	LOG_INF("announce scheduler stopped");
}

bool lichen_announce_sched_is_running(void)
{
	bool running;

	k_mutex_lock(&sched.mutex, K_FOREVER);
	running = sched.running;
	k_mutex_unlock(&sched.mutex);

	return running;
}

void lichen_announce_sched_set_seq(uint16_t seq_num)
{
	k_mutex_lock(&sched.mutex, K_FOREVER);
	sched.seq_num = seq_num;
	k_mutex_unlock(&sched.mutex);
	LOG_INF("sequence number set to %u", seq_num);
}

uint16_t lichen_announce_sched_get_seq(void)
{
	uint16_t seq;

	k_mutex_lock(&sched.mutex, K_FOREVER);
	seq = sched.seq_num;
	k_mutex_unlock(&sched.mutex);

	return seq;
}

int lichen_announce_sched_send_now(void)
{
	k_mutex_lock(&sched.mutex, K_FOREVER);
	if (!sched.running) {
		k_mutex_unlock(&sched.mutex);
		return -EAGAIN;
	}
	k_mutex_unlock(&sched.mutex);

	return send_announce();
}

int lichen_announce_sched_set_app_data(const uint8_t *app_data, size_t app_data_len)
{
	if (app_data_len > SCHED_APP_DATA_MAX_LEN) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&sched.mutex, K_FOREVER);
	if (app_data != NULL && app_data_len > 0) {
		memcpy(sched.app_data, app_data, app_data_len);
		sched.app_data_len = app_data_len;
	} else {
		sched.app_data_len = 0;
	}
	k_mutex_unlock(&sched.mutex);

	return 0;
}

/* Static initialization of scheduler state */
static int announce_sched_init(void)
{
	k_mutex_init(&sched.mutex);
	k_work_init_delayable(&sched.work, sched_work_handler);
	k_work_init_delayable(&sched.dodag_loss_work, dodag_loss_resume_handler);
	return 0;
}

SYS_INIT(announce_sched_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

#endif /* CONFIG_LICHEN_ANNOUNCE_SCHEDULER */
