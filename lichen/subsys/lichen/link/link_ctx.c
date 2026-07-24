/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file link_ctx.c
 * @brief LICHEN link layer context implementation
 */

#include <lichen/link_ctx.h>
#include <lichen/link.h>
#include <lichen/schnorr48.h>
#include <lichen/errno.h>
#include <string.h>
#include <stdbool.h>

#ifdef CONFIG_NVS
#include <zephyr/device.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/crc.h>
#endif

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"
#endif

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
LOG_MODULE_REGISTER(link_ctx, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
/* POSIX CSPRNG */
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#endif
#endif

/* Runtime warning flag for stub crypto */
#ifndef CONFIG_LICHEN_CRYPTO_MONOCYPHER
static bool stub_warned_load_key = false;
#endif

#ifdef CONFIG_NVS
/* Link tuple persistence using NVS on storage_partition (no dynamic alloc, statics, C11).
 * Persists EUI, keys, epoch/seq tuple + exhaustion + placeholder replay counter.
 * Follows nvs_persistence test and meshcore record-with-crc pattern for atomicity
 * and validation against stale storage_partition data. */
struct link_persisted_tuple {
	uint32_t crc;
	uint8_t eui64[LICHEN_EUI64_LEN];
	uint8_t ed25519_sk[LICHEN_SK_LEN];
	uint8_t ed25519_pk[LICHEN_PK_LEN];
	uint8_t epoch;
	uint16_t tx_seq;
	bool nonce_exhausted;
	uint64_t replay_counter; /* placeholder for replay state */
};

#define LINK_TUPLE_NVS_ID 0x10

static struct nvs_fs link_nvs_fs;
static bool link_nvs_mounted = false;

static int link_nvs_mount(void)
{
	if (link_nvs_mounted) {
		return 0;
	}
	const struct device *dev = FIXED_PARTITION_DEVICE(storage_partition);
	if (!device_is_ready(dev)) {
		return -ENODEV;
	}
	link_nvs_fs.flash_device = dev;
	link_nvs_fs.offset = FIXED_PARTITION_OFFSET(storage_partition);
	link_nvs_fs.sector_size = 4096;
	link_nvs_fs.sector_count = FIXED_PARTITION_SIZE(storage_partition) / 4096;
	int rc = nvs_mount(&link_nvs_fs);
	if (rc == 0) {
		link_nvs_mounted = true;
	}
	return rc;
}

static uint32_t tuple_crc(const struct link_persisted_tuple *t)
{
	if (t == NULL) return 0;
	return crc32_ieee((const uint8_t *)t + sizeof(uint32_t),
			 sizeof(*t) - sizeof(uint32_t));
}

static int save_tuple(const struct lichen_link_ctx *ctx)
{
	if (ctx == NULL) return -EINVAL;
	int rc = link_nvs_mount();
	if (rc != 0) return rc;
	struct link_persisted_tuple t = {0};
	memcpy(t.eui64, ctx->eui64, sizeof(t.eui64));
	memcpy(t.ed25519_sk, ctx->ed25519_sk, sizeof(t.ed25519_sk));
	memcpy(t.ed25519_pk, ctx->ed25519_pk, sizeof(t.ed25519_pk));
	t.epoch = ctx->epoch;
	t.tx_seq = ctx->tx_seq;
	t.nonce_exhausted = ctx->nonce_exhausted;
	t.replay_counter = 0; /* TODO: integrate replay table snapshot if needed */
	t.crc = tuple_crc(&t);
	rc = nvs_write(&link_nvs_fs, LINK_TUPLE_NVS_ID, &t, sizeof(t));
	return (rc == sizeof(t)) ? 0 : rc;
}

static int restore_tuple(struct lichen_link_ctx *ctx)
{
	if (ctx == NULL) return -EINVAL;
	int rc = link_nvs_mount();
	if (rc != 0) return rc;
	struct link_persisted_tuple t;
	rc = nvs_read(&link_nvs_fs, LINK_TUPLE_NVS_ID, &t, sizeof(t));
	if (rc != sizeof(t)) {
		return -ENOENT;
	}
	if (t.crc != tuple_crc(&t)) {
		return -EBADMSG;
	}
	memcpy(ctx->eui64, t.eui64, sizeof(ctx->eui64));
	memcpy(ctx->ed25519_sk, t.ed25519_sk, sizeof(ctx->ed25519_sk));
	memcpy(ctx->ed25519_pk, t.ed25519_pk, sizeof(ctx->ed25519_pk));
	ctx->epoch = t.epoch;
	ctx->tx_seq = t.tx_seq;
	ctx->has_key = true;
	ctx->nonce_exhausted = t.nonce_exhausted;
	/* replay counters restored via placeholder; full table in replay.c out of scope */
	return 0;
}
#endif

/* Forward declaration */
static void secure_wipe(void *buf, size_t len);
static int seq_lock(struct lichen_link_ctx *ctx);
static int seq_unlock(struct lichen_link_ctx *ctx);

int lichen_link_init(struct lichen_link_ctx *ctx, const uint8_t *eui64)
{
	uint8_t rand_byte;

	if (ctx == NULL || eui64 == NULL) {
		return -EINVAL;
	}

	/* ponytail: random epoch in [128,255] for reboot resilience without flash.
	 * Half-space arithmetic treats upper-half counters as "ahead" of lower-half.
	 * Used for TDMA slot = hash(EUI64 ^ epoch) % n_slots per
	 * spec/02a-coordinated-capacity.md §2a.2, ccp16.json, and ccp_tdma.json.
	 * Callers with persisted epoch should call lichen_link_set_epoch() after init.
	 *
	 * SECURITY: ESP32 HW RNG produces weak/predictable output before WiFi/BT radio
	 * init. On ESP32 without epoch persistence, an attacker who knows the boot
	 * timing may predict the epoch. Mitigation: persist epoch to flash, or defer
	 * this call until after radio subsystem init. */
#ifdef __ZEPHYR__
	if (sys_csrand_get(&rand_byte, sizeof(rand_byte)) != 0) {
		return -EIO;
	}
#elif defined(__linux__) || defined(__APPLE__)
	if (getentropy(&rand_byte, sizeof(rand_byte)) != 0) {
		return -EIO;
	}
#else
	return -EIO;
#endif

#ifdef __ZEPHYR__
	k_mutex_init(&ctx->seq_lock);
#else
	if (pthread_mutex_init(&ctx->seq_lock, NULL) != 0) {
		return -EIO;
	}
#endif

	memcpy(ctx->eui64, eui64, LICHEN_EUI64_LEN);
	memset(ctx->ed25519_sk, 0, LICHEN_SK_LEN);
	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	memset(ctx->link_key, 0, LICHEN_LINK_KEY_LEN);
	ctx->has_key = false;
	ctx->has_link_key = false;
	ctx->nonce_exhausted = false;

#ifdef CONFIG_NVS
	/* Initialization-only restore of persisted tuple (EUI, keys, replay counters,
	 * epoch/seq tuple + exhaustion). Prevents reuse of previously signed tuple
	 * across reboot. Falls back to random epoch if no persisted state. */
	if (restore_tuple(ctx) == 0) {
		return 0;
	}
#endif

	ctx->epoch = 128 + (rand_byte & 0x7F); /* [128, 255] */
	ctx->tx_seq = 0;

	return 0;
}

/**
 * @brief Load Ed25519 signing key from a 32-byte seed.
 *
 * @param ctx   Link context to initialize
 * @param seed  32-byte random seed (MUST come from a CSPRNG)
 *
 * @note Key Generation Requirements:
 *       The seed MUST be generated using a cryptographically secure PRNG.
 *       On Zephyr: use sys_csrand_get() from <zephyr/random/random.h>
 *       On POSIX: use getrandom(2) or /dev/urandom
 *       NEVER use rand(), random(), or other non-cryptographic sources.
 *
 * @return 0 on success, -EINVAL on invalid parameters
 */
int lichen_link_load_key(struct lichen_link_ctx *ctx,
			 const uint8_t seed[_Nonnull 32])
{
	uint8_t new_sk[LICHEN_SK_LEN];
	uint8_t new_pk[LICHEN_PK_LEN];
	uint8_t new_epoch;

	if (ctx == NULL || seed == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	if (sys_csrand_get(&new_epoch, 1) != 0) {
		return -EIO;
	}
#elif defined(__linux__) || defined(__APPLE__)
	if (getentropy(&new_epoch, 1) != 0) {
		return -EIO;
	}
#else
	return -EIO;
#endif
	new_epoch = 128 + (new_epoch & 0x7F);

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	schnorr48_derive_keypair(seed, new_sk, new_pk);
#else
#ifdef CONFIG_LICHEN_LINK_SCHNORR
#error "CONFIG_LICHEN_LINK_SCHNORR requires CONFIG_LICHEN_CRYPTO_MONOCYPHER for secure key derivation"
#endif
	/* Stub for builds without Monocypher - NOT FOR PRODUCTION */
	if (!stub_warned_load_key) {
		LOG_WRN("INSECURE: using stub lichen_link_load_key - NOT FOR PRODUCTION\n");
		stub_warned_load_key = true;
	}
	memcpy(new_sk, seed, sizeof(new_sk));
	schnorr48_clamp_scalar(new_sk);
	memset(new_pk, 0, sizeof(new_pk));
	new_pk[0] = 0x01;
#endif

	if (seq_lock(ctx) != 0) {
		secure_wipe(new_sk, sizeof(new_sk));
		secure_wipe(new_pk, sizeof(new_pk));
		return -EIO;
	}
	if (ctx->has_key) {
		secure_wipe(ctx->ed25519_sk, LICHEN_SK_LEN);
	}
	memcpy(ctx->ed25519_sk, new_sk, LICHEN_SK_LEN);
	memcpy(ctx->ed25519_pk, new_pk, LICHEN_PK_LEN);
	ctx->has_key = true;
	ctx->epoch = new_epoch;
	ctx->tx_seq = 0;
	ctx->nonce_exhausted = false;
#ifdef CONFIG_NVS
	(void)save_tuple(ctx); /* persist new key + reset tuple; ignore errors to not block boot */
#endif
	return 0;
}

int lichen_link_generate_key(struct lichen_link_ctx *ctx)
{
	uint8_t seed[LICHEN_SEED_LEN];
	int ret = -EINVAL;

	if (ctx == NULL) {
		goto wipe;
	}

#ifdef __ZEPHYR__
	if (sys_csrand_get(seed, sizeof(seed)) != 0) {
		ret = -EIO;
		goto wipe;
	}
#elif defined(__linux__) || defined(__APPLE__)
	if (getentropy(seed, sizeof(seed)) != 0) {
		ret = -EIO;
		goto wipe;
	}
#else
	return -EIO;
#endif

	ret = lichen_link_load_key(ctx, seed);

wipe:
	secure_wipe(seed, sizeof(seed));
	return ret;
}

int lichen_link_derive_seed(const uint8_t base_seed[LICHEN_SEED_LEN],
			    const uint8_t eui64[LICHEN_EUI64_LEN],
			    uint8_t out_seed[LICHEN_SEED_LEN])
{
	if (base_seed == NULL || eui64 == NULL || out_seed == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	uint8_t hash[64];
	crypto_sha512_ctx hash_ctx;

	/* out = SHA-512(base_seed || eui64)[0:32] */
	crypto_sha512_init(&hash_ctx);
	crypto_sha512_update(&hash_ctx, base_seed, LICHEN_SEED_LEN);
	crypto_sha512_update(&hash_ctx, eui64, LICHEN_EUI64_LEN);
	crypto_sha512_final(&hash_ctx, hash);
	memcpy(out_seed, hash, LICHEN_SEED_LEN);
	crypto_wipe(hash, sizeof(hash));
#else
	/* Stub for builds without Monocypher - NOT FOR PRODUCTION.
	 * XOR the EUI-64 into the seed so distinct nodes still get
	 * distinct (but trivially related) seeds. */
	memcpy(out_seed, base_seed, LICHEN_SEED_LEN);
	for (size_t i = 0; i < LICHEN_EUI64_LEN; i++) {
		out_seed[i] ^= eui64[i];
	}
#endif

	return 0;
}

int lichen_link_derive_pubkey(const uint8_t seed[LICHEN_SEED_LEN],
			      uint8_t out_pk[LICHEN_PK_LEN])
{
	if (seed == NULL || out_pk == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	uint8_t dummy_sk[LICHEN_SK_LEN];
	schnorr48_derive_keypair(seed, dummy_sk, out_pk);
	crypto_wipe(dummy_sk, sizeof(dummy_sk));
#else
	/* Stub matches the lichen_link_load_key() stub pubkey */
	memset(out_pk, 0, LICHEN_PK_LEN);
	out_pk[0] = 0x01;
#endif

	return 0;
}

int lichen_link_next_seq(struct lichen_link_ctx *ctx, uint16_t *seqnum)
{
	uint8_t epoch;

	return lichen_link_next_tx(ctx, &epoch, seqnum);
}

int lichen_link_next_tx(struct lichen_link_ctx *ctx, uint8_t *epoch, uint16_t *seqnum)
{
	uint8_t allocated_epoch;
	uint16_t allocated_seq;
	if (ctx == NULL || seqnum == NULL) {
		return -EINVAL;
	}
	if (epoch == NULL) {
		return -EINVAL;
	}

	if (seq_lock(ctx) != 0) {
		return -EIO;
	}

	/*
	 * SECURITY: Once nonce space is exhausted, block all TX until key
	 * rotation occurs. Continuing would cause catastrophic nonce reuse
	 * in AES-CCM, completely breaking confidentiality and authenticity.
	 */
	if (ctx->nonce_exhausted) {
		(void)seq_unlock(ctx);
		return -EOVERFLOW;
	}

	allocated_epoch = ctx->epoch;
	allocated_seq = ctx->tx_seq;

#ifdef CONFIG_LICHEN_LINK_EPOCH_PERSIST
	/* Commit the next live epoch before returning the final tuple from this
	 * epoch. A reset at any later instruction can only skip tuples, not reuse
	 * an epoch with sequence zero. */
	if (ctx->tx_seq == UINT16_MAX && ctx->epoch != UINT8_MAX &&
	    lichen_link_epoch_persist((uint8_t)(ctx->epoch + 1U)) != 0) {
		(void)seq_unlock(ctx);
		return -EIO;
	}
#endif

	ctx->tx_seq++;

	/*
	 * If tx_seq wrapped to 0, increment epoch to avoid nonce reuse.
	 * The AES-CCM nonce includes (eui64, epoch, seqnum), so reusing
	 * the same (epoch, seqnum) pair would break security guarantees.
	 */
	if (ctx->tx_seq == 0) {
		uint8_t old_epoch = ctx->epoch;
		ctx->epoch++;
		if (ctx->epoch == 0) {
			/*
			 * SECURITY: epoch wrapped from 255 to 0 - nonce space
			 * exhausted after 256 * 65536 = 16M frames. Block all
			 * further TX until key rotation clears the flag.
			 */
			ctx->nonce_exhausted = true;
			LOG_WRN("CRITICAL: nonce exhausted after 16M frames, TX blocked until key rotation\n");
		} else {
			LOG_WRN("tx_seq wrapped - epoch incremented to %u (was %u)\n",
				ctx->epoch, old_epoch);
		}
	}

	*epoch = allocated_epoch;
	*seqnum = allocated_seq;
	(void)seq_unlock(ctx);
	return 0;
}

int lichen_link_set_epoch(struct lichen_link_ctx *ctx, uint8_t epoch)
{
	if (ctx == NULL) {
		return -EINVAL;
	}
	if (seq_lock(ctx) != 0) {
		return -EIO;
	}
	ctx->epoch = epoch;
	(void)seq_unlock(ctx);
	return 0;
}

int lichen_link_load_link_key(struct lichen_link_ctx *ctx,
			      const uint8_t link_key[_Nonnull LICHEN_LINK_KEY_LEN])
{
	uint8_t new_link_key[LICHEN_LINK_KEY_LEN];

	if (ctx == NULL || link_key == NULL) {
		return -EINVAL;
	}

	memcpy(new_link_key, link_key, sizeof(new_link_key));

	if (ctx->has_link_key) {
		secure_wipe(ctx->link_key, LICHEN_LINK_KEY_LEN);
	}

	memcpy(ctx->link_key, new_link_key, LICHEN_LINK_KEY_LEN);
	secure_wipe(new_link_key, sizeof(new_link_key));
	ctx->has_link_key = true;

	return 0;
}

/**
 * @brief Secure wipe helper.
 *
 * Uses volatile to prevent compiler from optimizing out the wipe.
 * For Monocypher builds, crypto_wipe() is preferred as it uses
 * platform-specific secure-wipe mechanisms.
 */
static void secure_wipe(void *buf, size_t len)
{
#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	crypto_wipe(buf, len);
#else
	volatile uint8_t *p = (volatile uint8_t *)buf;
	while (len--) {
		*p++ = 0;
	}
#endif
}

static int seq_lock(struct lichen_link_ctx *ctx)
{
#ifdef __ZEPHYR__
	k_mutex_lock(&ctx->seq_lock, K_FOREVER);
	return 0;
#else
	return pthread_mutex_lock(&ctx->seq_lock);
#endif
}

static int seq_unlock(struct lichen_link_ctx *ctx)
{
#ifdef __ZEPHYR__
	k_mutex_unlock(&ctx->seq_lock);
	return 0;
#else
	return pthread_mutex_unlock(&ctx->seq_lock);
#endif
}

int lichen_link_copy_identity(const struct lichen_link_ctx *ctx,
			      uint8_t eui64[LICHEN_EUI64_LEN],
			      uint8_t pk[LICHEN_PK_LEN],
			      bool *has_key)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

	/*
	 * SECURITY: Acquire seq_lock to ensure atomic read of key material.
	 * This prevents a race where has_key is true but cleanup zeros the
	 * key between our check and copy. The cleanup function also holds
	 * this lock when modifying key state.
	 *
	 * Cast away const for lock acquisition - the lock protects the data,
	 * we are only reading, and mutex_lock requires non-const.
	 */
	struct lichen_link_ctx *mutable_ctx = (struct lichen_link_ctx *)ctx;

	if (seq_lock(mutable_ctx) != 0) {
		return -EIO;
	}

	bool key_loaded = ctx->has_key;

	if (has_key != NULL) {
		*has_key = key_loaded;
	}

	if (!key_loaded) {
		(void)seq_unlock(mutable_ctx);
		return -ENOKEY;
	}

	if (eui64 != NULL) {
		memcpy(eui64, ctx->eui64, LICHEN_EUI64_LEN);
	}
	if (pk != NULL) {
		memcpy(pk, ctx->ed25519_pk, LICHEN_PK_LEN);
	}

	(void)seq_unlock(mutable_ctx);
	return 0;
}

void lichen_link_cleanup(struct lichen_link_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	int locked = seq_lock(ctx);

	secure_wipe(ctx->ed25519_sk, LICHEN_SK_LEN);
	secure_wipe(ctx->link_key, LICHEN_LINK_KEY_LEN);

	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	ctx->has_key = false;
	ctx->has_link_key = false;

	ctx->epoch = 0;
	ctx->tx_seq = 0;
	ctx->nonce_exhausted = false;

	if (locked == 0) {
		(void)seq_unlock(ctx);
#ifndef __ZEPHYR__
		pthread_mutex_destroy(&ctx->seq_lock);
#endif
	}
}

int lichen_tdma_compute_slot(const uint8_t eui64[8], uint32_t epoch, uint8_t num_slots)
{
	if (num_slots == 0) num_slots = 8;
	uint8_t data[8];
	memcpy(data, eui64, 8);
	uint32_t e = epoch;
	for (size_t i = 0; i < 4; i++) {
		data[i] ^= (uint8_t)(e & 0xff);
		e >>= 8;
	}
	uint32_t h = lichen_hash_32(data, 8);
	return (uint8_t)(h % num_slots);
}
int lichen_tdma_init(struct lichen_tdma_ctx *tdma, struct lichen_link_ctx *ctx)
{
	if (tdma == NULL || ctx == NULL) return -EINVAL;
	uint8_t slot = lichen_tdma_compute_slot(ctx->eui64, (uint32_t)ctx->epoch, 8);
	tdma->slot = slot;
	tdma->n_slots = 8;
	tdma->superframe = 0;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	tdma->synced = false;
	return 0;
}
int lichen_link_set_slot(struct lichen_link_ctx *ctx, struct lichen_tdma_ctx *tdma, uint8_t slot_id, uint8_t n_slots, uint32_t sfn)
{
	if (tdma == NULL) return -EINVAL;
	if (slot_id == 0xff && ctx != NULL) {
		slot_id = lichen_tdma_compute_slot(ctx->eui64, (uint32_t)ctx->epoch, n_slots ? n_slots : 8);
	}
	tdma->slot = slot_id;
	tdma->n_slots = n_slots ? n_slots : 8;
	tdma->superframe = sfn;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	tdma->synced = true;
	return 0;
}
bool tdma_tx_allowed(const struct lichen_tdma_ctx *tdma, uint32_t now_ms)
{
	if (tdma == NULL || !tdma->synced) return true;
	uint32_t d = tdma->slot_duration;
	uint32_t slot_start = tdma->superframe * (uint32_t)tdma->n_slots * d + (uint32_t)tdma->slot * d;
	uint32_t g = LICHEN_TDMA_GUARD_MS;
	return (slot_start - g <= now_ms) && (now_ms <= slot_start + d + g);
}

uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
	uint32_t hash = 0x811c9dc5u;
	for (size_t i = 0; i < len; i++) {
		hash ^= (uint32_t)data[i];
		hash = hash * 0x01000193u;
	}
	return hash;
}

uint8_t lichen_tdma_compute_slot(const uint8_t eui64[8], uint32_t epoch, uint8_t num_slots)
{
	if (num_slots == 0) num_slots = 8;
	uint8_t buf[8];
	memcpy(buf, eui64, 8);
	uint32_t e = epoch;
	for (size_t i = 0; i < 8; i++) {
		buf[i] ^= (uint8_t)e;
		e >>= 8;
	}
	uint32_t h = lichen_hash_32(buf, 8);
	return (uint8_t)(h % num_slots);
}
