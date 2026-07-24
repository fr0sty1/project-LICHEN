/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_ROUTING_ANNOUNCE_H_
#define LICHEN_ROUTING_ANNOUNCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_ANNOUNCE_TYPE 0x01U
#define LICHEN_ANNOUNCE_MIN_LEN 93U
#define LICHEN_ANNOUNCE_MAX_HOPS 15U
#define LICHEN_ANNOUNCE_IID_LEN 8U
#define LICHEN_ANNOUNCE_PUBKEY_LEN 32U
#define LICHEN_ANNOUNCE_SIGNATURE_LEN 48U
#define LICHEN_ANNOUNCE_ACCEPT_SEQ_RESET 1
#define LICHEN_ANNOUNCE_OBSERVER_F_ALLOW_SEQ_RESET 0x01U

/*
 * LOCK ORDERING (see announce.c for full rules):
 * ingest_mutex > announce_mutex > observer_mutex. Ingest must be outermost.
 * Violating order risks deadlock. observer_mutex is usually independent.
 * Enforced via comments + call-site ordering in ingest/parse paths.
 */

struct lichen_announce_view {
	uint8_t flags;
	uint8_t hop_count;
	uint8_t rx_channel;
	uint16_t wire_seq_num;
	uint32_t seq_num;
	bool seq_stale;
	const uint8_t *_Nonnull originator_iid;
	const uint8_t *_Nonnull pubkey;
	const uint8_t *_Nonnull signature;
	const uint8_t *_Nullable app_data;
	size_t app_data_len;
};

struct lichen_announce_rx_meta {
	uint8_t immediate_eui64[8];
	int16_t rssi_dbm;
	int8_t snr_db;
	uint8_t link_epoch;
	uint16_t link_seqnum;
	uint32_t observed_uptime_s;
};

typedef int (*lichen_announce_app_data_fn)(
	const struct lichen_announce_view *_Nonnull announce,
	const struct lichen_announce_rx_meta *_Nonnull meta,
	void *_Nullable user_data);

int lichen_announce_parse(const uint8_t *_Nonnull data, size_t len,
			  struct lichen_announce_view *_Nonnull announce);

int lichen_announce_ingest_authenticated(
	const uint8_t *_Nonnull data, size_t len,
	const struct lichen_announce_rx_meta *_Nullable meta);

int lichen_announce_ingest_l2_payload(
	const uint8_t *_Nonnull data, size_t len,
	const struct lichen_announce_rx_meta *_Nullable meta);

int lichen_announce_register_app_data_observer(
	lichen_announce_app_data_fn _Nonnull cb, void *_Nullable user_data);

/**
 * @brief Register callback for announce app_data (coords, congestion, etc).
 *
 * @param cb Non-null callback (NULL returns -EINVAL).
 * @param user_data Opaque context passed to cb.
 * @param flags Observer flags (e.g. LICHEN_ANNOUNCE_OBSERVER_F_ALLOW_SEQ_RESET).
 * @return 0 on success, -EINVAL if cb NULL, -ENOMEM if table full.
 */
int lichen_announce_register_app_data_observer_ex(
	lichen_announce_app_data_fn _Nonnull cb, void *_Nullable user_data,
	uint8_t flags);

/**
 * @brief Unregister all app data observers.
 *
 * Clears the entire observer table under lock. Use during reset or to
 * disable all hooks. Preferred over NULL-cb (now rejected).
 */
void lichen_announce_unregister_all_app_data_observers(void);

void lichen_announce_reset(void);

#ifdef CONFIG_LICHEN_ANNOUNCE_SCHEDULER

struct lichen_link_ctx;

/**
 * @brief Callback to transmit announce data.
 *
 * @param data     Serialized announce message (L2 routing payload format)
 * @param data_len Length of the announce data
 * @param user_data User-provided context
 * @return 0 on success, negative errno on failure
 */
typedef int (*lichen_announce_tx_fn)(const uint8_t *_Nonnull data,
				     size_t data_len, void *_Nullable user_data);

/**
 * @brief Callback when sequence number changes (for persistence).
 *
 * Production implementations MUST persist seq_num to non-volatile storage
 * to avoid peers rejecting announces as stale after reboot.
 *
 * @param seq_num The new sequence number
 * @param user_data User-provided context
 */
typedef void (*lichen_announce_seq_change_fn)(uint16_t seq_num,
					      void *_Nullable user_data);

/**
 * @brief Announce scheduler configuration.
 */
struct lichen_announce_sched_config {
	/** Link context for identity (EUI-64, keypair). Required. */
	struct lichen_link_ctx *_Nonnull link_ctx;
	/** Transmit callback. Required. */
	lichen_announce_tx_fn _Nonnull tx_fn;
	/** User data for transmit callback. */
	void *_Nullable tx_user_data;
	/** Sequence change callback for persistence. Optional. */
	lichen_announce_seq_change_fn _Nullable seq_change_fn;
	/** User data for sequence change callback. */
	void *_Nullable seq_user_data;
	/** Optional application data to include in announces (may be NULL). */
	const uint8_t *_Nullable app_data;
	/** Length of application data. */
	size_t app_data_len;
	/** RX channel to announce and bind in signature (CCP-9). Default 0 for CH0. */
	uint8_t rx_channel;
};

/**
 * @brief Initialize and start the announce scheduler.
 *
 * Begins periodic announce transmission. The first announce is sent after
 * an initial delay (randomized 1-jitter_ms if CONFIG_LICHEN_ANNOUNCE_INITIAL_DELAY_MS
 * is 0, otherwise the configured value).
 *
 * @param config Scheduler configuration. The caller must ensure link_ctx
 *               and tx_fn remain valid for the lifetime of the scheduler.
 * @return 0 on success, -EINVAL if required fields are NULL,
 *         -EALREADY if scheduler is already running
 */
int lichen_announce_sched_start(const struct lichen_announce_sched_config *_Nonnull config);

/**
 * @brief Stop the announce scheduler.
 *
 * Cancels pending work. Safe to call even if not running.
 */
void lichen_announce_sched_stop(void);

/**
 * @brief Check if the scheduler is running.
 *
 * @return true if running, false otherwise
 */
bool lichen_announce_sched_is_running(void);

/**
 * @brief Set the current sequence number (for persistence restore).
 *
 * Call this before starting the scheduler to restore seq_num from flash.
 *
 * @param seq_num Sequence number to restore
 */
void lichen_announce_sched_set_seq(uint16_t seq_num);

/**
 * @brief Get the current sequence number (for persistence save).
 *
 * @return Current sequence number
 */
uint16_t lichen_announce_sched_get_seq(void);

/**
 * @brief Trigger an immediate announce transmission.
 *
 * Useful after significant events (topology change, link up).
 * Does not affect the periodic schedule.
 *
 * @return 0 on success, -EAGAIN if scheduler not running,
 *         negative errno from tx_fn on transmit failure
 */
int lichen_announce_sched_send_now(void);

/**
 * @brief Update application data for future announces.
 *
 * Changes take effect on the next announce transmission.
 *
 * @param app_data New application data (may be NULL to clear)
 * @param app_data_len Length of new application data
 * @return 0 on success, -EMSGSIZE if app_data_len exceeds limit
 */
int lichen_announce_sched_set_app_data(const uint8_t *_Nullable app_data,
				       size_t app_data_len);

/**
 * @brief Notify the announce scheduler of DODAG join/leave state.
 *
 * When joined to a DODAG, the announce interval is suppressed
 * (gateway-centric mode). On DODAG loss, a timer is started;
 * if it expires without rejoining, the normal interval resumes.
 *
 * @param joined true if joined to a DODAG, false if left
 */
void lichen_announce_sched_set_dodag_state(bool joined);

#endif /* CONFIG_LICHEN_ANNOUNCE_SCHEDULER */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_ANNOUNCE_H_ */
