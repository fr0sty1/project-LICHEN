/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_ROUTING_ANNOUNCE_H_
#define LICHEN_ROUTING_ANNOUNCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
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

struct lichen_announce_view {
	uint8_t flags;
	uint8_t hop_count;
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
	const struct lichen_announce_rx_meta *_Nonnull meta);

int lichen_announce_ingest_l2_payload(
	const uint8_t *_Nonnull data, size_t len,
	const struct lichen_announce_rx_meta *_Nonnull meta);

int lichen_announce_register_app_data_observer(
	lichen_announce_app_data_fn _Nonnull cb, void *_Nullable user_data);

int lichen_announce_register_app_data_observer_ex(
	lichen_announce_app_data_fn _Nonnull cb, void *_Nullable user_data,
	uint8_t flags);

void lichen_announce_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_ANNOUNCE_H_ */
