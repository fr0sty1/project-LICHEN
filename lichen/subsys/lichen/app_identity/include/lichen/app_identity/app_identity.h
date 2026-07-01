/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_IDENTITY_H_
#define LICHEN_APP_IDENTITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_APP_IDENTITY_EUI64_LEN 8U
#define LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN 32U
#define LICHEN_APP_IDENTITY_DISPLAY_MAX 32U
#define LICHEN_APP_IDENTITY_FIRMWARE_MAX 32U

struct lichen_link_ctx;

struct lichen_app_identity_self {
	uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN];
	uint8_t iid[LICHEN_APP_IDENTITY_EUI64_LEN];
	uint8_t public_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN];
	char display_name[LICHEN_APP_IDENTITY_DISPLAY_MAX];
	char firmware_name[LICHEN_APP_IDENTITY_FIRMWARE_MAX];
	bool has_public_key;
};

struct lichen_app_identity_peer {
	uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN];
	uint8_t iid[LICHEN_APP_IDENTITY_EUI64_LEN];
	uint8_t public_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN];
	char display_name[LICHEN_APP_IDENTITY_DISPLAY_MAX];
	uint32_t last_heard_seconds_ago;
	int16_t rssi_dbm;
	int8_t snr_db;
	uint8_t hop_distance;
	bool has_public_key;
	bool has_last_heard_seconds_ago;
	bool has_rssi_dbm;
	bool has_snr_db;
	bool has_hop_distance;
};

/*
 * Publish this node's public app identity. display_name and firmware_name are
 * copied as bounded C strings and must either be empty or NUL-terminated within
 * their fixed arrays. Private key material is not part of this structure.
 */
int lichen_app_identity_set_self(
	const struct lichen_app_identity_self *identity);

/*
 * Convenience wrapper for link contexts. Callers must serialize this call with
 * lichen_link_load_key()/lichen_link_generate_key() and any future key-rotation
 * path for the same context; struct lichen_link_ctx does not provide a public
 * read lock for atomic key snapshots.
 */
int lichen_app_identity_set_self_from_link_ctx(
	const struct lichen_link_ctx *ctx, const char *display_name,
	const char *firmware_name);
int lichen_app_identity_copy_self(
	struct lichen_app_identity_self *out);

int lichen_app_identity_upsert_peer(
	const struct lichen_app_identity_peer *peer);
int lichen_app_identity_upsert_peer_key(
	const uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN],
	const uint8_t public_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN]);
int lichen_app_identity_copy_peer(
	const uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN],
	struct lichen_app_identity_peer *out);
size_t lichen_app_identity_copy_peers(
	struct lichen_app_identity_peer *out, size_t out_len);
size_t lichen_app_identity_peer_count(void);

#ifdef CONFIG_LICHEN_APP_IDENTITY_TEST_HOOKS
void lichen_app_identity_test_reset(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_IDENTITY_H_ */
