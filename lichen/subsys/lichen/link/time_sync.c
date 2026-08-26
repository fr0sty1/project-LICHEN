/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file time_sync.c
 * @brief Time synchronization per spec 09 section 14.6
 *
 * Implements:
 * - Time source class tracking (GNSS, Network, Local-client, etc.)
 * - Time stratum (0-4) for DIO Time Option
 * - Epoch floor validation (firmware build + optional board provision)
 * - DIO Time Option encode/decode (provisional Type 0x15)
 * - Wall clock state with source provenance
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <lichen/link.h>

LOG_MODULE_REGISTER(lichen_time_sync, CONFIG_LICHEN_LINK_LOG_LEVEL);

/* ---- Static state ---- */

static uint32_t s_current_sfn;
static bool s_synced;
static uint8_t s_stratum;
static uint32_t s_wall_clock_unix;
static bool s_wall_clock_valid;
static enum lichen_time_source_class s_wall_clock_source;
static uint32_t s_firmware_build_epoch;
static uint32_t s_provision_epoch;
static bool s_provision_authenticated;

/* ---- Time source class ---- */

const char *lichen_time_source_class_str(enum lichen_time_source_class source)
{
	switch (source) {
	case LICHEN_TIME_SOURCE_GNSS:
		return "GNSS";
	case LICHEN_TIME_SOURCE_NETWORK:
		return "Network";
	case LICHEN_TIME_SOURCE_LOCAL_CLIENT:
		return "Local-client";
	case LICHEN_TIME_SOURCE_MANUAL:
		return "Manual/static";
	case LICHEN_TIME_SOURCE_INTERNAL_RTC:
		return "Internal RTC";
	case LICHEN_TIME_SOURCE_MONOTONIC:
		return "Monotonic";
	default:
		return "Unknown";
	}
}

bool lichen_time_source_can_establish_wall_clock(enum lichen_time_source_class source)
{
	return source != LICHEN_TIME_SOURCE_MONOTONIC;
}

/* ---- Time stratum ---- */

bool lichen_time_stratum_valid(uint8_t stratum)
{
	return stratum <= LICHEN_TIME_STRATUM_GNSS_GPSD;
}

/* ---- Epoch floor ---- */

int lichen_epoch_floor_init(uint32_t firmware_build_epoch)
{
	if (firmware_build_epoch == 0) {
		LOG_ERR("Zero firmware build epoch rejected");
		return -EINVAL;
	}
	s_firmware_build_epoch = firmware_build_epoch;
	s_provision_epoch = 0;
	s_provision_authenticated = false;
	return 0;
}

int lichen_epoch_floor_set_provision(uint32_t provision_epoch,
				     bool authenticated,
				     uint32_t max_lead_s,
				     enum lichen_provision_status *status)
{
	if (s_firmware_build_epoch == 0) {
		LOG_ERR("Epoch floor not initialized");
		return -EINVAL;
	}
	if (status == NULL) {
		return -EINVAL;
	}

	if (!authenticated) {
		*status = LICHEN_PROVISION_UNAUTHENTICATED;
		return 0;
	}

	if (provision_epoch < s_firmware_build_epoch) {
		*status = LICHEN_PROVISION_BEFORE_BUILD;
		return 0;
	}

	/* Check lead bound with overflow protection */
	uint32_t lead = provision_epoch - s_firmware_build_epoch;
	if (lead > max_lead_s) {
		*status = LICHEN_PROVISION_BEYOND_LEAD;
		return 0;
	}

	s_provision_epoch = provision_epoch;
	s_provision_authenticated = true;
	*status = LICHEN_PROVISION_ACCEPTED;
	return 0;
}

uint32_t lichen_epoch_floor_get(void)
{
	if (s_provision_authenticated && s_provision_epoch >= s_firmware_build_epoch) {
		return s_provision_epoch;
	}
	return s_firmware_build_epoch;
}

bool lichen_epoch_floor_accepts(uint32_t unix_time)
{
	return unix_time >= lichen_epoch_floor_get();
}

const char *lichen_provision_status_str(enum lichen_provision_status status)
{
	switch (status) {
	case LICHEN_PROVISION_MISSING:
		return "missing";
	case LICHEN_PROVISION_ACCEPTED:
		return "accepted";
	case LICHEN_PROVISION_UNAUTHENTICATED:
		return "unauthenticated";
	case LICHEN_PROVISION_BEFORE_BUILD:
		return "before-build";
	case LICHEN_PROVISION_BEYOND_LEAD:
		return "beyond-lead";
	default:
		return "unknown";
	}
}

/* ---- DIO Time Option ---- */

int lichen_dio_time_option_encode(const struct lichen_dio_time_option *opt,
				  uint8_t *buf, size_t buflen)
{
	if (opt == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buflen < LICHEN_DIO_TIME_OPTION_LEN) {
		return -ENOMEM;
	}
	if (opt->stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}
	/* NO_SYNC stratum MUST have zero timestamp */
	if (opt->stratum == LICHEN_TIME_STRATUM_NO_SYNC && opt->timestamp != 0) {
		return -EINVAL;
	}

	buf[0] = LICHEN_DIO_TIME_OPTION_TYPE;
	buf[1] = LICHEN_DIO_TIME_OPTION_DATA_LEN;
	buf[2] = opt->stratum;
	buf[3] = 0; /* Reserved */
	buf[4] = (opt->timestamp >> 24) & 0xFF;
	buf[5] = (opt->timestamp >> 16) & 0xFF;
	buf[6] = (opt->timestamp >> 8) & 0xFF;
	buf[7] = opt->timestamp & 0xFF;

	return LICHEN_DIO_TIME_OPTION_LEN;
}

int lichen_dio_time_option_decode(const uint8_t *buf, size_t buflen,
				  struct lichen_dio_time_option *opt)
{
	if (buf == NULL || opt == NULL) {
		return -EINVAL;
	}
	if (buflen < LICHEN_DIO_TIME_OPTION_LEN) {
		return -ENODATA;
	}
	if (buf[0] != LICHEN_DIO_TIME_OPTION_TYPE) {
		return -EPROTO;
	}
	if (buf[1] != LICHEN_DIO_TIME_OPTION_DATA_LEN) {
		return -EPROTO;
	}
	if (buf[3] != 0) {
		/* Reserved field must be zero */
		return -EPROTO;
	}
	if (buf[2] > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EPROTO;
	}

	opt->stratum = buf[2];
	opt->timestamp = ((uint32_t)buf[4] << 24) |
			 ((uint32_t)buf[5] << 16) |
			 ((uint32_t)buf[6] << 8) |
			 (uint32_t)buf[7];

	/* NO_SYNC stratum MUST have zero timestamp */
	if (opt->stratum == LICHEN_TIME_STRATUM_NO_SYNC && opt->timestamp != 0) {
		return -EPROTO;
	}

	return LICHEN_DIO_TIME_OPTION_LEN;
}

/* ---- Wall clock management ---- */

int lichen_wall_clock_set(uint32_t unix_time,
			  enum lichen_time_source_class source,
			  uint8_t stratum)
{
	if (!lichen_time_source_can_establish_wall_clock(source)) {
		LOG_WRN("Source %s cannot establish wall clock",
			lichen_time_source_class_str(source));
		return -EINVAL;
	}
	if (stratum == LICHEN_TIME_STRATUM_NO_SYNC) {
		LOG_WRN("Stratum NO_SYNC cannot establish wall clock");
		return -EINVAL;
	}
	if (!lichen_epoch_floor_accepts(unix_time)) {
		LOG_WRN("Unix time %u below epoch floor %u",
			unix_time, lichen_epoch_floor_get());
		return -ERANGE;
	}

	s_wall_clock_unix = unix_time;
	s_wall_clock_source = source;
	s_stratum = stratum;
	s_wall_clock_valid = true;

	LOG_INF("Wall clock set: %u (source=%s, stratum=%u)",
		unix_time, lichen_time_source_class_str(source), stratum);

	return 0;
}

bool lichen_wall_clock_valid(void)
{
	return s_wall_clock_valid;
}

uint32_t lichen_wall_clock_get(void)
{
	return s_wall_clock_unix;
}

enum lichen_time_source_class lichen_wall_clock_source(void)
{
	return s_wall_clock_source;
}

void lichen_wall_clock_invalidate(void)
{
	s_wall_clock_valid = false;
	s_stratum = LICHEN_TIME_STRATUM_NO_SYNC;
	LOG_INF("Wall clock invalidated");
}

/* ---- SFN (Super Frame Number) management ---- */

uint32_t lichen_time_sync_get_sfn(void)
{
	return s_current_sfn;
}

int lichen_time_sync_set_sfn(uint32_t sfn)
{
	if (s_synced && sfn <= s_current_sfn) {
		return -EALREADY;
	}

	s_current_sfn = sfn;
	s_synced = true;

	return 0;
}

bool lichen_time_sync_is_synced(void)
{
	return s_synced;
}

void lichen_time_sync_advance_sfn(void)
{
	s_current_sfn++;
}

void lichen_time_sync_desync(void)
{
	s_synced = false;
	s_stratum = LICHEN_TIME_STRATUM_NO_SYNC;
}

uint8_t lichen_time_sync_get_stratum(void)
{
	return s_stratum;
}

int lichen_time_sync_set_stratum(uint8_t stratum)
{
	if (stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}

	s_stratum = stratum;
	return 0;
}

int lichen_time_sync_update_from_parent(uint32_t sfn, uint8_t parent_stratum)
{
	if (parent_stratum == LICHEN_TIME_STRATUM_NO_SYNC ||
	    parent_stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}

	int err = lichen_time_sync_set_sfn(sfn);
	if (err == 0 || err == -EALREADY) {
		/* Child stratum is parent - 1, clamped to 0 minimum */
		s_stratum = (parent_stratum > 0) ? (parent_stratum - 1) : 0;
		return 0;
	}

	return err;
}

int lichen_time_sync_init(void)
{
	s_current_sfn = 0;
	s_synced = false;
	s_stratum = LICHEN_TIME_STRATUM_NO_SYNC;
	s_wall_clock_unix = 0;
	s_wall_clock_valid = false;
	s_wall_clock_source = LICHEN_TIME_SOURCE_MONOTONIC;
	s_firmware_build_epoch = 0;
	s_provision_epoch = 0;
	s_provision_authenticated = false;

	return 0;
}
