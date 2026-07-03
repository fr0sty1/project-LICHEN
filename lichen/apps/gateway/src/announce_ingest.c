/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "announce_ingest.h"

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/routing/announce.h>

#include "network_location.h"

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

static int gateway_announce_app_data_observer(
	const struct lichen_announce_view *announce,
	const struct lichen_announce_rx_meta *meta,
	void *user_data)
{
	struct gateway_network_location_announce_sample sample;
	struct gateway_network_location_announce_record existing_record;
	uint32_t observed_uptime_s;
	uint32_t location_seq_num;
	bool accepted_expired_reset = false;
	int ret;

	ARG_UNUSED(user_data);

	if (announce == NULL) {
		return -EINVAL;
	}

	observed_uptime_s = (meta != NULL && meta->observed_uptime_s != 0U) ?
			    meta->observed_uptime_s : 0U;
	if (observed_uptime_s == 0U) {
		observed_uptime_s = k_uptime_get_32() / 1000U;
	}
	location_seq_num = announce->seq_num;

	ret = gateway_network_location_announce_get(
		announce->originator_iid, LICHEN_ANNOUNCE_IID_LEN,
		&existing_record);
	if (ret == 0) {
		if (!announce_seq_newer(announce->wire_seq_num,
					(uint16_t)existing_record.seq_num) &&
		    !downstream_record_expired(observed_uptime_s,
					       &existing_record)) {
			return -EALREADY;
		}
		accepted_expired_reset = !announce_seq_newer(
			announce->wire_seq_num,
			(uint16_t)existing_record.seq_num);
		location_seq_num = extend_location_seq(announce->wire_seq_num,
						       existing_record.seq_num);
	} else if (ret != -ENOENT) {
		return ret;
	} else if (announce->seq_stale) {
		return -EALREADY;
	}

	sample.peer_id = announce->originator_iid;
	sample.peer_id_len = LICHEN_ANNOUNCE_IID_LEN;
	sample.seq_num = location_seq_num;
	sample.observed_uptime_s = observed_uptime_s;
	sample.app_data = announce->app_data;
	sample.app_data_len = announce->app_data_len;

	ret = gateway_network_location_submit_announce(&sample);
	if (ret < 0) {
		return ret;
	}
	return accepted_expired_reset ? LICHEN_ANNOUNCE_ACCEPT_SEQ_RESET : 0;
}

static void ensure_gateway_observer(void)
{
	(void)lichen_announce_register_app_data_observer_ex(
		gateway_announce_app_data_observer, NULL,
		LICHEN_ANNOUNCE_OBSERVER_F_ALLOW_SEQ_RESET);
}

int gateway_announce_parse(const uint8_t *data, size_t len,
			   struct gateway_announce_view *announce)
{
	struct lichen_announce_view view;
	int ret;

	if (announce == NULL) {
		return -EINVAL;
	}

	ret = lichen_announce_parse(data, len, &view);
	if (ret < 0) {
		return ret;
	}

	announce->flags = view.flags;
	announce->hop_count = view.hop_count;
	announce->seq_num = view.wire_seq_num;
	announce->originator_iid = view.originator_iid;
	announce->pubkey = view.pubkey;
	announce->signature = view.signature;
	announce->app_data = view.app_data;
	announce->app_data_len = view.app_data_len;
	return 0;
}

int gateway_announce_ingest_verified(const uint8_t *data, size_t len)
{
	ensure_gateway_observer();
	return lichen_announce_ingest_authenticated(data, len, NULL);
}

int gateway_announce_ingest_l2_payload(const uint8_t *data, size_t len)
{
	ensure_gateway_observer();
	return lichen_announce_ingest_l2_payload(data, len, NULL);
}

void gateway_announce_ingest_reset(void)
{
	lichen_announce_reset();
	ensure_gateway_observer();
}
