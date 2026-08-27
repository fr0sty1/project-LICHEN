/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file epoch_persist.c
 * @brief Persist the link TX epoch across reboots (lora_ipv6_mesh-3uhb, ado5)
 *
 * link_ctx.c picks a random epoch in [128,255] at boot "for reboot
 * resilience without flash". But a peer remembers this node's last
 * (epoch, seqnum) in its replay window, and whenever the fresh random
 * epoch is lower than the remembered one, every frame from the new boot
 * is rejected as a replay — a ~50% coin flip per reboot, per peer.
 *
 * With persistence we advance the epoch by exactly one each boot. Epochs use
 * ordinary unsigned ordering and 255 is terminal: wrapping to zero is
 * forbidden and requires key rotation.
 *
 * For T1000-E: add SMP epoch handler (mcumgr settings group) or erase
 * storage_partition before flash to clear stale Meshtastic NVS data
 * that prevents settings_load_subtree() from succeeding (see ado5).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <lichen/link_ctx.h>

LOG_MODULE_REGISTER(lichen_epoch, CONFIG_LICHEN_LINK_LOG_LEVEL);

#define EPOCH_KEY      "lichen/epoch"
#define EPOCH_KEY_LEAF EPOCH_KEY "/e"
#define EPOCH_RECORD_MAGIC UINT32_C(0x4c45504f)
#define EPOCH_RECORD_VERSION 1U

struct epoch_record {
	uint32_t magic;
	uint8_t version;
	uint8_t epoch;
	uint8_t epoch_inverse;
	uint8_t checksum;
};

_Static_assert(sizeof(struct epoch_record) == 8U,
	       "epoch persistence record layout must remain stable");

/* Last value durably saved by this boot. */
static uint8_t s_persisted;
static uint8_t s_boot_epoch;
static bool s_advanced;
/* Settings callbacks stage into these fields; they are not authoritative. */
static uint8_t s_load_epoch;
static bool s_load_seen;
static K_MUTEX_DEFINE(s_epoch_mutex);

static uint8_t epoch_record_checksum(const struct epoch_record *record)
{
	uint32_t magic = record->magic;

	return (uint8_t)(0xa5U ^ (uint8_t)magic ^ (uint8_t)(magic >> 8) ^
			 (uint8_t)(magic >> 16) ^ (uint8_t)(magic >> 24) ^
			 record->version ^ record->epoch ^ record->epoch_inverse);
}

static struct epoch_record epoch_record_make(uint8_t epoch)
{
	struct epoch_record record = {
		.magic = EPOCH_RECORD_MAGIC,
		.version = EPOCH_RECORD_VERSION,
		.epoch = epoch,
		.epoch_inverse = (uint8_t)~epoch,
	};

	record.checksum = epoch_record_checksum(&record);
	return record;
}

static bool epoch_record_valid(const struct epoch_record *record)
{
	/* Cast the complement explicitly: ~epoch promotes to int and the
	 * bare comparison against the stored uint8_t trips -Wsign-compare. */
	const uint8_t inverse = (uint8_t)~record->epoch;
	return record->magic == EPOCH_RECORD_MAGIC &&
	       record->version == EPOCH_RECORD_VERSION &&
	       record->epoch_inverse == inverse &&
	       record->checksum == epoch_record_checksum(record);
}

static int epoch_set(const char *name, size_t len, settings_read_cb read_cb,
		     void *cb_arg)
{
	const char *next;

	if (settings_name_steq(name, "e", &next) && next == NULL) {
		struct epoch_record record;

		if (len != sizeof(record)) {
			return -EBADMSG;
		}
		ssize_t rc = read_cb(cb_arg, &record, sizeof(record));
		if (rc < 0) {
			return (int)rc;
		}
		if ((size_t)rc != sizeof(record) || !epoch_record_valid(&record)) {
			return -EBADMSG;
		}
		s_load_epoch = record.epoch;
		s_load_seen = true;
		return 0;
	}

	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(lichen_epoch, EPOCH_KEY, NULL, epoch_set, NULL,
			      NULL);

int lichen_link_epoch_advance_for_boot(uint8_t fallback_epoch, uint8_t *epoch)
{
	if (epoch == NULL || fallback_epoch < 128U) {
		return -EINVAL;
	}
	k_mutex_lock(&s_epoch_mutex, K_FOREVER);
	if (s_advanced) {
		*epoch = s_boot_epoch;
		k_mutex_unlock(&s_epoch_mutex);
		return 0;
	}

	int rc = settings_subsys_init();
	if (rc != 0) {
		k_mutex_unlock(&s_epoch_mutex);
		return rc;
	}
	s_load_seen = false;
	s_load_epoch = 0U;
	rc = settings_load_subtree(EPOCH_KEY);
	if (rc != 0) {
		s_load_seen = false;
		s_load_epoch = 0U;
		k_mutex_unlock(&s_epoch_mutex);
		return rc;
	}
	if (s_load_seen && s_load_epoch == UINT8_MAX) {
		k_mutex_unlock(&s_epoch_mutex);
		return -EOVERFLOW;
	}
	uint8_t candidate = s_load_seen ? (uint8_t)(s_load_epoch + 1U) : fallback_epoch;
	struct epoch_record record = epoch_record_make(candidate);

	rc = settings_save_one(EPOCH_KEY_LEAF, &record, sizeof(record));
	if (rc != 0) {
		k_mutex_unlock(&s_epoch_mutex);
		return rc;
	}
	/* Publish only after the durable write succeeds. */
	s_persisted = candidate;
	s_boot_epoch = candidate;
	s_advanced = true;
	*epoch = candidate;
	LOG_INF("link TX epoch %u (persisted)", candidate);
	k_mutex_unlock(&s_epoch_mutex);
	return 0;
}

int lichen_link_epoch_persist(uint8_t epoch)
{
	if (epoch == 0U) {
		return -EOVERFLOW;
	}

	k_mutex_lock(&s_epoch_mutex, K_FOREVER);
	if (s_advanced && epoch <= s_boot_epoch) {
		k_mutex_unlock(&s_epoch_mutex);
		return -ERANGE;
	}
	struct epoch_record record = epoch_record_make(epoch);
	int rc = settings_save_one(EPOCH_KEY_LEAF, &record, sizeof(record));
	if (rc == 0) {
		s_persisted = epoch;
		s_boot_epoch = epoch;
		s_advanced = true;
	}
	k_mutex_unlock(&s_epoch_mutex);

	if (rc != 0) {
		LOG_ERR("epoch persist failed (%d); TX blocked", rc);
	}
	return rc;
}

#ifdef CONFIG_LICHEN_LINK_EPOCH_TEST_HOOKS
void lichen_link_epoch_test_reset(void)
{
	k_mutex_lock(&s_epoch_mutex, K_FOREVER);
	s_advanced = false;
	s_persisted = 0;
	s_boot_epoch = 0;
	s_load_epoch = 0;
	s_load_seen = false;
	k_mutex_unlock(&s_epoch_mutex);
}
#endif
