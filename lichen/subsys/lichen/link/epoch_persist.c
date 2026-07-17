/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file epoch_persist.c
 * @brief Persist the link TX epoch across reboots (lora_ipv6_mesh-3uhb)
 *
 * link_ctx.c picks a random epoch in [128,255] at boot "for reboot
 * resilience without flash". But a peer remembers this node's last
 * (epoch, seqnum) in its replay window, and whenever the fresh random
 * epoch is lower than the remembered one, every frame from the new boot
 * is rejected as a replay — a ~50% coin flip per reboot, per peer.
 *
 * With persistence we advance the epoch by exactly one each boot. The
 * replay window compares 24-bit counters ((epoch << 16) | seqnum) with
 * half-space (RFC 1982) arithmetic, so a +1 epoch is always "ahead" of
 * the peer's remembered counter — even across the 255->0 wrap — and a
 * rebooted node is never mistaken for a replay.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <lichen/link_ctx.h>

LOG_MODULE_REGISTER(lichen_epoch, CONFIG_LICHEN_LINK_LOG_LEVEL);

#define EPOCH_KEY      "lichen/epoch"
#define EPOCH_KEY_LEAF EPOCH_KEY "/e"

/* Last value read back from settings (previous boot's epoch). */
static uint8_t s_persisted;
/* Epoch chosen for this boot; stable once computed. */
static uint8_t s_boot_epoch;
/* True once this boot's epoch has been computed and persisted. */
static bool s_advanced;

static int epoch_set(const char *name, size_t len, settings_read_cb read_cb,
		     void *cb_arg)
{
	const char *next;

	if (settings_name_steq(name, "e", &next) && next == NULL) {
		if (len != sizeof(s_persisted)) {
			return -EINVAL;
		}

		ssize_t rc = read_cb(cb_arg, &s_persisted, sizeof(s_persisted));

		return (rc < 0) ? (int)rc : 0;
	}

	return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(lichen_epoch, EPOCH_KEY, NULL, epoch_set, NULL,
			      NULL);

uint8_t lichen_link_epoch_advance_for_boot(void)
{
	if (s_advanced) {
		return s_boot_epoch;
	}

	int rc = settings_subsys_init();

	if (rc == 0) {
		(void)settings_load_subtree(EPOCH_KEY);
	} else {
		LOG_WRN("settings init failed (%d); epoch not persisted", rc);
	}

	/* Monotonic advance with 8-bit wrap (see file header). */
	s_boot_epoch = (uint8_t)(s_persisted + 1U);
	s_advanced = true;

	rc = settings_save_one(EPOCH_KEY_LEAF, &s_boot_epoch,
			       sizeof(s_boot_epoch));
	if (rc != 0) {
		LOG_WRN("epoch persist failed (%d); reboot replay risk", rc);
	} else {
		LOG_INF("link TX epoch %u (persisted)", s_boot_epoch);
	}

	return s_boot_epoch;
}

#ifdef CONFIG_LICHEN_LINK_EPOCH_TEST_HOOKS
void lichen_link_epoch_test_reset(void)
{
	s_advanced = false;
	s_persisted = 0;
	s_boot_epoch = 0;
}
#endif
