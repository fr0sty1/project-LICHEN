/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Link TX epoch persistence tests (lora_ipv6_mesh-3uhb)
 *
 * Verifies that lichen_link_epoch_advance_for_boot() advances the epoch by
 * one each boot, persists it across (simulated) reboots, wraps 255->0, and
 * is idempotent within a boot. lichen_link_epoch_test_reset() clears the
 * in-RAM cache to simulate a reboot while the settings backend retains the
 * persisted value.
 */

#include <zephyr/ztest.h>
#include <zephyr/settings/settings.h>

#include <lichen/link_ctx.h>

#define EPOCH_KEY_LEAF "lichen/epoch/e"

/* Seed the persisted epoch as if a previous boot had saved it. */
static void seed_persisted(uint8_t value)
{
	int rc = settings_save_one(EPOCH_KEY_LEAF, &value, sizeof(value));

	zassert_equal(rc, 0, "seed settings_save_one failed: %d", rc);
}

static void *epoch_setup(void)
{
	zassert_equal(settings_subsys_init(), 0, "settings init failed");
	return NULL;
}

/* Fresh RAM (simulated reboot) before every test; the backend keeps its
 * last persisted value, which each test overwrites via seed_persisted(). */
static void epoch_before(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_link_epoch_test_reset();
}

ZTEST_SUITE(link_epoch, NULL, epoch_setup, epoch_before, NULL, NULL);

ZTEST(link_epoch, test_advance_increments_persisted)
{
	seed_persisted(42);
	lichen_link_epoch_test_reset();

	uint8_t e = lichen_link_epoch_advance_for_boot();

	zassert_equal(e, 43, "advance should be persisted+1, got %u", e);
}

ZTEST(link_epoch, test_wrap_255_to_0)
{
	seed_persisted(255);
	lichen_link_epoch_test_reset();

	uint8_t e = lichen_link_epoch_advance_for_boot();

	zassert_equal(e, 0, "255 must wrap to 0, got %u", e);
}

ZTEST(link_epoch, test_idempotent_within_boot)
{
	seed_persisted(10);
	lichen_link_epoch_test_reset();

	uint8_t e1 = lichen_link_epoch_advance_for_boot();
	uint8_t e2 = lichen_link_epoch_advance_for_boot();

	zassert_equal(e1, 11, "first advance should be 11, got %u", e1);
	zassert_equal(e2, e1, "repeated advance must not re-increment (%u != %u)",
		      e2, e1);
}

ZTEST(link_epoch, test_monotonic_across_reboots)
{
	seed_persisted(100);

	/* Boot 1 */
	lichen_link_epoch_test_reset();
	uint8_t e1 = lichen_link_epoch_advance_for_boot();
	zassert_equal(e1, 101, "boot 1 epoch should be 101, got %u", e1);

	/* Boot 2: RAM cleared, backend retains 101 from boot 1's persist */
	lichen_link_epoch_test_reset();
	uint8_t e2 = lichen_link_epoch_advance_for_boot();
	zassert_equal(e2, 102, "boot 2 epoch should be 102, got %u", e2);

	/* Boot 3 */
	lichen_link_epoch_test_reset();
	uint8_t e3 = lichen_link_epoch_advance_for_boot();
	zassert_equal(e3, 103, "boot 3 epoch should be 103, got %u", e3);
}

ZTEST(link_epoch, test_sequence_wrap_is_persisted_before_reboot)
{
	static const uint8_t eui64[LICHEN_EUI64_LEN] = { 0 };
	struct lichen_link_ctx ctx;
	uint8_t epoch;
	uint16_t seq;

	seed_persisted(41);
	lichen_link_epoch_test_reset();
	zassert_equal(lichen_link_init(&ctx, eui64), 0);
	lichen_link_set_epoch(&ctx, lichen_link_epoch_advance_for_boot());

	for (uint32_t i = 0; i <= UINT16_MAX; i++) {
		zassert_equal(lichen_link_next_tx(&ctx, &epoch, &seq), 0,
			      "allocation %u failed", i);
	}
	zassert_equal(epoch, 42, "last pre-wrap tuple used wrong epoch");
	zassert_equal(seq, UINT16_MAX, "long run did not reach sequence wrap");
	zassert_equal(ctx.epoch, 43, "live epoch did not advance at wrap");

	lichen_link_epoch_test_reset();
	zassert_equal(lichen_link_epoch_advance_for_boot(), 44,
		      "reboot reused the live post-wrap epoch");
	lichen_link_cleanup(&ctx);
}
