/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Link TX epoch persistence tests (lora_ipv6_mesh-3uhb)
 *
 * Verifies that lichen_link_epoch_advance_for_boot() advances the epoch by
 * one each boot, persists it across simulated reboots, rejects 255->0, and
 * is idempotent within a boot. lichen_link_epoch_test_reset() clears the
 * in-RAM cache to simulate a reboot while the settings backend retains the
 * persisted value.
 */

#include <zephyr/ztest.h>
#include <zephyr/settings/settings.h>

#include <lichen/link_ctx.h>

/* Seed the persisted epoch as if a previous boot had saved it. */
static void seed_persisted(uint8_t value)
{
	lichen_link_epoch_test_reset();
	zassert_ok(lichen_link_epoch_persist(value));
	lichen_link_epoch_test_reset();
}

static uint8_t advance(uint8_t fallback)
{
	uint8_t epoch = 0;

	zassert_ok(lichen_link_epoch_advance_for_boot(fallback, &epoch));
	return epoch;
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

	uint8_t e = advance(200);

	zassert_equal(e, 43, "advance should be persisted+1, got %u", e);
}

ZTEST(link_epoch, test_wrap_255_is_rejected)
{
	seed_persisted(255);
	lichen_link_epoch_test_reset();
	uint8_t epoch = 0xa5;

	zassert_equal(lichen_link_epoch_advance_for_boot(200, &epoch), -EOVERFLOW);
	zassert_equal(epoch, 0xa5, "failure must not publish an epoch");
}

ZTEST(link_epoch, test_idempotent_within_boot)
{
	seed_persisted(10);
	lichen_link_epoch_test_reset();

	uint8_t e1 = advance(200);
	uint8_t e2 = advance(201);

	zassert_equal(e1, 11, "first advance should be 11, got %u", e1);
	zassert_equal(e2, e1, "repeated advance must not re-increment (%u != %u)",
		      e2, e1);
}

ZTEST(link_epoch, test_monotonic_across_reboots)
{
	seed_persisted(100);

	/* Boot 1 */
	lichen_link_epoch_test_reset();
	uint8_t e1 = advance(200);
	zassert_equal(e1, 101, "boot 1 epoch should be 101, got %u", e1);

	/* Boot 2: RAM cleared, backend retains 101 from boot 1's persist */
	lichen_link_epoch_test_reset();
	uint8_t e2 = advance(200);
	zassert_equal(e2, 102, "boot 2 epoch should be 102, got %u", e2);

	/* Boot 3 */
	lichen_link_epoch_test_reset();
	uint8_t e3 = advance(200);
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
	uint8_t boot_epoch = advance(200);
	zassert_ok(lichen_link_set_epoch(&ctx, boot_epoch));

	for (uint32_t i = 0; i <= UINT16_MAX; i++) {
		zassert_equal(lichen_link_next_tx(&ctx, &epoch, &seq), 0,
			      "allocation %u failed", i);
	}
	zassert_equal(epoch, 42, "last pre-wrap tuple used wrong epoch");
	zassert_equal(seq, UINT16_MAX, "long run did not reach sequence wrap");
	zassert_equal(ctx.epoch, 43, "live epoch did not advance at wrap");

	lichen_link_epoch_test_reset();
	zassert_equal(advance(200), 44,
		      "reboot reused the live post-wrap epoch");
	lichen_link_cleanup(&ctx);
}

ZTEST(link_epoch, test_missing_record_uses_random_fallback)
{
	uint8_t epoch;

	/* A unique subtree is not available to this fixed handler; resetting the
	 * backend is covered by the host fault-injection suite. Validate input here. */
	zassert_equal(lichen_link_epoch_advance_for_boot(127, &epoch), -EINVAL);
	zassert_equal(lichen_link_epoch_advance_for_boot(200, NULL), -EINVAL);
}

ZTEST(link_epoch, test_persist_rejects_zero_and_rollback)
{
	seed_persisted(40);
	zassert_equal(advance(200), 41);
	zassert_equal(lichen_link_epoch_persist(0), -EOVERFLOW);
	zassert_equal(lichen_link_epoch_persist(41), -ERANGE);
	zassert_equal(lichen_link_epoch_persist(40), -ERANGE);
}
