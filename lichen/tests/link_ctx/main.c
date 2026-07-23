/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <lichen/link_ctx.h>
#include <string.h>

static bool entropy_fails;
static uint8_t entropy_byte;

int getentropy(void *buffer, size_t length)
{
	if (entropy_fails) {
		return -1;
	}

	memset(buffer, entropy_byte, length);
	return 0;
}

static int test_entropy_failure_preserves_context(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = { 0 };
	struct lichen_link_ctx ctx;
	struct lichen_link_ctx before;

	memset(&ctx, 0xa5, sizeof(ctx));
	memcpy(&before, &ctx, sizeof(before));
	entropy_fails = true;
	if (lichen_link_init(&ctx, eui64) != -EIO) {
		return 1;
	}
	return memcmp(&ctx, &before, sizeof(ctx)) != 0;
}

static int test_entropy_success_maps_epoch(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = {
		0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
	};
	struct lichen_link_ctx ctx;

	entropy_fails = false;
	entropy_byte = 0x42;
	if (lichen_link_init(&ctx, eui64) != 0) {
		return 1;
	}
	int failed = ctx.epoch != 0xc2 || ctx.tx_seq != 0 || ctx.has_key ||
		ctx.has_link_key || ctx.nonce_exhausted ||
		memcmp(ctx.eui64, eui64, sizeof(eui64)) != 0;
	lichen_link_cleanup(&ctx);
	return failed;
}

int main(void)
{
	int failed = test_entropy_failure_preserves_context();

	failed |= test_entropy_success_maps_epoch();
	return failed;
}
