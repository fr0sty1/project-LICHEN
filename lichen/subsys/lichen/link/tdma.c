/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/errno.h>
#include <string.h>
#include <stdbool.h>

int lichen_tdma_compute_slot(const uint8_t eui64[8], uint32_t epoch, uint8_t num_slots)
{
	if (num_slots == 0) num_slots = 8;
	uint8_t data[8];
	memcpy(data, eui64, 8);
	uint32_t e = epoch;
	for (size_t i = 0; i < 4; i++) {
		data[i] ^= (uint8_t)(e & 0xff);
		e >>= 8;
	}
	uint32_t h = lichen_hash_32(data, 8);
	return (uint8_t)(h % num_slots);
}

int lichen_tdma_init(struct lichen_tdma_ctx *tdma, struct lichen_link_ctx *ctx)
{
	if (tdma == NULL || ctx == NULL) return -EINVAL;
	uint8_t slot = lichen_tdma_compute_slot(ctx->eui64, (uint32_t)ctx->epoch, 8);
	tdma->slot = slot;
	tdma->n_slots = 8;
	tdma->superframe = 0;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	tdma->synced = false;
	return 0;
}

int lichen_link_set_slot(struct lichen_link_ctx *ctx, struct lichen_tdma_ctx *tdma, uint8_t slot_id, uint8_t n_slots, uint32_t sfn)
{
	if (tdma == NULL) return -EINVAL;
	if (slot_id == 0xff && ctx != NULL) {
		slot_id = lichen_tdma_compute_slot(ctx->eui64, (uint32_t)ctx->epoch, n_slots ? n_slots : 8);
	}
	tdma->slot = slot_id;
	tdma->n_slots = n_slots ? n_slots : 8;
	tdma->superframe = sfn;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	tdma->synced = true;
	return 0;
}

bool tdma_tx_allowed(const struct lichen_tdma_ctx *tdma, uint32_t now_ms)
{
	if (tdma == NULL || !tdma->synced) return true;
	uint32_t d = tdma->slot_duration;
	uint32_t slot_start = tdma->superframe * (uint32_t)tdma->n_slots * d + (uint32_t)tdma->slot * d;
	uint32_t g = LICHEN_TDMA_GUARD_MS;
	return (slot_start - g <= now_ms) && (now_ms <= slot_start + d + g);
}
