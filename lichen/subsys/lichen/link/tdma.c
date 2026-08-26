/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tdma.c
 * @brief LICHEN TDMA slot scheduling (gateway-centric mode)
 *
 * Implements hash-based slot computation and TDMA context management
 * for coordinated capacity protocol (CCP). Enabled via CONFIG_LICHEN_TDMA.
 */

#include <lichen/link_ctx.h>
#include <lichen/link.h>
#include <lichen/errno.h>
#include <string.h>
#include <stdbool.h>

#ifdef CONFIG_LICHEN_TDMA

uint8_t lichen_tdma_compute_slot(const uint8_t eui64[8], uint32_t sfn, uint8_t num_slots)
{
	if (num_slots == 0) num_slots = 8;
	return (uint8_t)((lichen_hash_32(eui64, 8) + sfn) % num_slots);
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
	tdma->ccp_state = LICHEN_CCP_UNJOINED;
	tdma->missed_beacons = 0;
	return 0;
}

int lichen_ccp_fsm_event(struct lichen_tdma_ctx *tdma, enum lichen_ccp_event event, uint8_t missed)
{
	if (tdma == NULL) return -EINVAL;

	/* CCP FSM per spec/09-packets-timing.md section 14.8 and tdma_ccp_fsm.json */
	switch (tdma->ccp_state) {
	case LICHEN_CCP_UNJOINED:
		if (event == LICHEN_CCP_EVENT_INIT) {
			tdma->ccp_state = LICHEN_CCP_ACQUIRING;
			tdma->missed_beacons = 0;
		}
		break;

	case LICHEN_CCP_ACQUIRING:
		if (event == LICHEN_CCP_EVENT_VALID_BEACON) {
			tdma->ccp_state = LICHEN_CCP_SYNCED;
			tdma->synced = true;
			tdma->missed_beacons = 0;
		}
		break;

	case LICHEN_CCP_SYNCED:
		if (event == LICHEN_CCP_EVENT_BEACON_IN_SLOT) {
			/* Stay SYNCED, reset missed counter */
			tdma->missed_beacons = 0;
		} else if (event == LICHEN_CCP_EVENT_MISSED_BEACON) {
			tdma->missed_beacons = missed;
			/* >3 missed beacons triggers DRIFTING */
			if (missed > LICHEN_TDMA_MISSED_BEACON_THRESHOLD) {
				tdma->ccp_state = LICHEN_CCP_DRIFTING;
				tdma->synced = false;
			}
		} else if (event == LICHEN_CCP_EVENT_RPL_VERSION) {
			tdma->ccp_state = LICHEN_CCP_DRIFTING;
			tdma->synced = false;
		}
		break;

	case LICHEN_CCP_DRIFTING:
		if (event == LICHEN_CCP_EVENT_VALID_BEACON) {
			tdma->ccp_state = LICHEN_CCP_ACQUIRING;
			tdma->missed_beacons = 0;
		} else if (event == LICHEN_CCP_EVENT_INVALID_BEACON) {
			/* Stay DRIFTING */
		}
		break;

	case LICHEN_CCP_REJOINING:
		if (event == LICHEN_CCP_EVENT_DAO_ACK_SLOT) {
			tdma->ccp_state = LICHEN_CCP_SYNCED;
			tdma->synced = true;
			tdma->missed_beacons = 0;
		}
		break;
	}

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

#endif /* CONFIG_LICHEN_TDMA */
