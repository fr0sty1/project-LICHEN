/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_multi_instance.c
 * @brief RPL Multi-Instance Coordination for Gateway Cooperation (GCP-5)
 *
 * Implementation of multi-root DODAG coordination as specified in
 * spec/08-gateway-coordination.md GCP-5. Follows the Python oracle
 * in python/src/lichen/rpl/multi_instance.py.
 */

#include <errno.h>
#include <string.h>

#include <lichen/rpl_multi_instance.h>

/* ── Coordinator initialization ────────────────────────────────────────────── */

int lichen_rpl_coordinator_init(
	struct lichen_rpl_multi_root_coordinator *coord,
	uint8_t rpl_instance_id)
{
	if (coord == NULL) {
		return -EINVAL;
	}

	memset(coord, 0, sizeof(*coord));
	coord->rpl_instance_id = rpl_instance_id;
	coord->dodag_version = LICHEN_RPL_INITIAL_DODAG_VERSION;
	coord->has_local_gateway = false;
	coord->peer_count = 0;

	return 0;
}

int lichen_rpl_coordinator_set_local(
	struct lichen_rpl_multi_root_coordinator *coord,
	const uint8_t *iid,
	bool has_gps)
{
	if (coord == NULL || iid == NULL) {
		return -EINVAL;
	}

	memcpy(coord->local_gateway.iid, iid, 16);
	coord->local_gateway.has_gps = has_gps;
	coord->local_gateway.valid = true;
	/* Default capabilities */
	coord->local_gateway.supports_psk = true;
	coord->local_gateway.supports_ed25519 = true;
	coord->local_gateway.slot_style = 0; /* interleaved */
	coord->local_gateway.superframe_duration_s = 60;
	coord->has_local_gateway = true;

	return 0;
}

/* ── Peer management ───────────────────────────────────────────────────────── */

int lichen_rpl_coordinator_add_peer(
	struct lichen_rpl_multi_root_coordinator *coord,
	const struct lichen_rpl_gateway_info *info)
{
	if (coord == NULL || info == NULL) {
		return -EINVAL;
	}

	/* Check for existing peer with same IID (update) */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS; i++) {
		if (coord->peers[i].valid &&
		    rpl_addr_eq(coord->peers[i].iid, info->iid)) {
			/* Update existing peer */
			memcpy(&coord->peers[i], info, sizeof(*info));
			coord->peers[i].valid = true;
			return 0;
		}
	}

	/* Find free slot */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS; i++) {
		if (!coord->peers[i].valid) {
			memcpy(&coord->peers[i], info, sizeof(*info));
			coord->peers[i].valid = true;
			coord->peer_count++;
			return 0;
		}
	}

	return -ENOMEM;
}

int lichen_rpl_coordinator_remove_peer(
	struct lichen_rpl_multi_root_coordinator *coord,
	const uint8_t *iid)
{
	if (coord == NULL || iid == NULL) {
		return -EINVAL;
	}

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS; i++) {
		if (coord->peers[i].valid &&
		    rpl_addr_eq(coord->peers[i].iid, iid)) {
			coord->peers[i].valid = false;
			coord->peer_count--;
			return 0;
		}
	}

	return -ENOENT;
}

const struct lichen_rpl_gateway_info *lichen_rpl_coordinator_get_peer(
	const struct lichen_rpl_multi_root_coordinator *coord,
	const uint8_t *iid)
{
	if (coord == NULL || iid == NULL) {
		return NULL;
	}

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS; i++) {
		if (coord->peers[i].valid &&
		    rpl_addr_eq(coord->peers[i].iid, iid)) {
			return &coord->peers[i];
		}
	}

	return NULL;
}

/* ── Time master election ──────────────────────────────────────────────────── */

int lichen_rpl_iid_compare(const uint8_t *a, const uint8_t *b)
{
	/* Compare packed bytes for deterministic ordering */
	int cmp = memcmp(a, b, 16);
	if (cmp < 0) {
		return -1;
	} else if (cmp > 0) {
		return 1;
	}
	return 0;
}

int lichen_rpl_coordinator_elect_time_master(
	const struct lichen_rpl_multi_root_coordinator *coord,
	uint8_t *master_iid)
{
	if (coord == NULL || master_iid == NULL) {
		return -EINVAL;
	}

	const uint8_t *lowest = NULL;

	/* Include local gateway in election */
	if (coord->has_local_gateway) {
		lowest = coord->local_gateway.iid;
	}

	/* Find lowest IID among peers */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS; i++) {
		if (coord->peers[i].valid) {
			if (lowest == NULL ||
			    lichen_rpl_iid_compare(coord->peers[i].iid, lowest) < 0) {
				lowest = coord->peers[i].iid;
			}
		}
	}

	if (lowest == NULL) {
		return -ENOENT;
	}

	memcpy(master_iid, lowest, 16);
	return 0;
}

enum lichen_rpl_gateway_role lichen_rpl_coordinator_get_role(
	const struct lichen_rpl_multi_root_coordinator *coord)
{
	if (coord == NULL) {
		return LICHEN_RPL_ROLE_STANDALONE;
	}

	if (!coord->has_local_gateway) {
		return LICHEN_RPL_ROLE_STANDALONE;
	}

	/* No peers = standalone */
	if (coord->peer_count == 0) {
		return LICHEN_RPL_ROLE_STANDALONE;
	}

	/* Elect time master and check if local is master */
	uint8_t master_iid[16];
	if (lichen_rpl_coordinator_elect_time_master(coord, master_iid) != 0) {
		return LICHEN_RPL_ROLE_STANDALONE;
	}

	if (rpl_addr_eq(coord->local_gateway.iid, master_iid)) {
		return LICHEN_RPL_ROLE_PRIMARY;
	}

	return LICHEN_RPL_ROLE_SECONDARY;
}

/* ── DODAG version management ──────────────────────────────────────────────── */

uint8_t lichen_rpl_coordinator_increment_version(
	struct lichen_rpl_multi_root_coordinator *coord)
{
	if (coord == NULL) {
		return 0;
	}

	/* Lollipop semantics per RFC 6550 Section 7.2:
	 * Linear region: 0-127 (increment normally, wrap 127->0)
	 * Circular region: 128-255 (increment with wrap 255->0)
	 */
	coord->dodag_version = (coord->dodag_version + 1) % 256;
	return coord->dodag_version;
}

/* ── DIO validation ────────────────────────────────────────────────────────── */

int lichen_rpl_coordinator_validate_dio(
	const struct lichen_rpl_multi_root_coordinator *coord,
	uint8_t dio_instance_id,
	uint16_t dio_rank)
{
	if (coord == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Per GCP-5, all cooperating gateways MUST use the same
	 * RPLInstanceID. Reject DIOs with mismatched instance ID to prevent
	 * rogue gateways from disrupting the federation. */
	if (dio_instance_id != coord->rpl_instance_id) {
		return -EINVAL;
	}

	/* Peer gateway DIOs must have root rank (256) */
	if (dio_rank != LICHEN_RPL_ROOT_RANK_VALUE) {
		return -EPROTO;
	}

	return 0;
}

/* ── Slot conflict resolution ──────────────────────────────────────────────── */

void lichen_rpl_resolve_slot_conflict(
	const uint8_t *claimant_a,
	const uint8_t *claimant_b,
	uint8_t *winner_iid)
{
	if (claimant_a == NULL || claimant_b == NULL || winner_iid == NULL) {
		return;
	}

	/* Per GCP-6.3: lowest IID MUST win */
	if (lichen_rpl_iid_compare(claimant_a, claimant_b) <= 0) {
		memcpy(winner_iid, claimant_a, 16);
	} else {
		memcpy(winner_iid, claimant_b, 16);
	}
}
