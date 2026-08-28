/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_dao_build.c
 * @brief DAO Manager initialization and DAO message building
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#ifdef LICHEN_RPL_TEST
#include <stdbool.h>
#include <stdint.h>

/* Host tests provide lichen/tests/include/zephyr/kernel.h, a minimal stub
 * that satisfies the header's struct k_mutex member, so the real enum
 * declaration in rpl_routing.h is the single source of truth. */
#include <lichen/rpl_routing.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>
#include "rpl_internal.h"

#endif

/**
 * RFC 6550 Section 7.2 lollipop comparison for DAOSequence / Path Sequence.
 *
 * Duplicated from dodag.c (do not share that file's private static).
 *
 * Region layout per RFC 6550 Section 7.2: values in [128..255] are the
 * linear region (restart/bootstrap); values in [0..127] are the circular
 * region, a 128-value serial number space per RFC 1982.
 * SEQUENCE_WINDOW = 16.
 *
 * Mirrors rust/lichen-rpl/src/routing.rs seq_is_newer():
 * - Same region: RFC 1982 serial arithmetic on the low 7 bits; the counter
 *   is newer iff the wrapped difference is in [1..SEQUENCE_WINDOW]. This
 *   accepts multi-step crossings of the 127->0 restart (e.g. 5 after 120)
 *   exactly as the Rust reference does.
 * - new linear, old circular: newer iff more than SEQUENCE_WINDOW steps
 *   past the 255->0 wrap, i.e. (256 + old - new) > SEQUENCE_WINDOW.
 * - new circular, old linear: newer iff within SEQUENCE_WINDOW steps of
 *   the 255->0 wrap, i.e. (256 + new - old) <= SEQUENCE_WINDOW.
 *
 * Exhaustive cross-check against the Rust semantics:
 * lichen/tests/rpl_dao_sequence/sweep.c + golden_lollipop_sweep.txt.
 */
#define LOLLIPOP_LINEAR_BASE	 128
#define LOLLIPOP_SEQUENCE_WINDOW 16

static bool dao_seq_is_newer(uint8_t new_seq, uint8_t old_seq)
{
	bool new_linear = new_seq >= LOLLIPOP_LINEAR_BASE;
	bool old_linear = old_seq >= LOLLIPOP_LINEAR_BASE;
	uint8_t diff;

	if (new_linear == old_linear) {
		/* RFC 1982 serial arithmetic inside one region (mod 128). */
		diff = (uint8_t)((uint8_t)(new_seq - old_seq) & 0x7Fu);
		return diff != 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW;
	}
	if (new_linear) {
		/* New past the 255->0 wrap by more than SEQUENCE_WINDOW. */
		return (256u + old_seq - new_seq) > LOLLIPOP_SEQUENCE_WINDOW;
	}
	/* New within SEQUENCE_WINDOW steps of the 255->0 wrap. */
	return (256u + new_seq - old_seq) <= LOLLIPOP_SEQUENCE_WINDOW;
}

enum lichen_rpl_sequence_relation lichen_rpl_sequence_compare(uint8_t incoming, uint8_t current) /* NOLINT(misc-use-internal-linkage) */
{
	if (incoming == current) {
		return LICHEN_RPL_SEQUENCE_EQUAL;
	}
	if (dao_seq_is_newer(incoming, current)) {
		return LICHEN_RPL_SEQUENCE_NEWER;
	}
	if (dao_seq_is_newer(current, incoming)) {
		return LICHEN_RPL_SEQUENCE_STALE;
	}
	return LICHEN_RPL_SEQUENCE_INCOMPARABLE;
}

#undef LOLLIPOP_LINEAR_BASE
#undef LOLLIPOP_SEQUENCE_WINDOW

#ifndef LICHEN_RPL_TEST

int lichen_rpl_dao_manager_init(struct lichen_rpl_dao_manager *dm,
				const uint8_t *node_address,
				uint8_t rpl_instance_id,
				const uint8_t *dodag_id)
{
	if (dm == NULL || node_address == NULL || dodag_id == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	memset(dm, 0, sizeof(*dm));
	k_mutex_init(&dm->lock);
	rpl_addr_copy(dm->node_address, node_address);
	dm->rpl_instance_id = rpl_instance_id;
	rpl_addr_copy(dm->dodag_id, dodag_id);
	dm->is_root = false;
	dm->dao_sequence = 240;
	dm->path_sequence = 240;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_init_root(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *node_address,
				     uint8_t rpl_instance_id,
				     const uint8_t *dodag_id)
{
	int ret = lichen_rpl_dao_manager_init(dm, node_address, rpl_instance_id, dodag_id);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	dm->is_root = true;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_bind_root_state(
	struct lichen_rpl_dao_manager *dm,
	struct lichen_rpl_dao_root_state *root_state)
{
	if (dm == NULL || root_state == NULL || !dm->is_root) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	memset(root_state, 0, sizeof(*root_state));
	dm->root_state = root_state;
	k_mutex_unlock(&dm->lock);
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_lookup(struct lichen_rpl_dao_manager *dm,
				  const uint8_t *target,
				  struct lichen_rpl_route *route)
{
	if (dm == NULL || target == NULL || route == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	if (!dm->is_root || dm->root_state == NULL) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_INVALID;
	}
	const struct lichen_rpl_route *found =
		lichen_rpl_routing_table_lookup(&dm->root_state->routing_table, target);
	if (found == NULL) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_NOT_FOUND;
	}
	*route = *found;
	k_mutex_unlock(&dm->lock);
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_route_count(struct lichen_rpl_dao_manager *dm)
{
	if (dm == NULL) {
		return 0;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	int count = !dm->is_root || dm->root_state == NULL ? 0 :
		lichen_rpl_routing_table_count(&dm->root_state->routing_table);
	k_mutex_unlock(&dm->lock);
	return count;
}

static int build_dao(struct lichen_rpl_dao_manager *dm,
		     const uint8_t *parent_addr, uint8_t path_lifetime,
		     uint8_t dao_sequence, uint8_t path_sequence,
		     uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_LEAF_DAO_LEN) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}
	uint8_t encoded[LICHEN_RPL_LEAF_DAO_LEN];

	struct lichen_rpl_dao dao = {
		.rpl_instance_id = dm->rpl_instance_id,
		.ack_requested = false,
		.has_dodag_id = true,
		.flags = 0,
		.dao_sequence = dao_sequence,
	};
	rpl_addr_copy(dao.dodag_id, dm->dodag_id);

	int pos = lichen_rpl_dao_write(&dao, encoded, sizeof(encoded));
	if (pos < 0) {
		return pos;
	}

	/* RPL Target option: advertise self */
	struct lichen_rpl_target target = {
		.prefix_len = 128,
	};
	rpl_addr_copy(target.prefix, dm->node_address);

	int n = lichen_rpl_target_write(&target, &encoded[pos], sizeof(encoded) - (size_t)pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	/* Transit Info option: via parent */
	struct lichen_rpl_transit_info transit = {
		.path_control = 0x80,
		.path_sequence = path_sequence,
		.path_lifetime = path_lifetime,
	};
	rpl_addr_copy(transit.parent_address, parent_addr);

	n = lichen_rpl_transit_info_write(&transit, &encoded[pos],
					  sizeof(encoded) - (size_t)pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	if ((size_t)pos != sizeof(encoded)) {
		return LICHEN_RPL_ERR_INVALID;
	}
	memcpy(buf, encoded, sizeof(encoded));
	return pos;
}

/*
 * Snapshot, serialize, and advance the sequence counters while holding the
 * manager lock. Two concurrent builders must never both observe and consume
 * the same DAOSequence/PathSequence value; a lost increment would reuse a
 * sequence number across transmissions and degrade DAO<->ACK correlation
 * (RFC 6550 Section 7.1).
 */
static int build_dao_mut(struct lichen_rpl_dao_manager *dm,
			 const uint8_t *parent_addr, uint8_t path_lifetime,
			 uint8_t *buf, size_t len)
{
	int ret;

	k_mutex_lock(&dm->lock, K_FOREVER);

	uint8_t dao_sequence = increment_lollipop(dm->dao_sequence);
	uint8_t path_sequence = increment_lollipop(dm->path_sequence);
	ret = build_dao(dm, parent_addr, path_lifetime, dao_sequence,
			path_sequence, buf, len);
	if (ret > 0) {
		dm->dao_sequence = dao_sequence;
		dm->path_sequence = path_sequence;
		rpl_addr_copy(dm->last_dao_parent, parent_addr);
		dm->last_dao_lifetime = path_lifetime;
		dm->last_dao_path_sequence = path_sequence;
		dm->has_last_dao_update = true;
	}

	k_mutex_unlock(&dm->lock);
	return ret;
}

int lichen_rpl_dao_manager_build_dao(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *parent_addr,
				     uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	return build_dao_mut(dm, parent_addr, 255, buf, len);
}

int lichen_rpl_dao_manager_build_dao_with_lifetime(struct lichen_rpl_dao_manager *dm,
						   const uint8_t *parent_addr,
						   uint8_t path_lifetime,
						   uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	return build_dao_mut(dm, parent_addr, path_lifetime, buf, len);
}

int lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
	struct lichen_rpl_dao_manager *dm,
	const uint8_t *parent_addr,
	uint8_t path_lifetime,
	uint8_t *buf, size_t len)
{
	int ret;

	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	if (!dm->has_last_dao_update ||
	    !rpl_addr_eq(dm->last_dao_parent, parent_addr) ||
	    dm->last_dao_lifetime != path_lifetime ||
	    dm->last_dao_path_sequence != dm->path_sequence) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_INVALID;
	}

	/* Build without advancing path_sequence, only dao_sequence. Same
	 * lock-held snapshot+advance discipline as build_dao_mut(). */
	uint8_t dao_sequence = increment_lollipop(dm->dao_sequence);
	ret = build_dao(dm, parent_addr, path_lifetime, dao_sequence,
			dm->path_sequence, buf, len);
	if (ret > 0) {
		dm->dao_sequence = dao_sequence;
	}
	k_mutex_unlock(&dm->lock);
	return ret;
}

int lichen_rpl_dao_manager_build_dao_ack(struct lichen_rpl_dao_manager *dm,
				     uint8_t dao_sequence, uint8_t status,
				     uint8_t *buf, size_t len)
{
	if (dm == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 20) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	struct lichen_rpl_dao_ack ack = {
		.rpl_instance_id = dm->rpl_instance_id,
		.flags = 0,
		.dao_sequence = dao_sequence,
		.status = status,
		.has_dodag_id = true,
	};
	rpl_addr_copy(ack.dodag_id, dm->dodag_id);

	return lichen_rpl_dao_ack_write(&ack, buf, len);
}

#endif /* LICHEN_RPL_TEST */
