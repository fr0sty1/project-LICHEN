/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_dao_build.c
 * @brief DAO Manager initialization and DAO message building
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>
#include "rpl_internal.h"

/* Need: DAO(20) + Target(20) + TransitInfo(22) = 62 bytes, pad to 64 */
#define LICHEN_RPL_DAO_MIN_BUF 64

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

enum lichen_rpl_sequence_relation lichen_rpl_sequence_compare(
	uint8_t incoming, uint8_t current)
{
	#define LOLLIPOP_CIRCULAR_BIT     128
	#define LOLLIPOP_SEQUENCE_WINDOW  16

	if (incoming == current) {
		return LICHEN_RPL_SEQUENCE_EQUAL;
	}

	if (incoming < LOLLIPOP_CIRCULAR_BIT && current < LOLLIPOP_CIRCULAR_BIT) {
		return incoming > current
			? LICHEN_RPL_SEQUENCE_NEWER
			: LICHEN_RPL_SEQUENCE_STALE;
	}

	if (incoming >= LOLLIPOP_CIRCULAR_BIT && current >= LOLLIPOP_CIRCULAR_BIT) {
		uint8_t diff = (uint8_t)((incoming - current) & 0x7F);
		if (diff > 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW) {
			return LICHEN_RPL_SEQUENCE_NEWER;
		}
		diff = (uint8_t)((current - incoming) & 0x7F);
		if (diff > 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW) {
			return LICHEN_RPL_SEQUENCE_STALE;
		}
		return LICHEN_RPL_SEQUENCE_INCOMPARABLE;
	}

	if (incoming < LOLLIPOP_CIRCULAR_BIT) {
		return LICHEN_RPL_SEQUENCE_NEWER;
	}
	return LICHEN_RPL_SEQUENCE_STALE;

	#undef LOLLIPOP_CIRCULAR_BIT
	#undef LOLLIPOP_SEQUENCE_WINDOW
}

static int build_dao(struct lichen_rpl_dao_manager *dm,
		     const uint8_t *parent_addr, uint8_t path_lifetime,
		     uint8_t dao_sequence, uint8_t path_sequence,
		     uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DAO_MIN_BUF) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	struct lichen_rpl_dao dao = {
		.rpl_instance_id = dm->rpl_instance_id,
		.ack_requested = true,
		.flags = 0,
		.dao_sequence = dao_sequence,
	};
	rpl_addr_copy(dao.dodag_id, dm->dodag_id);

	int pos = lichen_rpl_dao_write(&dao, buf, len);
	if (pos < 0) {
		return pos;
	}

	/* RPL Target option: advertise self */
	struct lichen_rpl_target target = {
		.prefix_len = 128,
	};
	rpl_addr_copy(target.prefix, dm->node_address);

	int n = lichen_rpl_target_write(&target, &buf[pos], len - pos);
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

	n = lichen_rpl_transit_info_write(&transit, &buf[pos], len - pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	return pos;
}

static int build_dao_mut(struct lichen_rpl_dao_manager *dm,
			 const uint8_t *parent_addr, uint8_t path_lifetime,
			 uint8_t dao_sequence, uint8_t path_sequence,
			 uint8_t *buf, size_t len)
{
	int ret = build_dao(dm, parent_addr, path_lifetime, dao_sequence,
			    path_sequence, buf, len);
	if (ret > 0) {
		dm->dao_sequence = increment_lollipop(dm->dao_sequence);
		dm->path_sequence = increment_lollipop(dm->path_sequence);
		rpl_addr_copy(dm->last_dao_parent, parent_addr);
		dm->last_dao_lifetime = path_lifetime;
		dm->has_last_dao_update = true;
	} else {
		dm->has_last_dao_update = false;
	}
	return ret;
}

int lichen_rpl_dao_manager_build_dao(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *parent_addr,
				     uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	uint8_t dao_seq = dm->dao_sequence;
	uint8_t path_seq = dm->path_sequence;
	uint8_t lifetime = 255;
	k_mutex_unlock(&dm->lock);
	return build_dao_mut(dm, parent_addr, lifetime, dao_seq, path_seq, buf, len);
}

int lichen_rpl_dao_manager_build_dao_with_lifetime(struct lichen_rpl_dao_manager *dm,
						   const uint8_t *parent_addr,
						   uint8_t path_lifetime,
						   uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (path_lifetime > 255) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	uint8_t dao_seq = dm->dao_sequence;
	uint8_t path_seq = dm->path_sequence;
	k_mutex_unlock(&dm->lock);
	return build_dao_mut(dm, parent_addr, path_lifetime, dao_seq, path_seq, buf, len);
}

int lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
	struct lichen_rpl_dao_manager *dm,
	const uint8_t *parent_addr,
	uint8_t path_lifetime,
	uint8_t *buf, size_t len)
{
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (path_lifetime > 255) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	if (!dm->has_last_dao_update ||
	    !rpl_addr_eq(dm->last_dao_parent, parent_addr) ||
	    dm->last_dao_lifetime != path_lifetime) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_INVALID;
	}
	uint8_t dao_seq = dm->dao_sequence;
	uint8_t path_seq = dm->path_sequence;
	k_mutex_unlock(&dm->lock);

	/* Build without advancing path_sequence, only dao_sequence */
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	int ret = build_dao(dm, parent_addr, path_lifetime, dao_seq, path_seq, buf, len);
	if (ret > 0) {
		dm->dao_sequence = increment_lollipop(dm->dao_sequence);
	}
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
	};
	rpl_addr_copy(ack.dodag_id, dm->dodag_id);

	return lichen_rpl_dao_ack_write(&ack, buf, len);
}
