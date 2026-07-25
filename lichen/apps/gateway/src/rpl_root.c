/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>
LOG_MODULE_REGISTER(lichen_rpl_root, LOG_LEVEL_INF);

struct lichen_rpl_root {
	struct lichen_rpl_dodag dodag;
	struct lichen_trickle trickle;
	struct lichen_rpl_dao_manager dao_manager;
	struct lichen_rpl_dao_root_state root_state;
	uint8_t prefix[16];
	uint8_t prefix_len;
};

int lichen_rpl_root_init(struct lichen_rpl_root *root, const uint8_t *dodag_id, const uint8_t *node_addr)
{
	if (root == NULL || dodag_id == NULL || node_addr == NULL) {
		return -EINVAL;
	}
	lichen_rpl_dodag_init_root(&root->dodag, 0, dodag_id, 0);
	lichen_rpl_dao_manager_init_root(&root->dao_manager, node_addr, 0, dodag_id);
	lichen_rpl_dao_manager_bind_root_state(&root->dao_manager, &root->root_state);
	lichen_trickle_init(&root->trickle, CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS,
			   CONFIG_LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS,
			   CONFIG_LICHEN_RPL_TRICKLE_K);
	lichen_trickle_start(&root->trickle, 0, 0);
	memcpy(root->prefix, dodag_id, 16);
	root->prefix_len = 128;
	return 0;
}

void lichen_rpl_root_tick(struct lichen_rpl_root *root, uint32_t now)
{
	struct lichen_trickle_event ev;
	lichen_trickle_next_event(&root->trickle, &ev);
	if (ev.type == LICHEN_TRICKLE_TRANSMIT) {
		lichen_trickle_fire_transmit(&root->trickle);
	} else if (ev.type == LICHEN_TRICKLE_EXPIRE) {
		lichen_trickle_expire(&root->trickle, now, 0);
	}
}

bool lichen_rpl_root_handle_dao(struct lichen_rpl_root *root, const uint8_t *data,
				size_t len, uint32_t now, bool authenticated)
{
	if (!authenticated) {
		return false;
	}
	return lichen_rpl_dao_manager_process_dao(&root->dao_manager, data, len, now);
}

const struct lichen_rpl_route *lichen_rpl_root_lookup(struct lichen_rpl_root *root, const uint8_t *target)
{
	if (root == NULL || target == NULL) {
		return NULL;
	}
	return lichen_rpl_routing_table_lookup(&root->root_state.routing_table, target);
}

int lichen_rpl_root_set_prefix(struct lichen_rpl_root *root, const uint8_t *prefix, uint8_t len)
{
	if (root == NULL || prefix == NULL || len > 128) return -EINVAL;
	memcpy(root->prefix, prefix, 16);
	root->prefix_len = len;
	if (len >= 64) {
		memcpy(root->dodag.dodag_id, prefix, 16);
		memcpy(root->dao_manager.dodag_id, prefix, 16);
	}
	return 0;
}
