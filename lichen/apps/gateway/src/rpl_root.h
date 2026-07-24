/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_RPL_ROOT_H_
#define LICHEN_GATEWAY_RPL_ROOT_H_

#include <stdint.h>
#include <stddef.h>
#include <lichen/rpl.h>

struct lichen_rpl_root;

int lichen_rpl_root_init(struct lichen_rpl_root *root, const uint8_t *dodag_id, const uint8_t *node_addr);
void lichen_rpl_root_tick(struct lichen_rpl_root *root, uint32_t now);
bool lichen_rpl_root_handle_dao(struct lichen_rpl_root *root, const uint8_t *data,
				size_t len, uint32_t now, bool authenticated);
const struct lichen_rpl_route *lichen_rpl_root_lookup(struct lichen_rpl_root *root, const uint8_t *target);
int lichen_rpl_root_set_prefix(struct lichen_rpl_root *root, const uint8_t *prefix, uint8_t len);

#endif
