/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/rpl_routing.h>

#include "rpl_route_state_vectors.h"

BUILD_ASSERT(RPL_ROUTE_VECTOR_TARGET_MAX == CONFIG_LICHEN_RPL_MAX_ROUTES);
BUILD_ASSERT(RPL_ROUTE_VECTOR_CANDIDATES_PER_TARGET_MAX ==
	     CONFIG_LICHEN_RPL_MAX_PARENTS);
BUILD_ASSERT(RPL_ROUTE_VECTOR_AGGREGATE_CANDIDATE_MAX ==
	     CONFIG_LICHEN_RPL_MAX_ACTIVE_DAO_CANDIDATES);

static struct lichen_rpl_dao_manager manager;
static struct lichen_rpl_dao_manager tx_manager;
static struct lichen_rpl_dao_root_state root_state;
static struct lichen_rpl_dao_root_state saved_root_state;
static uint8_t root[16];
static uint8_t dodag[16];

static void address(uint8_t out[16], uint8_t id)
{
	memset(out, 0, 16);
	out[0] = 0xfd;
	out[15] = id;
}

static size_t dao_begin(uint8_t *buf, uint8_t sequence)
{
	struct lichen_rpl_dao dao = {
		.rpl_instance_id = 1,
		.dao_sequence = sequence,
	};

	memcpy(dao.dodag_id, dodag, 16);
	int len = lichen_rpl_dao_write(&dao, buf, 512);
	zassert_true(len > 0, "DAO base write failed");
	return (size_t)len;
}

static void add_target(uint8_t *buf, size_t *len, uint8_t id)
{
	struct lichen_rpl_target target = { .prefix_len = 128 };

	address(target.prefix, id);
	int written = lichen_rpl_target_write(&target, &buf[*len], 512 - *len);
	zassert_true(written > 0, "target write failed");
	*len += (size_t)written;
}

static void add_overlong_target(uint8_t *buf, size_t *len, uint8_t id)
{
	size_t option_offset = *len;

	add_target(buf, len, id);
	buf[option_offset + 1]++;
	buf[(*len)++] = 0;
}

static void add_transit(uint8_t *buf, size_t *len, uint8_t parent,
			uint8_t control, uint8_t sequence, uint8_t lifetime)
{
	struct lichen_rpl_transit_info transit = {
		.path_control = control,
		.path_sequence = sequence,
		.path_lifetime = lifetime,
	};

	address(transit.parent_address, parent);
	int written = lichen_rpl_transit_info_write(&transit, &buf[*len], 512 - *len);
	zassert_true(written > 0, "transit write failed");
	*len += (size_t)written;
}

static void add_descriptor(uint8_t *buf, size_t *len, uint8_t data_len)
{
	buf[(*len)++] = LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR;
	buf[(*len)++] = data_len;
	for (uint8_t i = 0; i < data_len; i++) {
		buf[(*len)++] = i;
	}
}

static void dao_sequences(const uint8_t *wire, size_t len,
			  uint8_t *dao_sequence, uint8_t *path_sequence,
			  uint8_t *path_lifetime)
{
	struct lichen_rpl_dao dao;
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;

	zassert_equal(lichen_rpl_dao_parse(&dao, wire, len), LICHEN_RPL_OK,
		      "built DAO did not parse");
	*dao_sequence = dao.dao_sequence;
	lichen_rpl_opt_iter_init(&it, lichen_rpl_dao_options(wire, len),
				 lichen_rpl_dao_options_len_ex(wire, len));
	while (lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_TRANSIT_INFO) {
			struct lichen_rpl_transit_info transit;

			zassert_equal(lichen_rpl_transit_info_parse(&transit, opt.data,
							       opt.data_len),
				      LICHEN_RPL_OK, "built Transit did not parse");
			*path_sequence = transit.path_sequence;
			*path_lifetime = transit.path_lifetime;
			return;
		}
	}
	zassert_unreachable("built DAO has no Transit");
}

static const struct lichen_rpl_dao_snapshot *find_snapshot(
	const struct lichen_rpl_dao_manager *dm, const uint8_t target[16])
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (dm->root_state->snapshots[i].valid &&
		    memcmp(dm->root_state->snapshots[i].target, target, 16) == 0) {
			return &dm->root_state->snapshots[i];
		}
	}
	return NULL;
}

static bool lookup_route(struct lichen_rpl_dao_manager *dm,
			 const uint8_t target[16], struct lichen_rpl_route *route)
{
	return lichen_rpl_dao_manager_lookup(dm, target, route) == LICHEN_RPL_OK;
}

static bool install_one(uint8_t target, uint8_t parent, uint8_t path_sequence,
			uint8_t lifetime, uint32_t now)
{
	uint8_t dao[512];
	size_t len = dao_begin(dao, path_sequence);

	add_target(dao, &len, target);
	add_transit(dao, &len, parent, 0x40, path_sequence, lifetime);
	return lichen_rpl_dao_manager_process_dao(&manager, dao, len, now);
}

static enum lichen_rpl_dao_process_result process_one(
	uint8_t target, uint8_t parent, uint8_t path_sequence, uint32_t now)
{
	uint8_t dao[512];
	size_t len = dao_begin(dao, path_sequence);

	add_target(dao, &len, target);
	add_transit(dao, &len, parent, 0x40, path_sequence, 255);
	return lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, now, NULL, 0);
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	address(root, 1);
	address(dodag, 0x99);
	zassert_equal(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag),
		      LICHEN_RPL_OK, "root init failed");
	zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
		      LICHEN_RPL_OK, "root state bind failed");
}

ZTEST(rpl_routing, test_group_cartesian_and_path_control)
{
	uint8_t dao[512];
	uint8_t target2[16];
	uint8_t target3[16];
	size_t len;

	zassert_true(install_one(4, 1, 1, 255, 10), "parent route missing");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x10, 2, 20);
	add_transit(dao, &len, 4, 0x40, 2, 20);
	zassert_true(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 20),
		     "grouped DAO rejected");

	address(target2, 2);
	address(target3, 3);
	struct lichen_rpl_route route;
	zassert_true(lookup_route(&manager, target2, &route), "target 2 route missing");
	zassert_equal(route.path_len, 2, "preferred candidate not selected");
	zassert_equal(route.path[0][15], 4, "wrong preferred parent");
	zassert_true(lookup_route(&manager, target3, &route),
		     "Cartesian target route missing");

	int snapshots = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (root_state.snapshots[i].valid && root_state.snapshots[i].target[15] >= 2 &&
		    root_state.snapshots[i].target[15] <= 3) {
			zassert_equal(root_state.snapshots[i].candidate_count, 2,
				      "candidate snapshot incomplete");
			snapshots++;
		}
	}
	zassert_equal(snapshots, 2, "group targets not retained");
}

ZTEST(rpl_routing, test_tx_path_sequence_and_explicit_copy)
{
	uint8_t wire[64];
	uint8_t parent[16];
	uint8_t dao_sequence;
	uint8_t path_sequence;
	uint8_t lifetime = 0;
	int len;

	address(parent, 1);
	zassert_equal(lichen_rpl_dao_manager_init(&tx_manager, root, 1, dodag),
		      LICHEN_RPL_OK, "TX manager init failed");
	for (size_t i = 0; i < RPL_ROUTE_TX_SEQUENCE_TRANSITION_COUNT; i++) {
		const struct rpl_route_tx_sequence_transition *transition =
			&rpl_route_tx_sequence_transitions[i];

		if (transition->advance_path_sequence) {
			len = lichen_rpl_dao_manager_build_dao_with_lifetime(
				&tx_manager, parent, transition->path_lifetime, wire, sizeof(wire));
		} else {
			len = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
				&tx_manager, parent, lifetime, wire, sizeof(wire));
		}
		zassert_true(len > 0, "%s: DAO build failed", transition->name);
		dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
		zassert_equal(dao_sequence, transition->expected_dao_sequence,
			      "%s: DAOSequence", transition->name);
		zassert_equal(path_sequence, transition->expected_path_sequence,
			      "%s: Path Sequence", transition->name);
		zassert_equal(lifetime, transition->advance_path_sequence ?
			      transition->path_lifetime : 255,
			      "%s: Path Lifetime", transition->name);
		zassert_equal(wire[43], 0x80, "%s: non-canonical Path Control",
			      transition->name);
	}

	tx_manager.path_sequence = 255;
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(path_sequence, 0, "circular Path Sequence did not wrap");
	tx_manager.path_sequence = 127;
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(path_sequence, 0, "linear Path Sequence did not wrap");

	tx_manager.dao_sequence = 126;
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(dao_sequence, 127, "DAOSequence skipped 127");
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(dao_sequence, 0, "DAOSequence did not wrap 127 to 0");
	tx_manager.dao_sequence = 254;
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(dao_sequence, 255, "DAOSequence skipped 255");
	len = lichen_rpl_dao_manager_build_dao(&tx_manager, parent, wire, sizeof(wire));
	dao_sequences(wire, (size_t)len, &dao_sequence, &path_sequence, &lifetime);
	zassert_equal(dao_sequence, 0, "DAOSequence did not wrap 255 to 0");
}

ZTEST(rpl_routing, test_tx_copy_requires_exact_successful_update)
{
	uint8_t wire[64];
	uint8_t parent[16];
	uint8_t other_parent[16];
	uint8_t dao_sequence;
	uint8_t path_sequence;
	int ret;

	address(parent, 1);
	address(other_parent, 2);
	zassert_equal(lichen_rpl_dao_manager_init(&tx_manager, root, 1, dodag),
		      LICHEN_RPL_OK, "TX manager init failed");
	dao_sequence = tx_manager.dao_sequence;
	path_sequence = tx_manager.path_sequence;
	ret = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
		&tx_manager, parent, 10, wire, sizeof(wire));
	zassert_equal(ret, LICHEN_RPL_ERR_INVALID, "copy without update accepted");
	zassert_equal(tx_manager.dao_sequence, dao_sequence, "no-prior copy changed DAOSequence");
	zassert_equal(tx_manager.path_sequence, path_sequence, "no-prior copy changed Path Sequence");

	ret = lichen_rpl_dao_manager_build_dao_with_lifetime(
		&tx_manager, parent, 10, wire, sizeof(wire));
	zassert_true(ret > 0, "initial logical update failed");
	dao_sequence = tx_manager.dao_sequence;
	path_sequence = tx_manager.path_sequence;
	ret = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
		&tx_manager, other_parent, 10, wire, sizeof(wire));
	zassert_equal(ret, LICHEN_RPL_ERR_INVALID, "parent mismatch accepted");
	zassert_equal(tx_manager.dao_sequence, dao_sequence, "parent mismatch changed DAOSequence");
	zassert_equal(tx_manager.path_sequence, path_sequence, "parent mismatch changed Path Sequence");
	ret = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
		&tx_manager, parent, 11, wire, sizeof(wire));
	zassert_equal(ret, LICHEN_RPL_ERR_INVALID, "lifetime mismatch accepted");
	zassert_equal(tx_manager.dao_sequence, dao_sequence, "lifetime mismatch changed DAOSequence");
	zassert_equal(tx_manager.path_sequence, path_sequence, "lifetime mismatch changed Path Sequence");
	tx_manager.path_sequence++;
	ret = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
		&tx_manager, parent, 10, wire, sizeof(wire));
	zassert_equal(ret, LICHEN_RPL_ERR_INVALID, "Path Sequence mismatch accepted");
	zassert_equal(tx_manager.dao_sequence, dao_sequence,
		      "Path Sequence mismatch changed DAOSequence");
	tx_manager.path_sequence = path_sequence;

	ret = lichen_rpl_dao_manager_build_dao_with_lifetime(
		&tx_manager, other_parent, 11, wire, sizeof(wire) - 1);
	zassert_equal(ret, LICHEN_RPL_ERR_BUF_SMALL, "short logical update accepted");
	zassert_equal(tx_manager.dao_sequence, dao_sequence, "failed update changed DAOSequence");
	zassert_equal(tx_manager.path_sequence, path_sequence, "failed update changed Path Sequence");
	ret = lichen_rpl_dao_manager_build_dao_copy_with_lifetime(
		&tx_manager, parent, 10, wire, sizeof(wire));
	zassert_true(ret > 0, "failed update replaced successful cache");
	zassert_equal(tx_manager.dao_sequence, dao_sequence + 1,
		      "exact copy did not advance DAOSequence");
	zassert_equal(tx_manager.path_sequence, path_sequence,
		      "exact copy advanced Path Sequence");
}

ZTEST(rpl_routing, test_route_hop_boundaries)
{
	struct lichen_rpl_routing_table table;

	zassert_equal(RPL_ROUTE_ORACLE_MAX_HOPS, LICHEN_RPL_MAX_HOPS,
		      "oracle max_route_hops differs from production");
	for (size_t i = 0; i < RPL_ROUTE_HOP_BOUNDARY_COUNT; i++) {
		const struct rpl_route_hop_boundary *boundary = &rpl_route_hop_boundaries[i];
		const uint8_t *target = boundary->path[boundary->path_len - 1];

		lichen_rpl_routing_table_init(&table);
		int result = lichen_rpl_routing_table_add(
			&table, target, boundary->path, boundary->path_len);
		const struct lichen_rpl_route *route =
			lichen_rpl_routing_table_lookup(&table, target);

		zassert_equal(result == LICHEN_RPL_OK, boundary->accepted,
			      "%s: acceptance", boundary->name);
		zassert_equal(route != NULL, boundary->accepted,
			      "%s: lookup", boundary->name);
		zassert_equal(lichen_rpl_routing_table_count(&table),
			      boundary->accepted ? 1 : 0, "%s: route count", boundary->name);
		if (boundary->accepted) {
			zassert_equal(route->path_len, boundary->path_len,
				      "%s: path length", boundary->name);
			zassert_mem_equal(route->path, boundary->path,
					  boundary->path_len * sizeof(boundary->path[0]),
					  "%s: path", boundary->name);
		}
	}
}

ZTEST(rpl_routing, test_root_requires_bound_state)
{
	uint8_t dao[512];
	size_t len;

	zassert_equal(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag),
		      LICHEN_RPL_OK, "unbound root init failed");
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "unbound root processed DAO");
	uint8_t target[16];
	struct lichen_rpl_route route;
	address(target, 2);
	zassert_false(lookup_route(&manager, target, &route), "unbound root lookup succeeded");
	zassert_equal(lichen_rpl_dao_manager_route_count(&manager), 0,
		      "unbound root route count succeeded");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 10, 60), 0,
		      "unbound root expiry mutated state");
	zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
		      LICHEN_RPL_OK, "root state bind failed");
	zassert_true(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 1),
		     "bound root rejected DAO");
}

ZTEST(rpl_routing, test_child_before_parent_rebuilds_route)
{
	uint8_t child[16];
	struct lichen_rpl_route route;

	zassert_equal(process_one(3, 2, 1, 1), LICHEN_RPL_DAO_APPLIED,
		      "child state was not retained");
	address(child, 3);
	zassert_false(lookup_route(&manager, child, &route), "child route exists before parent");
	zassert_equal(process_one(2, 1, 1, 2), LICHEN_RPL_DAO_APPLIED,
		      "parent install failed");
	zassert_true(lookup_route(&manager, child, &route),
		     "child route not rebuilt after parent");
	zassert_equal(route.path_len, 2, "rebuilt child path length");
	zassert_equal(route.path[0][15], 2, "rebuilt child parent");
	zassert_equal(route.path[1][15], 3, "rebuilt child target");
}

ZTEST(rpl_routing, test_canonical_sequence_relations)
{
	for (size_t i = 0; i < RPL_ROUTE_SEQUENCE_RELATION_COUNT; i++) {
		const struct rpl_route_sequence_relation *relation =
			&rpl_route_sequence_relations[i];

		zassert_equal(lichen_rpl_sequence_compare(relation->incoming,
						  relation->current),
			      relation->expected, "%s: comparator", relation->name);
		zassert_equal(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag),
			      LICHEN_RPL_OK, "%s: root init", relation->name);
		zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
			      LICHEN_RPL_OK, "%s: root state bind", relation->name);
		zassert_equal(process_one(2, 1, relation->current, 1),
			      LICHEN_RPL_DAO_APPLIED, "%s: current install", relation->name);
		enum lichen_rpl_dao_process_result result =
			process_one(2, 1, relation->incoming, 2);
		enum lichen_rpl_dao_process_result expected =
			relation->expected == LICHEN_RPL_SEQUENCE_EQUAL ?
				LICHEN_RPL_DAO_IDEMPOTENT :
			relation->expected == LICHEN_RPL_SEQUENCE_NEWER ?
				LICHEN_RPL_DAO_APPLIED : LICHEN_RPL_DAO_REJECTED;

		zassert_equal(result, expected, "%s: transition", relation->name);
	}
}

ZTEST(rpl_routing, test_routing_table_expiry_boundaries)
{
	uint8_t target[16];
	uint8_t path[1][16];
	struct lichen_rpl_routing_table table;
	struct lichen_rpl_routing_table saved_table;

	address(target, 2);
	address(path[0], 2);
	lichen_rpl_routing_table_init(&table);
	zassert_equal(lichen_rpl_routing_table_add(&table, target, path, 1),
		      LICHEN_RPL_OK, "routing table setup failed");
	table.routes[0].path_lifetime = 2;
	table.routes[0].last_updated = 100;
	saved_table = table;
	zassert_equal(lichen_rpl_routing_table_expire(&table, 200, 0),
		      LICHEN_RPL_ERR_INVALID, "zero route duration accepted");
	zassert_mem_equal(&table, &saved_table, sizeof(table),
			  "zero route duration mutated table");
	zassert_equal(lichen_rpl_routing_table_expire(&table, 200, INT32_MAX),
		      LICHEN_RPL_ERR_INVALID, "oversized route duration accepted");
	zassert_mem_equal(&table, &saved_table, sizeof(table),
			  "oversized route duration mutated table");

	table.routes[0].path_lifetime = 1;
	table.routes[0].last_updated = 100;
	zassert_equal(lichen_rpl_routing_table_expire(&table, 99, 10), 0,
		      "table route expired before installation");
	zassert_equal(lichen_rpl_routing_table_expire(&table, 109, 10), 0,
		      "table route expired before deadline");
	zassert_equal(lichen_rpl_routing_table_expire(&table, 110, 10), 1,
		      "table route missed exact deadline");

	lichen_rpl_routing_table_init(&table);
	zassert_equal(lichen_rpl_routing_table_add(&table, target, path, 1),
		      LICHEN_RPL_OK, "wrapping routing table setup failed");
	table.routes[0].path_lifetime = 1;
	table.routes[0].last_updated = UINT32_MAX - 5U;
	zassert_equal(lichen_rpl_routing_table_expire(&table, UINT32_MAX - 6U, 10), 0,
		      "wrapping table route expired before installation");
	zassert_equal(lichen_rpl_routing_table_expire(&table, 3, 10), 0,
		      "wrapping table route expired early");
	zassert_equal(lichen_rpl_routing_table_expire(&table, 4, 10), 1,
		      "wrapping table route missed exact deadline");
}

ZTEST(rpl_routing, test_dao_manager_expiry_boundaries)
{
	uint8_t target[16];
	struct lichen_rpl_route route;

	zassert_true(install_one(2, 1, 1, 2, 100), "finite route missing");
	saved_root_state = root_state;
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 200, 0),
		      LICHEN_RPL_ERR_INVALID, "zero manager duration accepted");
	zassert_mem_equal(&root_state, &saved_root_state, sizeof(root_state),
			  "zero manager duration mutated state");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 200, INT32_MAX),
		      LICHEN_RPL_ERR_INVALID, "oversized manager duration accepted");
	zassert_mem_equal(&root_state, &saved_root_state, sizeof(root_state),
			  "oversized manager duration mutated state");

	zassert_equal(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag),
		      LICHEN_RPL_OK, "root reinit failed");
	zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
		      LICHEN_RPL_OK, "root state rebind failed");
	zassert_true(install_one(2, 1, 1, 1, 100), "deadline route missing");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 99, 10), 0,
		      "route expired before installation");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 109, 10), 0,
		      "route expired before deadline");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 110, 10), 1,
		      "route did not expire at deadline");

	zassert_equal(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag),
		      LICHEN_RPL_OK, "root reinit failed");
	zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
		      LICHEN_RPL_OK, "root state rebind failed");
	zassert_true(install_one(2, 1, 1, 1, UINT32_MAX - 5U), "wrap route missing");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, UINT32_MAX - 6U, 10), 0,
		      "wrapping route expired before installation");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 3, 10), 0,
		      "wrapping route expired early");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 4, 10), 1,
		      "wrapping route missed exact deadline");
	address(target, 2);
	zassert_false(lookup_route(&manager, target, &route), "wrapping expired route remains");
}

ZTEST(rpl_routing, test_descriptor_grammar)
{
	uint8_t dao[512];
	size_t len;

	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_descriptor(dao, &len, 4);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_true(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 1),
		     "valid descriptor rejected");
	uint8_t target2[16];
	address(target2, 2);
	const struct lichen_rpl_dao_snapshot *snapshot = find_snapshot(&manager, target2);
	zassert_true(snapshot->has_descriptor, "descriptor not retained");
	zassert_equal(snapshot->descriptor, 0x00010203U, "descriptor value changed");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_descriptor(dao, &len, 4);
	dao[len - 1] = 9;
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 2, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED,
		      "equal Path Sequence descriptor mutation was accepted");
	snapshot = find_snapshot(&manager, target2);
	zassert_equal(snapshot->descriptor, 0x00010203U,
		      "descriptor mutation changed snapshot");

	len = dao_begin(dao, 2);
	add_target(dao, &len, 3);
	add_descriptor(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 2, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "bad descriptor length accepted");

	len = dao_begin(dao, 3);
	add_target(dao, &len, 3);
	add_descriptor(dao, &len, 4);
	add_descriptor(dao, &len, 4);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 3, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "repeated descriptor accepted");

	len = dao_begin(dao, 4);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	add_descriptor(dao, &len, 4);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 4, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "post-Transit descriptor accepted");

	len = dao_begin(dao, 5);
	add_descriptor(dao, &len, 4);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 5, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "descriptor without Target accepted");
}

ZTEST(rpl_routing, test_dao_base_and_options_are_exact)
{
	uint8_t dao[512];
	size_t len = dao_begin(dao, 1);

	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	dao[1] |= 0x01;
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "reserved DAO flag accepted");
	dao[1] &= ~0x01;
	dao[2] = 1;
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "reserved DAO byte accepted");
	dao[2] = 0;

	memmove(&dao[22], &dao[20], len - 20);
	dao[20] = 0xee;
	dao[21] = 0;
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len + 2, 1, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "leading unsupported option accepted");
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	dao[len++] = 0xee;
	dao[len++] = 0;
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "trailing unsupported option accepted");
}

ZTEST(rpl_routing, test_path_control_same_subfield_and_validation)
{
	uint8_t dao[512];
	uint8_t target[16];
	struct lichen_rpl_route route;
	size_t len;

	zassert_true(install_one(2, 1, 1, 255, 1), "parent 2 missing");
	zassert_true(install_one(3, 1, 1, 255, 1), "parent 3 missing");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 4);
	add_transit(dao, &len, 3, 0x80, 1, 255);
	add_transit(dao, &len, 2, 0x40, 1, 255);
	zassert_true(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 2),
		     "same-subfield candidates rejected");
	address(target, 4);
	zassert_true(lookup_route(&manager, target, &route), "selected route missing");
	zassert_equal(route.path[0][15], 2, "same-subfield selection was numeric");

	len = dao_begin(dao, 3);
	add_target(dao, &len, 5);
	add_transit(dao, &len, 1, 0, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 3, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "empty Path Control accepted");
	len = dao_begin(dao, 4);
	add_target(dao, &len, 5);
	size_t transit_offset = len;
	add_transit(dao, &len, 1, 0x40, 1, 255);
	dao[transit_offset + 2] = 0x01;
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 4, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "reserved Transit flag accepted");
}

ZTEST(rpl_routing, test_equal_is_idempotent_without_refresh)
{
	uint8_t target[16];
	struct lichen_rpl_route route;

	zassert_true(install_one(2, 1, 10, 2, 100), "initial route missing");
	zassert_true(install_one(2, 1, 10, 2, 200), "equal copy rejected");
	address(target, 2);
	zassert_true(lookup_route(&manager, target, &route), "initial route missing");
	zassert_equal(route.last_updated, 100, "equal copy refreshed lifetime");

	zassert_false(install_one(2, 3, 10, 2, 210), "equal conflict accepted");
	zassert_true(lookup_route(&manager, target, &route), "conflict removed route");
	zassert_equal(route.path[0][15], 2, "conflict mutated route");
	zassert_false(install_one(2, 3, 9, 2, 220), "stale sequence accepted");
	zassert_true(install_one(2, 1, 11, 3, 230), "newer sequence rejected");
	zassert_true(lookup_route(&manager, target, &route), "replacement route missing");
	zassert_equal(route.last_updated, 230, "newer sequence did not replace snapshot");
}

ZTEST(rpl_routing, test_lollipop_withdrawal_expiry_and_tombstone)
{
	uint8_t target[16];
	struct lichen_rpl_route route;

	zassert_true(install_one(2, 1, 250, 1, 0), "initial lollipop route missing");
	zassert_true(install_one(2, 1, 0, 1, 1), "lollipop wrap rejected");
	zassert_false(install_one(2, 1, 100, 1, 2), "incomparable sequence accepted");
	zassert_equal(lichen_rpl_dao_manager_expire(&manager, 62, 60), 1,
		      "route did not expire");
	address(target, 2);
	zassert_false(lookup_route(&manager, target, &route), "expired route remains");
	zassert_false(install_one(2, 1, 0, 1, 70), "equal sequence revived expiry");
	zassert_false(install_one(2, 1, 1, 0, 80), "withdrawal installed route");
	zassert_false(install_one(2, 1, 1, 1, 90), "equal sequence changed tombstone");
	zassert_true(install_one(2, 1, 2, 1, 100), "newer sequence did not revive route");
}

ZTEST(rpl_routing, test_malformed_group_and_cycle_are_atomic)
{
	uint8_t dao[512];
	uint8_t target2[16];
	size_t len;

	zassert_true(install_one(2, 1, 1, 255, 10), "initial route missing");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 2, 20);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 15),
		      "duplicate target accepted");

	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 2, 20);
	add_transit(dao, &len, 3, 0x10, 3, 20);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 20),
		      "inconsistent group accepted");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 2, 20);
	size_t external_offset = len;
	add_transit(dao, &len, 3, 0x10, 2, 20);
	dao[external_offset + 2] = 0x80;
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 25),
		      "inconsistent E flag accepted");

	len = dao_begin(dao, 3);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 3, 0x40, 2, 20);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 2, 0x40, 1, 20);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 30),
		      "cycle accepted");
	address(target2, 2);
	struct lichen_rpl_route route;
	zassert_true(lookup_route(&manager, target2, &route),
		     "cycle rejection removed old route");
	zassert_equal(route.path_len, 1, "cycle rejection changed old route");
}

ZTEST(rpl_routing, test_overlong_target_is_atomic)
{
	uint8_t dao[512];
	uint8_t target2[16];
	struct lichen_rpl_route route;
	struct lichen_rpl_dao_snapshot saved_snapshot;
	size_t len;

	zassert_true(install_one(2, 1, 1, 255, 10), "initial route missing");
	address(target2, 2);
	saved_snapshot = *find_snapshot(&manager, target2);

	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 2, 20);
	add_overlong_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_equal(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 20, NULL, 0),
		      LICHEN_RPL_DAO_REJECTED, "overlong Target accepted");
	zassert_mem_equal(find_snapshot(&manager, target2), &saved_snapshot,
			  sizeof(saved_snapshot), "overlong Target partially updated snapshot");
	zassert_true(lookup_route(&manager, target2, &route),
		     "overlong Target rejection removed route");
	zassert_equal(route.last_updated, 10, "overlong Target partially refreshed route");
}

ZTEST(rpl_routing, test_candidate_conflict_and_capacity_are_atomic)
{
	uint8_t dao[512];
	uint8_t target2[16];
	size_t len;

	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	add_transit(dao, &len, 1, 0x10, 1, 255);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 1),
		      "conflicting duplicate candidate accepted");
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_true(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 1),
		     "identical duplicate candidate was not canonicalized");

	for (uint8_t id = 2; id < 2 + CONFIG_LICHEN_RPL_MAX_ROUTES; id++) {
		zassert_true(install_one(id, 1, 1, 255, id), "capacity setup failed");
	}
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 3, 0x40, 2, 255);
	add_target(dao, &len, 20);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 100),
		      "over-capacity transaction accepted");
	address(target2, 2);
	struct lichen_rpl_route route;
	zassert_true(lookup_route(&manager, target2, &route),
		     "capacity failure removed route");
	zassert_equal(route.path_len, 1, "capacity failure partially replaced route");

	zassert_false(install_one(2, 1, 2, 0, 110), "withdrawal installed route");
	len = dao_begin(dao, 3);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 3, 255);
	add_target(dao, &len, 20);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	zassert_false(lichen_rpl_dao_manager_process_dao(&manager, dao, len, 120),
		      "new target reused updated tombstone slot");
	zassert_false(lookup_route(&manager, target2, &route),
		      "failed transaction revived tombstone");
}

static void assert_vector_state(struct lichen_rpl_dao_manager *dm,
				const struct rpl_route_state_vector *vector)
{
	int target_count = 0;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (dm->root_state->snapshots[i].valid &&
		    dm->root_state->snapshots[i].target[0] != 0xfc) {
			target_count++;
		}
	}
	zassert_equal(target_count, vector->target_count, "%s: target count", vector->name);
	for (int i = 0; i < vector->target_count; i++) {
		const struct rpl_route_vector_target *expected = &vector->targets[i];
		const struct lichen_rpl_dao_snapshot *actual =
			find_snapshot(dm, expected->target);

		zassert_not_null(actual, "%s: target missing", vector->name);
		zassert_equal(actual->path_sequence, expected->path_sequence,
			      "%s: Path Sequence", vector->name);
		zassert_equal(actual->active,
			      expected->disposition == RPL_ROUTE_DISPOSITION_ACTIVE,
			      "%s: active flag", vector->name);
		zassert_equal(actual->disposition, expected->disposition,
			      "%s: disposition", vector->name);
		zassert_equal(actual->last_updated, expected->last_updated,
			      "%s: installed time", vector->name);
		zassert_equal(actual->retain_until, expected->retain_until,
			      "%s: retention", vector->name);
		zassert_equal(actual->has_descriptor, expected->has_descriptor,
			      "%s: descriptor presence", vector->name);
		zassert_equal(actual->descriptor, expected->descriptor,
			      "%s: descriptor value", vector->name);
		zassert_equal(actual->candidate_count, expected->candidate_count,
			      "%s: candidate count", vector->name);
		for (int j = 0; j < expected->candidate_count; j++) {
			zassert_mem_equal(actual->candidates[j].parent,
					  expected->candidates[j].parent, 16,
					  "%s: candidate parent", vector->name);
			zassert_equal(actual->candidates[j].path_control,
				      expected->candidates[j].path_control,
				      "%s: Path Control", vector->name);
			zassert_equal(actual->candidates[j].path_lifetime,
				      expected->candidates[j].path_lifetime,
				      "%s: Path Lifetime", vector->name);
			zassert_equal(actual->candidates[j].external,
				      expected->candidates[j].external,
				      "%s: E flag", vector->name);
			zassert_equal(actual->last_updated, expected->candidates[j].installed_at,
				      "%s: candidate installation", vector->name);
			bool has_expiry = actual->candidates[j].path_lifetime != 255 &&
					  actual->candidates[j].path_lifetime != 0;
			uint32_t expires_at = has_expiry ?
				actual->last_updated + actual->candidates[j].path_lifetime * 10U : 0;

			zassert_equal(has_expiry, expected->candidates[j].has_expiry,
				      "%s: candidate expiry presence", vector->name);
			zassert_equal(expires_at, expected->candidates[j].expires_at,
				      "%s: candidate expiry", vector->name);
		}
		struct lichen_rpl_route selected;
		bool selected_present = lookup_route(dm, expected->target, &selected);

		if (!expected->selected.present) {
			zassert_false(selected_present, "%s: unselected route present", vector->name);
		} else {
			zassert_true(selected_present, "%s: selected route absent", vector->name);
			zassert_equal(selected.path_len, expected->selected.path_len,
				      "%s: selected path length", vector->name);
			zassert_mem_equal(selected.path, expected->selected.path,
					  (size_t)selected.path_len * 16U,
					  "%s: selected path", vector->name);
			ptrdiff_t slot = actual - dm->root_state->snapshots;

			zassert_mem_equal(dm->root_state->parent_map[slot].parent,
					  expected->selected.parent, 16,
					  "%s: selected parent", vector->name);
			int selected_subfield = 0;
			const uint8_t masks[] = { 0xc0, 0x30, 0x0c, 0x03 };

			for (int j = 0; j < actual->candidate_count; j++) {
				if (memcmp(actual->candidates[j].parent,
					   expected->selected.parent, 16) != 0) {
					continue;
				}
				for (int k = 0; k < 4; k++) {
					if ((actual->candidates[j].path_control & masks[k]) != 0) {
						selected_subfield = k + 1;
						break;
					}
				}
			}
			zassert_equal(selected_subfield, expected->selected.preference_subfield,
				      "%s: selected subfield", vector->name);
		}
	}
	zassert_equal(lichen_rpl_dao_manager_route_count(dm), vector->route_count,
		      "%s: route count", vector->name);
	for (int i = 0; i < vector->route_count; i++) {
		const struct rpl_route_vector_route *expected = &vector->routes[i];
		struct lichen_rpl_route actual;

		zassert_true(lookup_route(dm, expected->target, &actual),
			     "%s: route missing", vector->name);
		zassert_equal(actual.path_len, expected->path_len,
			      "%s: route path length", vector->name);
		zassert_mem_equal(actual.path, expected->path,
				  expected->path_len * sizeof(expected->path[0]),
				  "%s: route path", vector->name);
		zassert_equal(actual.path_lifetime, expected->path_lifetime,
			      "%s: route lifetime", vector->name);
		zassert_equal(actual.last_updated, expected->installed_at,
			      "%s: route installation", vector->name);
		bool has_expiry = actual.path_lifetime != 255 && actual.path_lifetime != 0;
		uint32_t expires_at = has_expiry ?
			actual.last_updated + actual.path_lifetime * 10U : 0;

		zassert_equal(has_expiry, expected->has_expiry,
			      "%s: route expiry presence", vector->name);
		zassert_equal(expires_at, expected->expires_at,
			      "%s: route expiry", vector->name);
	}
}

ZTEST(rpl_routing, test_canonical_route_state_vectors)
{
	uint8_t vector_root[16] = {
		0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	};

	zassert_equal(lichen_rpl_dao_manager_init_root(&manager, vector_root, 0, vector_root),
		      LICHEN_RPL_OK, "vector root init failed");
	zassert_equal(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state),
		      LICHEN_RPL_OK, "vector root state bind failed");
	for (size_t i = 0; i < RPL_ROUTE_STATE_VECTOR_COUNT; i++) {
		const struct rpl_route_state_vector *vector = &rpl_route_state_vectors[i];
		bool accepted;
		bool changed;

		zassert_false(vector->refreshed, "%s: refreshed oracle (%s)",
			      vector->name, vector->reason);
		zassert_true(vector->reason[0] != '\0', "%s: empty oracle reason",
			     vector->name);

		if (vector->expire) {
			int expired = lichen_rpl_dao_manager_expire(&manager, vector->now, 10);

			accepted = true;
			changed = expired > 0;
		} else {
			enum lichen_rpl_dao_process_result result =
				lichen_rpl_dao_manager_process_dao_ex(
					&manager, vector->dao, vector->dao_len, vector->now,
					NULL, 0);

			accepted = result != LICHEN_RPL_DAO_REJECTED;
			changed = result == LICHEN_RPL_DAO_APPLIED;
		}
		zassert_equal(accepted, vector->accepted, "%s: acceptance (%s)",
			      vector->name, vector->reason);
		zassert_equal(changed, vector->changed, "%s: mutation (%s)",
			      vector->name, vector->reason);
		assert_vector_state(&manager, vector);
	}
}

ZTEST_SUITE(rpl_routing, NULL, NULL, before, NULL, NULL);
