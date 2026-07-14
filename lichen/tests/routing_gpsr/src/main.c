/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Tests for GPSR geographic forwarding (spec 9.7)
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <lichen/routing/router.h>
#include <lichen/routing/gradient.h>

/* Test helper: create a link-local address from IID byte */
static void make_link_local(uint8_t addr[16], uint8_t iid)
{
	memset(addr, 0, 16);
	addr[0] = 0xfe;
	addr[1] = 0x80;
	addr[15] = iid;
}

/* Test helper: create a ULA mesh address */
static void make_ula(uint8_t addr[16], uint8_t iid)
{
	memset(addr, 0, 16);
	addr[0] = 0xfd;
	addr[15] = iid;
}

/* Coordinates in e7 format */
#define LAT_SEATTLE   476062000   /* 47.6062 degrees */
#define LON_SEATTLE  -1223321000  /* -122.3321 degrees */
#define LAT_PORTLAND  455152000   /* 45.5152 degrees */
#define LON_PORTLAND -1226784000  /* -122.6784 degrees */

static struct lichen_router router;

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	uint8_t node_addr[16];
	make_ula(node_addr, 1);
	lichen_router_init(&router, node_addr);
}

ZTEST(routing_gpsr, test_gpsr_no_coords_returns_enoent)
{
	uint8_t next_hop[16];
	int ret;

	/* Router has no coords set */
	ret = lichen_router_gpsr_forward(&router, LAT_PORTLAND, LON_PORTLAND,
					 next_hop);
	zassert_equal(ret, -ENOENT, "should return -ENOENT without node coords");
}

ZTEST(routing_gpsr, test_gpsr_null_island_returns_einval)
{
	uint8_t next_hop[16];
	int ret;

	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Null island (0,0) is rejected as invalid GPS sentinel */
	ret = lichen_router_gpsr_forward(&router, 0, 0, next_hop);
	zassert_equal(ret, -EINVAL, "should reject null island");
}

ZTEST(routing_gpsr, test_gpsr_invalid_latitude_returns_einval)
{
	uint8_t next_hop[16];
	int ret;

	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Latitude > 90 degrees */
	ret = lichen_router_gpsr_forward(&router, 910000000, 0, next_hop);
	zassert_equal(ret, -EINVAL, "should reject lat > 90");

	/* Latitude < -90 degrees */
	ret = lichen_router_gpsr_forward(&router, -910000000, 0, next_hop);
	zassert_equal(ret, -EINVAL, "should reject lat < -90");
}

ZTEST(routing_gpsr, test_gpsr_invalid_longitude_returns_einval)
{
	uint8_t next_hop[16];
	int ret;

	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Longitude > 180 degrees */
	ret = lichen_router_gpsr_forward(&router, 0, 1810000000, next_hop);
	zassert_equal(ret, -EINVAL, "should reject lon > 180");

	/* Longitude < -180 degrees */
	ret = lichen_router_gpsr_forward(&router, 0, -1810000000, next_hop);
	zassert_equal(ret, -EINVAL, "should reject lon < -180");
}

ZTEST(routing_gpsr, test_gpsr_no_neighbors_returns_enoent)
{
	uint8_t next_hop[16];
	int ret;

	/* Set our coords but no neighbors with coords */
	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	ret = lichen_router_gpsr_forward(&router, LAT_PORTLAND, LON_PORTLAND,
					 next_hop);
	zassert_equal(ret, -ENOENT, "should return -ENOENT without neighbors");
}

ZTEST(routing_gpsr, test_gpsr_selects_closest_neighbor)
{
	uint8_t next_hop[16];
	uint8_t neighbor_a[16], neighbor_b[16];
	struct lichen_gradient_entry entry;
	int ret;

	/* Our position: Seattle */
	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Neighbor A: closer to Portland (about halfway) */
	make_link_local(neighbor_a, 0xa);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &neighbor_a[8], 8);
	memcpy(entry.next_hop, neighbor_a, 16);
	entry.lat_e7 = 465000000;  /* 46.5 degrees - between Seattle and Portland */
	entry.lon_e7 = -1225000000;
	entry.coords_valid = true;
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Neighbor B: further from Portland (north of Seattle) */
	make_link_local(neighbor_b, 0xb);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &neighbor_b[8], 8);
	memcpy(entry.next_hop, neighbor_b, 16);
	entry.lat_e7 = 480000000;  /* 48.0 degrees - north of Seattle */
	entry.lon_e7 = -1223000000;
	entry.coords_valid = true;
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Destination: Portland */
	ret = lichen_router_gpsr_forward(&router, LAT_PORTLAND, LON_PORTLAND,
					 next_hop);
	zassert_ok(ret, "should find a forwarding neighbor");
	zassert_mem_equal(next_hop, neighbor_a, 16,
			  "should select neighbor closer to destination");
}

ZTEST(routing_gpsr, test_gpsr_requires_progress)
{
	uint8_t next_hop[16];
	uint8_t neighbor[16];
	struct lichen_gradient_entry entry;
	int ret;

	/* Our position: close to destination */
	lichen_router_set_coords(&router, LAT_PORTLAND, LON_PORTLAND);

	/* Neighbor: further from destination than we are */
	make_link_local(neighbor, 0xa);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &neighbor[8], 8);
	memcpy(entry.next_hop, neighbor, 16);
	entry.lat_e7 = LAT_SEATTLE;  /* Seattle is further from Portland */
	entry.lon_e7 = LON_SEATTLE;
	entry.coords_valid = true;
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Try to route to a point south of Portland */
	ret = lichen_router_gpsr_forward(&router, 440000000, -1227000000,
					 next_hop);
	zassert_equal(ret, -ENOENT,
		      "should return -ENOENT when no progress possible (local minimum)");
}

ZTEST(routing_gpsr, test_gpsr_skips_invalid_neighbor_coords)
{
	uint8_t next_hop[16];
	uint8_t bad_neighbor[16], good_neighbor[16];
	struct lichen_gradient_entry entry;
	int ret;

	/* Our position: Seattle */
	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Bad neighbor: null island coords (invalid) */
	make_link_local(bad_neighbor, 0xa);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &bad_neighbor[8], 8);
	memcpy(entry.next_hop, bad_neighbor, 16);
	entry.lat_e7 = 0;
	entry.lon_e7 = 0;
	entry.coords_valid = true;  /* Marked valid but coords are null island */
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Good neighbor: valid coords closer to destination */
	make_link_local(good_neighbor, 0xb);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &good_neighbor[8], 8);
	memcpy(entry.next_hop, good_neighbor, 16);
	entry.lat_e7 = 465000000;  /* Between Seattle and Portland */
	entry.lon_e7 = -1225000000;
	entry.coords_valid = true;
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Destination: Portland */
	ret = lichen_router_gpsr_forward(&router, LAT_PORTLAND, LON_PORTLAND,
					 next_hop);
	zassert_ok(ret, "should find good neighbor");
	zassert_mem_equal(next_hop, good_neighbor, 16,
			  "should skip bad neighbor and select good one");
}

ZTEST(routing_gpsr, test_gpsr_ignores_neighbor_without_coords)
{
	uint8_t next_hop[16];
	uint8_t no_coords_neighbor[16], with_coords_neighbor[16];
	struct lichen_gradient_entry entry;
	int ret;

	/* Our position: Seattle */
	lichen_router_set_coords(&router, LAT_SEATTLE, LON_SEATTLE);

	/* Neighbor without coords */
	make_link_local(no_coords_neighbor, 0xa);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &no_coords_neighbor[8], 8);
	memcpy(entry.next_hop, no_coords_neighbor, 16);
	entry.coords_valid = false;  /* No coordinates */
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Neighbor with coords */
	make_link_local(with_coords_neighbor, 0xb);
	memset(&entry, 0, sizeof(entry));
	memcpy(entry.destination_iid, &with_coords_neighbor[8], 8);
	memcpy(entry.next_hop, with_coords_neighbor, 16);
	entry.lat_e7 = 465000000;
	entry.lon_e7 = -1225000000;
	entry.coords_valid = true;
	entry.valid = true;
	entry.hop_count = 1;
	entry.source = LICHEN_GRADIENT_ANNOUNCE;
	entry.expires_ms = 1000000;
	lichen_gradient_update(&router.gradient_table, &entry, 0);

	/* Destination: Portland */
	ret = lichen_router_gpsr_forward(&router, LAT_PORTLAND, LON_PORTLAND,
					 next_hop);
	zassert_ok(ret, "should find neighbor with coords");
	zassert_mem_equal(next_hop, with_coords_neighbor, 16,
			  "should use neighbor with coords");
}

ZTEST_SUITE(routing_gpsr, NULL, NULL, before, NULL, NULL);
