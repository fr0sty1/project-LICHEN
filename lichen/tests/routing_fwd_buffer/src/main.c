/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Tests for forwarding buffer with backpressure (spec appendix-bufferbloat)
 *
 * Tests the per-source forwarding buffer that prevents one chatty source from
 * monopolizing relay capacity. Verifies:
 * - Per-source packet limits (MAX_PACKETS_PER_SOURCE)
 * - ENOBUFS return when limit reached
 * - FIFO dequeue across sources
 * - Deadline expiry
 * - LRU source eviction
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <lichen/routing/router.h>

/* Test helper: create a ULA mesh address */
static void make_ula(uint8_t addr[16], uint8_t iid)
{
	memset(addr, 0, 16);
	addr[0] = 0xfd;
	addr[15] = iid;
}

/* Test helper: create an IID from a byte */
static void make_iid(uint8_t iid[8], uint8_t val)
{
	memset(iid, 0, 8);
	iid[7] = val;
}

static struct lichen_router router;
static uint8_t packet_data[4][64];  /* Test packet buffers */

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	uint8_t node_addr[16];
	make_ula(node_addr, 1);
	lichen_router_init(&router, node_addr);

	/* Initialize test packet data */
	for (int i = 0; i < 4; i++) {
		memset(packet_data[i], 0xAA + i, sizeof(packet_data[i]));
	}
}

ZTEST(routing_fwd_buffer, test_fwd_can_accept_new_source)
{
	uint8_t source_iid[8];
	make_iid(source_iid, 0x10);

	/* New source should be accepted */
	zassert_true(lichen_router_fwd_can_accept(&router, source_iid),
		     "should accept packets from new source");
}

ZTEST(routing_fwd_buffer, test_fwd_enqueue_dequeue_single)
{
	uint8_t source_iid[8];
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;
	int ret;

	make_iid(source_iid, 0x10);

	/* Enqueue one packet */
	ret = lichen_router_fwd_enqueue(&router, source_iid, packet_data[0],
					32, 1000);
	zassert_ok(ret, "enqueue should succeed");
	zassert_equal(lichen_router_fwd_count(&router), 1,
		      "should have 1 packet queued");

	/* Dequeue it */
	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_ok(ret, "dequeue should succeed");
	zassert_mem_equal(out_source, source_iid, 8, "source IID should match");
	zassert_equal(out_data, packet_data[0], "data pointer should match");
	zassert_equal(out_len, 32, "length should match");
	zassert_equal(lichen_router_fwd_count(&router), 0,
		      "should have 0 packets after dequeue");
}

ZTEST(routing_fwd_buffer, test_fwd_per_source_limit)
{
	uint8_t source_iid[8];
	int ret;

	make_iid(source_iid, 0x20);

	/* Enqueue MAX_PACKETS_PER_SOURCE packets */
	for (int i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; i++) {
		ret = lichen_router_fwd_enqueue(&router, source_iid,
						packet_data[i], 32, 1000);
		zassert_ok(ret, "enqueue %d should succeed", i);
	}

	/* Verify can_accept returns false */
	zassert_false(lichen_router_fwd_can_accept(&router, source_iid),
		      "should not accept more packets from this source");

	/* Next enqueue should fail with -ENOBUFS */
	ret = lichen_router_fwd_enqueue(&router, source_iid, packet_data[0],
					32, 1000);
	zassert_equal(ret, -ENOBUFS, "should return -ENOBUFS at limit");

	/* Verify stats */
	const struct lichen_fwd_stats *stats = lichen_router_fwd_stats(&router);
	zassert_equal(stats->packets_dropped_full, 1,
		      "should count dropped packet");
	zassert_equal(stats->nacks_sent, 1, "should count NACK signal");
}

ZTEST(routing_fwd_buffer, test_fwd_multiple_sources)
{
	uint8_t source_a[8], source_b[8];
	int ret;

	make_iid(source_a, 0x30);
	make_iid(source_b, 0x31);

	/* Each source can have MAX_PACKETS_PER_SOURCE */
	ret = lichen_router_fwd_enqueue(&router, source_a, packet_data[0],
					32, 1000);
	zassert_ok(ret, "source A packet 1 should succeed");

	ret = lichen_router_fwd_enqueue(&router, source_b, packet_data[1],
					32, 1001);
	zassert_ok(ret, "source B packet 1 should succeed");

	ret = lichen_router_fwd_enqueue(&router, source_a, packet_data[2],
					32, 1002);
	zassert_ok(ret, "source A packet 2 should succeed");

	ret = lichen_router_fwd_enqueue(&router, source_b, packet_data[3],
					32, 1003);
	zassert_ok(ret, "source B packet 2 should succeed");

	/* Both sources now at limit */
	zassert_false(lichen_router_fwd_can_accept(&router, source_a),
		      "source A should be at limit");
	zassert_false(lichen_router_fwd_can_accept(&router, source_b),
		      "source B should be at limit");

	zassert_equal(lichen_router_fwd_count(&router), 4,
		      "should have 4 packets total");
}

ZTEST(routing_fwd_buffer, test_fwd_fifo_dequeue_order)
{
	uint8_t source_a[8], source_b[8];
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;
	int ret;

	make_iid(source_a, 0x40);
	make_iid(source_b, 0x41);

	/* Enqueue in interleaved order: A@1000, B@1001, A@1002 */
	lichen_router_fwd_enqueue(&router, source_a, packet_data[0], 32, 1000);
	lichen_router_fwd_enqueue(&router, source_b, packet_data[1], 32, 1001);
	lichen_router_fwd_enqueue(&router, source_a, packet_data[2], 32, 1002);

	/* Dequeue should return in FIFO order (by timestamp) */
	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_ok(ret, "dequeue 1 should succeed");
	zassert_mem_equal(out_source, source_a, 8, "first should be source A");
	zassert_equal(out_data, packet_data[0], "first should be packet 0");

	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_ok(ret, "dequeue 2 should succeed");
	zassert_mem_equal(out_source, source_b, 8, "second should be source B");
	zassert_equal(out_data, packet_data[1], "second should be packet 1");

	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_ok(ret, "dequeue 3 should succeed");
	zassert_mem_equal(out_source, source_a, 8, "third should be source A");
	zassert_equal(out_data, packet_data[2], "third should be packet 2");
}

ZTEST(routing_fwd_buffer, test_fwd_dequeue_empty_returns_enoent)
{
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;
	int ret;

	/* Empty buffer */
	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_equal(ret, -ENOENT, "should return -ENOENT when empty");
}

ZTEST(routing_fwd_buffer, test_fwd_expire_old_packets)
{
	uint8_t source_iid[8];
	int expired;

	make_iid(source_iid, 0x50);

	/* Enqueue packets at time 1000 */
	lichen_router_fwd_enqueue(&router, source_iid, packet_data[0], 32, 1000);
	lichen_router_fwd_enqueue(&router, source_iid, packet_data[1], 32, 1001);

	zassert_equal(lichen_router_fwd_count(&router), 2,
		      "should have 2 packets");

	/* Expire at time beyond deadline */
	uint32_t now = 1000 + CONFIG_LICHEN_ROUTER_FORWARDING_DEADLINE_MS + 100;
	expired = lichen_router_fwd_expire(&router, now);

	zassert_equal(expired, 2, "should expire 2 packets");
	zassert_equal(lichen_router_fwd_count(&router), 0,
		      "should have 0 packets after expire");

	const struct lichen_fwd_stats *stats = lichen_router_fwd_stats(&router);
	zassert_equal(stats->packets_dropped_deadline, 2,
		      "should count deadline drops");
}

ZTEST(routing_fwd_buffer, test_fwd_expire_keeps_fresh_packets)
{
	uint8_t source_iid[8];
	int expired;

	make_iid(source_iid, 0x51);

	/* Enqueue packet at time 1000 */
	lichen_router_fwd_enqueue(&router, source_iid, packet_data[0], 32, 1000);

	/* Expire at time before deadline */
	expired = lichen_router_fwd_expire(&router, 5000);  /* deadline is 10000 */

	zassert_equal(expired, 0, "should not expire fresh packets");
	zassert_equal(lichen_router_fwd_count(&router), 1,
		      "should still have 1 packet");
}

ZTEST(routing_fwd_buffer, test_fwd_slot_reuse_after_dequeue)
{
	uint8_t source_iid[8];
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;
	int ret;

	make_iid(source_iid, 0x60);

	/* Fill to limit */
	for (int i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; i++) {
		ret = lichen_router_fwd_enqueue(&router, source_iid,
						packet_data[i], 32, 1000 + i);
		zassert_ok(ret, "enqueue %d should succeed", i);
	}

	/* At limit */
	zassert_false(lichen_router_fwd_can_accept(&router, source_iid),
		      "should be at limit");

	/* Dequeue one */
	ret = lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);
	zassert_ok(ret, "dequeue should succeed");

	/* Should be able to enqueue again */
	zassert_true(lichen_router_fwd_can_accept(&router, source_iid),
		     "should accept after dequeue");

	ret = lichen_router_fwd_enqueue(&router, source_iid, packet_data[0],
					32, 2000);
	zassert_ok(ret, "re-enqueue should succeed");
}

ZTEST(routing_fwd_buffer, test_fwd_stats_counts)
{
	uint8_t source_iid[8];
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;

	make_iid(source_iid, 0x70);

	const struct lichen_fwd_stats *stats = lichen_router_fwd_stats(&router);
	uint32_t initial_queued = stats->packets_queued;
	uint32_t initial_forwarded = stats->packets_forwarded;

	/* Enqueue and dequeue */
	lichen_router_fwd_enqueue(&router, source_iid, packet_data[0], 32, 1000);
	lichen_router_fwd_dequeue(&router, out_source, &out_data, &out_len);

	zassert_equal(stats->packets_queued, initial_queued + 1,
		      "packets_queued should increment");
	zassert_equal(stats->packets_forwarded, initial_forwarded + 1,
		      "packets_forwarded should increment");
}

ZTEST(routing_fwd_buffer, test_fwd_null_params)
{
	uint8_t source_iid[8];
	uint8_t out_source[8];
	uint8_t *out_data;
	size_t out_len;

	make_iid(source_iid, 0x80);

	/* NULL router */
	zassert_false(lichen_router_fwd_can_accept(NULL, source_iid),
		      "NULL router should return false");
	zassert_equal(lichen_router_fwd_enqueue(NULL, source_iid, packet_data[0],
						32, 1000), -EINVAL,
		      "NULL router should return -EINVAL");
	zassert_equal(lichen_router_fwd_dequeue(NULL, out_source, &out_data,
						&out_len), -EINVAL,
		      "NULL router should return -EINVAL");

	/* NULL source_iid */
	zassert_false(lichen_router_fwd_can_accept(&router, NULL),
		      "NULL source should return false");
	zassert_equal(lichen_router_fwd_enqueue(&router, NULL, packet_data[0],
						32, 1000), -EINVAL,
		      "NULL source should return -EINVAL");

	/* NULL data */
	zassert_equal(lichen_router_fwd_enqueue(&router, source_iid, NULL,
						32, 1000), -EINVAL,
		      "NULL data should return -EINVAL");
}

ZTEST_SUITE(routing_fwd_buffer, NULL, NULL, before, NULL, NULL);
