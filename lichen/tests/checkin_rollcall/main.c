/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Check-In / Roll Call conformance tests
 *
 * Consumes the canonical oracle test/vectors/checkin_rollcall.json via the
 * generated header (gen_vectors.py). Expectations come from the vectors,
 * never from the implementation under test.
 */

#include <lichen/checkin.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "checkin_vectors.h"

/* --- test framework --- */

static int tests_run;
static int tests_passed;

#define RUN_TEST(fn) do { \
	tests_run++; \
	if (fn()) { \
		tests_passed++; \
	} else { \
		printf("FAIL: %s\n", #fn); \
	} \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
	if ((int64_t)(a) != (int64_t)(b)) { \
		printf("  FAIL: %s (got %lld, expected %lld)\n", msg, \
		       (long long)(a), (long long)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_STR_EQ(a, b, msg) do { \
	if ((a) == NULL || (b) == NULL || strcmp((a), (b)) != 0) { \
		printf("  FAIL: %s (got %s, expected %s)\n", msg, \
		       (a) == NULL ? "(null)" : (a), \
		       (b) == NULL ? "(null)" : (b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s (memory mismatch at byte %zu)\n", msg, \
		       (size_t)(memcmp(a, b, 1) ? 0 : first_diff(a, b, len))); \
		return 0; \
	} \
} while (0)

static size_t first_diff(const void *a, const void *b, size_t len)
{
	const uint8_t *pa = a;
	const uint8_t *pb = b;

	for (size_t i = 0; i < len; i++) {
		if (pa[i] != pb[i]) {
			return i;
		}
	}
	return len;
}

/* --- error string mapping (vector error vocabulary) --- */

static const char *error_str(int err)
{
	switch (err) {
	case LICHEN_CHECKIN_ERR_MISSING_NODE:
		return "missing_required_field_node";
	case LICHEN_CHECKIN_ERR_MISSING_TS:
		return "missing_required_field_ts";
	case LICHEN_CHECKIN_ERR_MISSING_STATUS:
		return "missing_required_field_status";
	case LICHEN_CHECKIN_ERR_MISSING_ID:
		return "missing_required_field_id";
	case LICHEN_CHECKIN_ERR_INVALID_STATUS:
		return "invalid_status_value";
	case LICHEN_CHECKIN_ERR_COORD_PAIR:
		return "incomplete_coordinate_pair";
	case LICHEN_CHECKIN_ERR_COORD_RANGE:
		return "coordinate_out_of_range";
	case LICHEN_CHECKIN_ERR_INVALID_TIMEOUT:
		return "invalid_timeout_value";
	case LICHEN_CHECKIN_ERR_TIMEOUT_MAX:
		return "timeout_exceeds_maximum";
	default:
		return NULL;
	}
}

/* --- helpers --- */

static void make_node(char *dst, size_t cap, unsigned n)
{
	snprintf(dst, cap,
		 "0200:0000:0000:0000:0000:0000:0000:%04x", n & 0xffffU);
}

/* --- constants vectors --- */

static int test_constants_match_vectors(void)
{
	ASSERT_EQ(LICHEN_CHECKIN_MAX, constants.max_checkins,
		  "LICHEN_CHECKIN_MAX == max_checkins");
	ASSERT_EQ(LICHEN_ROLLCALL_MAX, constants.max_rollcalls,
		  "LICHEN_ROLLCALL_MAX == max_rollcalls");
	ASSERT_EQ(LICHEN_ROLLCALL_TIMEOUT_MAX_S, constants.max_timeout_s,
		  "max_timeout_s");
	ASSERT_EQ(LICHEN_ROLLCALL_TIMEOUT_DEFAULT_S, constants.default_timeout_s,
		  "default_timeout_s");
	ASSERT_EQ(LICHEN_CHECKIN_LAT_MAX == constants.lat_min * -1.0 &&
		  constants.lat_min == -90.0, 1, "lat range");
	ASSERT_STR_EQ(constants.prune_policy, "remove_oldest_by_ts",
		      "prune policy");
	return 1;
}

static int test_coord_bounds_from_vector(void)
{
	ASSERT_EQ(lichen_checkin_coord_valid(90.0, -180.0), 0,
		  "inclusive bounds accepted");
	ASSERT_EQ(lichen_checkin_coord_valid(-90.0, 180.0), 0,
		  "negative inclusive bounds accepted");
	ASSERT_EQ(lichen_checkin_coord_valid(90.5, 0.0) != 0, 1,
		  "lat above max rejected");
	ASSERT_EQ(lichen_checkin_coord_valid(0.0, -180.5) != 0, 1,
		  "lon below min rejected");
	return 1;
}

static int test_node_format_from_vector(void)
{
	for (size_t i = 0; i < constants.valid_nodes_count; i++) {
		ASSERT_EQ(lichen_checkin_addr_valid(constants.valid_nodes[i]),
			  0, "valid node example accepted");
	}
	for (size_t i = 0; i < constants.invalid_nodes_count; i++) {
		ASSERT_EQ(lichen_checkin_addr_valid(constants.invalid_nodes[i])
			  != 0, 1, "invalid node example rejected");
	}
	return 1;
}

static int test_status_values_from_vector(void)
{
	ASSERT_STR_EQ(lichen_checkin_status_str(LICHEN_CHECKIN_STATUS_OK), "ok",
		      "ok string");
	ASSERT_STR_EQ(lichen_checkin_status_str(LICHEN_CHECKIN_STATUS_HELP),
		      "help", "help string");
	ASSERT_STR_EQ(lichen_checkin_status_str(LICHEN_CHECKIN_STATUS_DELAYED),
		      "delayed", "delayed string");
	ASSERT_EQ(lichen_checkin_status_str((enum lichen_checkin_status)7)
		  == NULL, 1, "invalid status has no string");
	return 1;
}

/* --- wire vectors --- */

static int decode_vector(const struct checkin_vector *v,
			 struct lichen_checkin *c,
			 struct lichen_rollcall_req *req,
			 struct lichen_rollcall_status *status,
			 int *err_out)
{
	*err_out = LICHEN_CHECKIN_OK;

	if (strcmp(v->kind, "checkin") == 0) {
		*err_out = lichen_checkin_from_cbor(v->wire, v->wire_len, c);
		return 1;
	}
	if (strcmp(v->kind, "rollcall_req") == 0) {
		*err_out = lichen_rollcall_req_from_cbor(v->wire, v->wire_len,
							 req);
		return 1;
	}
	*err_out = lichen_rollcall_status_from_cbor(v->wire, v->wire_len,
						    status);
	return 1;
}

static int encode_vector(const struct checkin_vector *v,
			 const struct lichen_checkin *c,
			 const struct lichen_rollcall_req *req,
			 const struct lichen_rollcall_status *status,
			 const uint8_t **out, size_t *out_len)
{
	static uint8_t buf[4096];
	int err;

	if (strcmp(v->kind, "checkin") == 0) {
		err = lichen_checkin_to_cbor(c, buf, sizeof(buf), out_len);
	} else if (strcmp(v->kind, "rollcall_req") == 0) {
		err = lichen_rollcall_req_to_cbor(req, buf, sizeof(buf),
						  out_len);
	} else {
		err = lichen_rollcall_status_to_cbor(status, buf,
						     sizeof(buf), out_len);
	}
	if (err != LICHEN_CHECKIN_OK) {
		printf("  encode failed err=%d\n", err);
		return 0;
	}
	*out = buf;
	return 1;
}

static int verify_fields(const struct checkin_vector *v,
			 const struct lichen_checkin *c,
			 const struct lichen_rollcall_status *status)
{
	const char *fields = v->fields;

	if (fields == NULL) {
		return 1;
	}
	if (strstr(fields, "node") != NULL) {
		if (strcmp(v->kind, "checkin") == 0) {
			ASSERT_EQ(c->node[0] != '\0', 1, "node present");
		} else {
			ASSERT_EQ(status->id[0] != '\0' ||
				  strstr(fields, "id") == NULL, 1,
				  "id present");
		}
	}
	if (strcmp(v->kind, "checkin") == 0) {
		if (strstr(fields, "msg") != NULL) {
			ASSERT_EQ(c->has_msg, 1, "msg present");
		}
		if (strstr(fields, "lat") != NULL) {
			ASSERT_EQ(c->has_location, 1, "lat present");
		}
		if (v->lat_negative) {
			ASSERT_EQ(c->lat < 0.0, 1, "lat is negative");
		}
		if (v->status_value != NULL) {
			ASSERT_STR_EQ(lichen_checkin_status_str(c->status),
				      v->status_value, "status value");
		}
	} else {
		if (strstr(fields, "responded") != NULL) {
			ASSERT_EQ(status->responded_count >= 1, 1,
				  "responded non-empty");
			ASSERT_STR_EQ(
				lichen_checkin_status_str(
					status->responded[0].status),
				"ok", "responded[0] status");
		}
		if (strstr(fields, "missing") != NULL) {
			ASSERT_EQ(status->missing_count >= 1, 1,
				  "missing non-empty");
		}
	}
	return 1;
}

static int test_wire_vectors(void)
{
	for (size_t v = 0; v < VECTORS_COUNT; v++) {
		const struct checkin_vector *vec = &vectors[v];
		struct lichen_checkin checkin;
		struct lichen_rollcall_req req;
		struct lichen_rollcall_status status;
		int err = LICHEN_CHECKIN_OK;

		decode_vector(vec, &checkin, &req, &status, &err);

		if ((err == LICHEN_CHECKIN_OK) != (vec->decode_success != 0)) {
			printf("  vector %s: decode outcome %d, expected %d\n",
			       vec->name, err, vec->decode_success);
			return 0;
		}

		if (err != LICHEN_CHECKIN_OK) {
			if (vec->error != NULL) {
				ASSERT_STR_EQ(error_str(err), vec->error,
					      "error string matches vector");
			}
			continue;
		}

		if (!verify_fields(vec, &checkin, &status)) {
			return 0;
		}

		const uint8_t *reencoded = NULL;
		size_t reencoded_len = 0U;

		if (!encode_vector(vec, &checkin, &req, &status, &reencoded,
				   &reencoded_len)) {
			return 0;
		}
		if (reencoded_len != vec->reencode_len ||
		    memcmp(reencoded, vec->reencode, reencoded_len) != 0) {
			printf("  vector %s: re-encode drift (%zu vs %zu)\n",
			       vec->name, reencoded_len, vec->reencode_len);
			for (size_t i = 0; i < reencoded_len && i < vec->reencode_len;
			     i++) {
				if (reencoded[i] != vec->reencode[i]) {
					printf("    first diff at %zu: "
					       "0x%02x vs 0x%02x\n", i,
					       reencoded[i], vec->reencode[i]);
					break;
				}
			}
			return 0;
		}
	}
	return 1;
}

static int test_vector_service_codes(void)
{
	for (size_t v = 0; v < VECTORS_COUNT; v++) {
		const struct checkin_vector *vec = &vectors[v];
		static struct lichen_checkin_entry checkins[LICHEN_CHECKIN_MAX];
		static struct lichen_rollcall rollcalls[LICHEN_ROLLCALL_MAX];
		struct lichen_checkin_service svc;
		enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;
		uint8_t code;

		if (vec->response_code == 0U) {
			continue;
		}

		lichen_checkin_service_init(&svc, checkins, LICHEN_CHECKIN_MAX,
					    rollcalls, LICHEN_ROLLCALL_MAX);
		lichen_checkin_service_set_time(&svc, 1716742800U);

		if (strcmp(vec->kind, "checkin") == 0) {
			code = lichen_checkin_post(&svc, vec->wire,
						   vec->wire_len, &detail);
		} else if (strcmp(vec->kind, "rollcall_req") == 0) {
			code = lichen_rollcall_post(&svc, vec->wire,
						    vec->wire_len, &detail);
		} else {
			/* Status document: GET semantics; code is metadata. */
			ASSERT_EQ(vec->response_code,
				  LICHEN_CHECKIN_CODE_CONTENT,
				  "status vector code is 2.05");
			continue;
		}

		if (code != vec->response_code) {
			printf("  vector %s: service code 0x%02x, expected "
			       "0x%02x (detail %d)\n", vec->name, code,
			       vec->response_code, detail);
			return 0;
		}
		if (code == LICHEN_CHECKIN_CODE_BAD_REQUEST &&
		    vec->error != NULL) {
			ASSERT_STR_EQ(error_str(detail), vec->error,
				      "service detail error string");
		}
	}
	return 1;
}

/* --- service policies (driven by the constants vectors) --- */

static int test_checkin_capacity_prune_oldest(void)
{
	static struct lichen_checkin_entry checkins[LICHEN_CHECKIN_MAX + 1U];
	static struct lichen_rollcall rollcalls[1];
	struct lichen_checkin_service svc;
	char node[LICHEN_CHECKIN_ADDR_LEN];
	uint8_t wire[LICHEN_CHECKIN_CBOR_MAX];
	size_t wire_len;
	char oldest_node[LICHEN_CHECKIN_ADDR_LEN];

	lichen_checkin_service_init(&svc, checkins, LICHEN_CHECKIN_MAX,
				    rollcalls, 1U);
	lichen_checkin_service_set_time(&svc, 1000U);

	for (unsigned i = 0; i < LICHEN_CHECKIN_MAX; i++) {
		struct lichen_checkin c;

		memset(&c, 0, sizeof(c));
		make_node(node, sizeof(node), i);
		strcpy(c.node, node);
		c.ts = 2000U + i; /* node 0 has the smallest ts */
		c.status = LICHEN_CHECKIN_STATUS_OK;
		ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire),
						 &wire_len), 0, "encode");
		ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, NULL),
			  LICHEN_CHECKIN_CODE_CHANGED, "post");
	}
	ASSERT_EQ(svc.checkin_count, LICHEN_CHECKIN_MAX, "store full");

	/* Oldest entry must currently be node 0 (ts 2000). */
	make_node(oldest_node, sizeof(oldest_node), 0);
	ASSERT_EQ(strcmp(svc.checkins[0].checkin.node, oldest_node), 0,
		  "oldest is at index 0 before eviction");

	/* One more: evicts the smallest-ts entry (node 0). */
	{
		struct lichen_checkin c;

		memset(&c, 0, sizeof(c));
		make_node(node, sizeof(node), LICHEN_CHECKIN_MAX);
		strcpy(c.node, node);
		c.ts = 5000U;
		c.status = LICHEN_CHECKIN_STATUS_OK;
		ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire),
						 &wire_len), 0, "encode");
		ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, NULL),
			  LICHEN_CHECKIN_CODE_CHANGED, "post at capacity");
	}
	ASSERT_EQ(svc.checkin_count, LICHEN_CHECKIN_MAX,
		  "count stays at capacity");
	make_node(node, sizeof(node), 0);
	ASSERT_EQ(strcmp(svc.checkins[0].checkin.node, node) != 0, 1,
		  "oldest-by-ts evicted");
	{
		char new_node[LICHEN_CHECKIN_ADDR_LEN];

		make_node(new_node, sizeof(new_node), LICHEN_CHECKIN_MAX);
		ASSERT_STR_EQ(svc.checkins[LICHEN_CHECKIN_MAX - 1U]
			      .checkin.node, new_node, "new entry appended");
	}
	return 1;
}

static int test_checkin_duplicate_node_updates(void)
{
	static struct lichen_checkin_entry checkins[LICHEN_CHECKIN_MAX];
	static struct lichen_rollcall rollcalls[1];
	struct lichen_checkin_service svc;
	struct lichen_checkin c;
	uint8_t wire[LICHEN_CHECKIN_CBOR_MAX];
	size_t wire_len;

	lichen_checkin_service_init(&svc, checkins, LICHEN_CHECKIN_MAX,
				    rollcalls, 1U);
	lichen_checkin_service_set_time(&svc, 10U);

	memset(&c, 0, sizeof(c));
	make_node(c.node, sizeof(c.node), 1U);
	c.ts = 100U;
	c.status = LICHEN_CHECKIN_STATUS_OK;
	ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire), &wire_len),
		  0, "encode");
	ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_CHANGED, "first post");

	c.ts = 200U;
	c.status = LICHEN_CHECKIN_STATUS_HELP;
	ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire), &wire_len),
		  0, "encode");
	ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_CHANGED, "second post");

	ASSERT_EQ(svc.checkin_count, 1U, "update in place, no prune");
	ASSERT_EQ(svc.checkins[0].checkin.status, LICHEN_CHECKIN_STATUS_HELP,
		  "status updated");
	ASSERT_EQ(svc.checkins[0].checkin.ts, 200U, "ts updated");
	return 1;
}

static int test_checkin_zero_capacity_store(void)
{
	static struct lichen_rollcall rollcalls[1];
	struct lichen_checkin_service svc;
	struct lichen_checkin c;
	uint8_t wire[LICHEN_CHECKIN_CBOR_MAX];
	size_t wire_len;
	enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;

	/* checkins=NULL with cap 0 is documented-legal (checkin.h);
	 * the post must fail closed instead of indexing the NULL store. */
	lichen_checkin_service_init(&svc, NULL, 0U, rollcalls, 1U);
	lichen_checkin_service_set_time(&svc, 1716742800U);

	memset(&c, 0, sizeof(c));
	strcpy(c.node, "0200:0000:0000:0000:0011:2233:4455:6677");
	c.ts = 1716742800U;
	c.status = LICHEN_CHECKIN_STATUS_OK;
	ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire), &wire_len),
		  0, "encode");

	ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, &detail),
		  LICHEN_CHECKIN_CODE_UNAVAILABLE, "cap-0 post 5.03");
	ASSERT_EQ(svc.checkin_count, 0U, "count stays zero");
	return 1;
}

static int test_rollcall_capacity_unavailable(void)
{
	static struct lichen_checkin_entry checkins[1];
	static struct lichen_rollcall rollcalls[LICHEN_ROLLCALL_MAX];
	struct lichen_checkin_service svc;
	struct lichen_rollcall_req req;
	uint8_t wire[LICHEN_ROLLCALL_REQ_CBOR_MAX];
	size_t wire_len;
	char id[LICHEN_ROLLCALL_ID_MAX];

	lichen_checkin_service_init(&svc, checkins, 1U, rollcalls,
				    LICHEN_ROLLCALL_MAX);
	lichen_checkin_service_set_time(&svc, 1716742800U);

	for (unsigned i = 0; i < LICHEN_ROLLCALL_MAX; i++) {
		memset(&req, 0, sizeof(req));
		snprintf(id, sizeof(id), "rc-%u", i);
		strcpy(req.id, id);
		ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
						      &wire_len), 0, "encode");
		ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
			  LICHEN_CHECKIN_CODE_CREATED, "created");
	}

	memset(&req, 0, sizeof(req));
	strcpy(req.id, "overflow");
	ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
					      &wire_len), 0, "encode");
	ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_UNAVAILABLE, "5.03 when full");

	/* Existing id still updates at capacity (oracle behavior). */
	memset(&req, 0, sizeof(req));
	strcpy(req.id, "rc-0");
	ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
					      &wire_len), 0, "encode");
	ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_CREATED, "existing id updated");
	return 1;
}

static int test_rollcall_expiry_and_defaults(void)
{
	static struct lichen_checkin_entry checkins[1];
	static struct lichen_rollcall rollcalls[LICHEN_ROLLCALL_MAX];
	struct lichen_checkin_service svc;
	struct lichen_rollcall_req req;
	uint8_t wire[LICHEN_ROLLCALL_REQ_CBOR_MAX];
	size_t wire_len;
	uint8_t render[LICHEN_ROLLCALL_STATUS_CBOR_MAX];
	size_t render_len;
	struct lichen_rollcall_status st;

	lichen_checkin_service_init(&svc, checkins, 1U, rollcalls,
				    LICHEN_ROLLCALL_MAX);
	lichen_checkin_service_set_time(&svc, 1716742800U);

	memset(&req, 0, sizeof(req));
	strcpy(req.id, "roll-001");
	ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
					      &wire_len), 0, "encode");
	ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_CREATED, "created");

	{
		struct lichen_rollcall *rc = lichen_rollcall_find(&svc,
								  "roll-001");

		ASSERT_EQ(rc != NULL, 1, "found before expiry");
		ASSERT_EQ(rc->timeout_s, LICHEN_ROLLCALL_TIMEOUT_DEFAULT_S,
			  "default timeout is 60");
	}

	lichen_checkin_service_set_time(&svc, 1716742860U); /* +60: not expired */
	ASSERT_EQ(lichen_rollcall_find(&svc, "roll-001") != NULL, 1,
		  "boundary not expired");

	lichen_checkin_service_set_time(&svc, 1716742861U); /* +61: expired */
	ASSERT_EQ(lichen_rollcall_find(&svc, "roll-001") == NULL, 1,
		  "expired after timeout");

	/* Far-future start rejection and boundary. */
	lichen_checkin_service_set_time(&svc, 1716742800U);
	memset(&req, 0, sizeof(req));
	strcpy(req.id, "future");
	req.has_ts = true;
	req.ts = 1716742800U + LICHEN_ROLLCALL_FUTURE_SLACK_S + 1U;
	ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
					      &wire_len), 0, "encode");
	{
		enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;

		ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, &detail),
			  LICHEN_CHECKIN_CODE_BAD_REQUEST, "far future 4.00");
		ASSERT_EQ(detail, LICHEN_CHECKIN_ERR_TS_FUTURE, "detail");
	}
	req.ts = 1716742800U + LICHEN_ROLLCALL_FUTURE_SLACK_S;
	ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire, sizeof(wire),
					      &wire_len), 0, "encode");
	ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
		  LICHEN_CHECKIN_CODE_CREATED, "slack boundary created");

	/* Render + decode round trip of a stored entry. */
	{
		struct lichen_rollcall *rc = lichen_rollcall_find(&svc,
								  "future");
		struct lichen_rollcall_track track;

		ASSERT_EQ(rc != NULL, 1, "found");
		memset(&track, 0, sizeof(track));
		make_node(track.node, sizeof(track.node), 0x1111U);
		track.ts = 1716742805U;
		track.status = LICHEN_CHECKIN_STATUS_OK;
		ASSERT_EQ(lichen_rollcall_record_responded(rc, &track), 0,
			  "record responded");
		ASSERT_EQ(lichen_rollcall_render(rc, render, sizeof(render),
						 &render_len), 0, "render");
		ASSERT_EQ(lichen_rollcall_status_from_cbor(render, render_len,
							   &st), 0, "decode");
		ASSERT_EQ(st.responded_count, 1U, "one responded");
		ASSERT_STR_EQ(st.responded[0].node, track.node, "node matches");
		ASSERT_EQ(st.responded[0].ts, 1716742805U, "ts matches");

		/* Moving to missing removes from responded. */
		ASSERT_EQ(lichen_rollcall_record_missing(rc, &track), 0,
			  "record missing");
		ASSERT_EQ(lichen_rollcall_render(rc, render, sizeof(render),
						 &render_len), 0, "render");
		ASSERT_EQ(lichen_rollcall_status_from_cbor(render, render_len,
							   &st), 0, "decode");
		ASSERT_EQ(st.responded_count, 0U, "responded emptied");
		ASSERT_EQ(st.missing_count, 1U, "missing filled");
	}
	return 1;
}

static int test_track_capacity_full(void)
{
	static struct lichen_checkin_entry checkins[1];
	static struct lichen_rollcall rollcalls[LICHEN_ROLLCALL_MAX];
	struct lichen_checkin_service svc;
	struct lichen_rollcall *rc;
	struct lichen_rollcall_track track;

	lichen_checkin_service_init(&svc, checkins, 1U, rollcalls, 1U);
	lichen_checkin_service_set_time(&svc, 0U);

	{
		struct lichen_rollcall_req req;
		uint8_t wire[LICHEN_ROLLCALL_REQ_CBOR_MAX];
		size_t wire_len;

		memset(&req, 0, sizeof(req));
		strcpy(req.id, "big");
		ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire,
						      sizeof(wire),
						      &wire_len), 0, "encode");
		ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
			  LICHEN_CHECKIN_CODE_CREATED, "created");
	}

	rc = lichen_rollcall_find(&svc, "big");
	ASSERT_EQ(rc != NULL, 1, "found");

	for (unsigned i = 0; i < LICHEN_ROLLCALL_TRACK_MAX; i++) {
		memset(&track, 0, sizeof(track));
		make_node(track.node, sizeof(track.node), i);
		track.ts = i;
		track.status = LICHEN_CHECKIN_STATUS_OK;
		ASSERT_EQ(lichen_rollcall_record_responded(rc, &track), 0,
			  "track fill");
	}

	memset(&track, 0, sizeof(track));
	make_node(track.node, sizeof(track.node), LICHEN_ROLLCALL_TRACK_MAX);
	track.ts = 0U;
	track.status = LICHEN_CHECKIN_STATUS_OK;
	ASSERT_EQ(lichen_rollcall_record_responded(rc, &track), -ENOSPC,
		  "track overflow rejected");
	return 1;
}

static int test_rollcall_invalid_status_rejected(void)
{
	static struct lichen_checkin_entry checkins[1];
	static struct lichen_rollcall rollcalls[1];
	struct lichen_checkin_service svc;
	struct lichen_rollcall *rc;
	struct lichen_rollcall_track track;
	struct lichen_rollcall_status st;
	uint8_t wire[LICHEN_ROLLCALL_REQ_CBOR_MAX];
	uint8_t render[LICHEN_ROLLCALL_STATUS_CBOR_MAX];
	size_t wire_len;
	size_t render_len;
	enum lichen_checkin_status bogus =
		(enum lichen_checkin_status)99;

	lichen_checkin_service_init(&svc, checkins, 1U, rollcalls, 1U);
	lichen_checkin_service_set_time(&svc, 1716742800U);

	{
		struct lichen_rollcall_req req;

		memset(&req, 0, sizeof(req));
		strcpy(req.id, "roll-001");
		ASSERT_EQ(lichen_rollcall_req_to_cbor(&req, wire,
						      sizeof(wire),
						      &wire_len), 0, "encode");
		ASSERT_EQ(lichen_rollcall_post(&svc, wire, wire_len, NULL),
			  LICHEN_CHECKIN_CODE_CREATED, "created");
	}

	rc = lichen_rollcall_find(&svc, "roll-001");
	ASSERT_EQ(rc != NULL, 1, "found");

	/* Out-of-range status is rejected at the public entry points;
	 * the track lists must stay untouched. */
	memset(&track, 0, sizeof(track));
	make_node(track.node, sizeof(track.node), 0x2222U);
	track.ts = 1716742801U;
	track.status = bogus;
	ASSERT_EQ(lichen_rollcall_record_responded(rc, &track),
		  -LICHEN_CHECKIN_ERR_INVALID_STATUS, "responded rejected");
	ASSERT_EQ(rc->responded_count, 0U, "responded unchanged");
	ASSERT_EQ(lichen_rollcall_record_missing(rc, &track),
		  -LICHEN_CHECKIN_ERR_INVALID_STATUS, "missing rejected");
	ASSERT_EQ(rc->missing_count, 0U, "missing unchanged");

	/* The encoder also fails closed on a caller-supplied struct. */
	memset(&st, 0, sizeof(st));
	strcpy(st.id, "roll-001");
	st.started = 1716742800U;
	st.timeout_s = 60U;
	st.responded_count = 1U;
	make_node(st.responded[0].node, sizeof(st.responded[0].node),
		  0x3333U);
	st.responded[0].ts = 1716742801U;
	st.responded[0].status = bogus;
	ASSERT_EQ(lichen_rollcall_status_to_cbor(&st, render,
						 sizeof(render),
						 &render_len),
		  -LICHEN_CHECKIN_ERR_INVALID_STATUS,
		  "encoder rejects out-of-range status");

	/* A valid status still renders and round-trips. */
	st.responded[0].status = LICHEN_CHECKIN_STATUS_DELAYED;
	ASSERT_EQ(lichen_rollcall_status_to_cbor(&st, render,
						 sizeof(render),
						 &render_len), 0,
		  "valid status renders");
	{
		struct lichen_rollcall_status parsed;

		ASSERT_EQ(lichen_rollcall_status_from_cbor(render,
							   render_len,
							   &parsed), 0,
			  "decode");
		ASSERT_EQ(parsed.responded_count, 1U, "one responded");
		ASSERT_EQ(parsed.responded[0].status,
			  LICHEN_CHECKIN_STATUS_DELAYED, "status kept");
	}
	return 1;
}

/* --- list encodings (oracle GET shapes) --- */

static int test_list_encode_shapes(void)
{
	static struct lichen_checkin_entry checkins[LICHEN_CHECKIN_MAX];
	static struct lichen_rollcall rollcalls[LICHEN_ROLLCALL_MAX];
	struct lichen_checkin_service svc;
	uint8_t buf[LICHEN_CHECKIN_CBOR_MAX + LICHEN_ROLLCALL_STATUS_CBOR_MAX];
	size_t len = 0U;

	lichen_checkin_service_init(&svc, checkins, LICHEN_CHECKIN_MAX,
				    rollcalls, LICHEN_ROLLCALL_MAX);

	/* Empty store: {"checkins": []} */
	static const uint8_t empty_checkins[] = {
		0xa1, 0x68, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x69,
		0x6e, 0x73, 0x80,
	};
	ASSERT_EQ(lichen_checkin_list_encode(&svc, buf, sizeof(buf), &len), 0,
		  "empty checkins encode");
	ASSERT_EQ(len, sizeof(empty_checkins), "empty checkins len");
	ASSERT_MEM_EQ(buf, empty_checkins, sizeof(empty_checkins),
		      "empty checkins bytes");

	/* Empty store: {"rollcalls": []} */
	static const uint8_t empty_rollcalls[] = {
		0xa1, 0x69, 0x72, 0x6f, 0x6c, 0x6c, 0x63, 0x61,
		0x6c, 0x6c, 0x73, 0x80,
	};
	ASSERT_EQ(lichen_rollcall_list_encode(&svc, buf, sizeof(buf), &len), 0,
		  "empty rollcalls encode");
	ASSERT_EQ(len, sizeof(empty_rollcalls), "empty rollcalls len");
	ASSERT_MEM_EQ(buf, empty_rollcalls, sizeof(empty_rollcalls),
		      "empty rollcalls bytes");

	/* One check-in: {"checkins": [<payload>]} */
	{
		struct lichen_checkin c;
		uint8_t wire[LICHEN_CHECKIN_CBOR_MAX];
		size_t wire_len;
		enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;

		lichen_checkin_service_set_time(&svc, 1716742800U);
		memset(&c, 0, sizeof(c));
		strcpy(c.node, "0200:0000:0000:0000:0011:2233:4455:6677");
		c.ts = 1716742800U;
		c.status = LICHEN_CHECKIN_STATUS_OK;
		ASSERT_EQ(lichen_checkin_to_cbor(&c, wire, sizeof(wire),
						 &wire_len), 0, "encode");
		ASSERT_EQ(lichen_checkin_post(&svc, wire, wire_len, &detail),
			  LICHEN_CHECKIN_CODE_CHANGED, "post");
		ASSERT_EQ(lichen_checkin_list_encode(&svc, buf, sizeof(buf),
						     &len), 0, "list encode");
		ASSERT_EQ(len, 10U + 1U + wire_len, "list wraps one item");
		ASSERT_MEM_EQ(buf, empty_checkins, 10U, "wrapper prefix");
		ASSERT_EQ(buf[10], 0x81, "array of one");
		ASSERT_MEM_EQ(&buf[11], wire, wire_len, "item bytes verbatim");
	}
	return 1;
}

/* --- scheduled check-in config (18.6.4) --- */

static int test_config_codec_and_due(void)
{
	static struct lichen_checkin_entry checkins[1];
	static struct lichen_rollcall rollcalls[1];
	struct lichen_checkin_service svc;
	struct lichen_checkin_config cfg;
	uint8_t wire[LICHEN_CHECKIN_CONFIG_CBOR_MAX];
	size_t wire_len;
	struct lichen_checkin_config parsed;

	/* Round-trip smoke (no oracle vectors exist for 18.6.4). */
	memset(&cfg, 0, sizeof(cfg));
	cfg.enabled = true;
	cfg.has_target = true;
	strcpy(cfg.target, "0200:0000:0000:0000:0000:0000:0000:0001");
	cfg.interval_s = 900U;
	cfg.include_location = true;
	ASSERT_EQ(lichen_checkin_config_to_cbor(&cfg, wire, sizeof(wire),
						&wire_len), 0, "encode");
	ASSERT_EQ(lichen_checkin_config_from_cbor(wire, wire_len, &parsed), 0,
		  "decode");
	ASSERT_EQ(parsed.enabled, true, "enabled");
	ASSERT_EQ(parsed.has_target, 1, "target present");
	ASSERT_STR_EQ(parsed.target, cfg.target, "target");
	ASSERT_EQ(parsed.interval_s, 900U, "interval");
	ASSERT_EQ(parsed.include_location, true, "include_location");

	lichen_checkin_service_init(&svc, checkins, 1U, rollcalls, 1U);
	lichen_checkin_config_apply(&svc, &cfg);

	lichen_checkin_service_set_time(&svc, 0U);
	ASSERT_EQ(lichen_checkin_due(&svc), false, "not due at t=0");
	lichen_checkin_service_set_time(&svc, 899U);
	ASSERT_EQ(lichen_checkin_due(&svc), false, "not due before interval");
	lichen_checkin_service_set_time(&svc, 900U);
	ASSERT_EQ(lichen_checkin_due(&svc), true, "due at interval");
	lichen_checkin_mark_sent(&svc);
	ASSERT_EQ(lichen_checkin_due(&svc), false, "not due after send");

	cfg.enabled = false;
	lichen_checkin_config_apply(&svc, &cfg);
	ASSERT_EQ(lichen_checkin_due(&svc), false, "disabled never due");
	return 1;
}

/* --- buffer bounds --- */

static int test_buffer_too_small(void)
{
	struct lichen_checkin c;
	uint8_t tiny[8];
	size_t len = 0U;

	memset(&c, 0, sizeof(c));
	strcpy(c.node, "0200:0000:0000:0000:0011:2233:4455:6677");
	c.ts = 1U;
	c.status = LICHEN_CHECKIN_STATUS_OK;
	ASSERT_EQ(lichen_checkin_to_cbor(&c, tiny, sizeof(tiny), &len),
		  -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL, "tiny buffer");
	return 1;
}

int main(void)
{
	RUN_TEST(test_constants_match_vectors);
	RUN_TEST(test_coord_bounds_from_vector);
	RUN_TEST(test_node_format_from_vector);
	RUN_TEST(test_status_values_from_vector);
	RUN_TEST(test_wire_vectors);
	RUN_TEST(test_vector_service_codes);
	RUN_TEST(test_checkin_capacity_prune_oldest);
	RUN_TEST(test_checkin_duplicate_node_updates);
	RUN_TEST(test_checkin_zero_capacity_store);
	RUN_TEST(test_rollcall_capacity_unavailable);
	RUN_TEST(test_rollcall_expiry_and_defaults);
	RUN_TEST(test_track_capacity_full);
	RUN_TEST(test_rollcall_invalid_status_rejected);
	RUN_TEST(test_list_encode_shapes);
	RUN_TEST(test_config_codec_and_due);
	RUN_TEST(test_buffer_too_small);

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
