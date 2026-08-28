/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file checkin.c
 * @brief Check-In / Roll Call codec and service (spec section 18.6)
 *
 * Wire format matches test/vectors/checkin_rollcall.json (canonical CBOR,
 * string keys, spec key order). Pure C11: no Zephyr, no allocation, no
 * recursion, no global state. All bounds are checked; text over-length
 * inputs are rejected rather than truncated.
 */

#include <lichen/checkin.h>

#include <errno.h>
#include <math.h>
#include <string.h>

/* ── Status helpers ────────────────────────────────────────────────────── */

static const char *const STATUS_STRINGS[] = {
	"ok",
	"help",
	"delayed",
};
#define STATUS_COUNT (sizeof(STATUS_STRINGS) / sizeof(STATUS_STRINGS[0]))

const char *lichen_checkin_status_str(enum lichen_checkin_status status)
{
	if ((size_t)status >= STATUS_COUNT) {
		return NULL;
	}
	return STATUS_STRINGS[status];
}

int lichen_checkin_status_parse(const char *str,
				enum lichen_checkin_status *status)
{
	for (size_t i = 0; i < STATUS_COUNT; i++) {
		if (strcmp(str, STATUS_STRINGS[i]) == 0) {
			*status = (enum lichen_checkin_status)i;
			return 0;
		}
	}
	return -LICHEN_CHECKIN_ERR_INVALID_STATUS;
}

int lichen_checkin_addr_valid(const char *addr)
{
	if (strlen(addr) != 39U) {
		return -LICHEN_CHECKIN_ERR_NODE_FORMAT;
	}

	for (size_t g = 0; g < 8U; g++) {
		for (size_t i = 0; i < 4U; i++) {
			char c = addr[g * 5U + i];

			if (!((c >= '0' && c <= '9') ||
			      (c >= 'a' && c <= 'f') ||
			      (c >= 'A' && c <= 'F'))) {
				return -LICHEN_CHECKIN_ERR_NODE_FORMAT;
			}
		}
		if (g < 7U && addr[g * 5U + 4U] != ':') {
			return -LICHEN_CHECKIN_ERR_NODE_FORMAT;
		}
	}
	return 0;
}

int lichen_checkin_coord_valid(double lat, double lon)
{
	if (!isfinite(lat) || !isfinite(lon)) {
		return -LICHEN_CHECKIN_ERR_COORD_RANGE;
	}
	if (lat < -LICHEN_CHECKIN_LAT_MAX || lat > LICHEN_CHECKIN_LAT_MAX) {
		return -LICHEN_CHECKIN_ERR_COORD_RANGE;
	}
	if (lon < -LICHEN_CHECKIN_LON_MAX || lon > LICHEN_CHECKIN_LON_MAX) {
		return -LICHEN_CHECKIN_ERR_COORD_RANGE;
	}
	return 0;
}

/* ── CBOR encoding helpers ─────────────────────────────────────────────── */

static size_t cbor_encode_header(uint8_t *buf, size_t cap,
				 uint8_t major, uint64_t n)
{
	uint8_t mt = (uint8_t)(major << 5);

	if (n < 24U) {
		if (cap < 1U) {
			return 0U;
		}
		buf[0] = mt | (uint8_t)n;
		return 1U;
	}
	if (n <= 0xffU) {
		if (cap < 2U) {
			return 0U;
		}
		buf[0] = mt | 24U;
		buf[1] = (uint8_t)n;
		return 2U;
	}
	if (n <= 0xffffU) {
		if (cap < 3U) {
			return 0U;
		}
		buf[0] = mt | 25U;
		buf[1] = (uint8_t)(n >> 8);
		buf[2] = (uint8_t)n;
		return 3U;
	}
	if (n <= 0xffffffffU) {
		if (cap < 5U) {
			return 0U;
		}
		buf[0] = mt | 26U;
		buf[1] = (uint8_t)(n >> 24);
		buf[2] = (uint8_t)(n >> 16);
		buf[3] = (uint8_t)(n >> 8);
		buf[4] = (uint8_t)n;
		return 5U;
	}
	if (cap < 9U) {
		return 0U;
	}
	buf[0] = mt | 27U;
	buf[1] = (uint8_t)(n >> 56);
	buf[2] = (uint8_t)(n >> 48);
	buf[3] = (uint8_t)(n >> 40);
	buf[4] = (uint8_t)(n >> 32);
	buf[5] = (uint8_t)(n >> 24);
	buf[6] = (uint8_t)(n >> 16);
	buf[7] = (uint8_t)(n >> 8);
	buf[8] = (uint8_t)n;
	return 9U;
}

static size_t cbor_encode_tstr(uint8_t *buf, size_t cap,
			       const char *str, size_t len)
{
	size_t hdr = cbor_encode_header(buf, cap, 3, (uint64_t)len);

	if (hdr == 0U) {
		return 0U;
	}
	if (cap - hdr < len) {
		return 0U;
	}
	memcpy(&buf[hdr], str, len);
	return hdr + len;
}

static size_t cbor_encode_double(uint8_t *buf, size_t cap, double value)
{
	uint64_t bits;

	if (cap < 9U) {
		return 0U;
	}
	memcpy(&bits, &value, sizeof(bits));
	/* Always the 8-byte float form (0xfb): the bits must never be
	 * shortened into a small simple-value header. */
	buf[0] = 0xfbU;
	for (unsigned int shift = 56U; shift != 0U; shift -= 8U) {
		buf[1U + (7U - shift / 8U)] = (uint8_t)(bits >> shift);
	}
	buf[8] = (uint8_t)bits;
	return 9U;
}

/* ── CBOR decoding helpers ─────────────────────────────────────────────── */

struct cbor_reader {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static bool cbor_reader_has(const struct cbor_reader *r, size_t n)
{
	return r->pos <= r->len && n <= r->len - r->pos;
}

static int cbor_read_header(struct cbor_reader *r, uint8_t *major,
			    uint64_t *value)
{
	uint8_t first;
	uint8_t ai;

	if (!cbor_reader_has(r, 1U)) {
		return LICHEN_CHECKIN_ERR_TRUNCATED;
	}

	first = r->buf[r->pos++];
	*major = (uint8_t)(first >> 5);
	ai = (uint8_t)(first & 0x1fU);

	if (ai < 24U) {
		*value = ai;
		return LICHEN_CHECKIN_OK;
	}
	if (ai == 24U) {
		if (!cbor_reader_has(r, 1U)) {
			return LICHEN_CHECKIN_ERR_TRUNCATED;
		}
		*value = r->buf[r->pos++];
		return LICHEN_CHECKIN_OK;
	}
	if (ai == 25U) {
		if (!cbor_reader_has(r, 2U)) {
			return LICHEN_CHECKIN_ERR_TRUNCATED;
		}
		*value = ((uint64_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1U];
		r->pos += 2U;
		return LICHEN_CHECKIN_OK;
	}
	if (ai == 26U) {
		if (!cbor_reader_has(r, 4U)) {
			return LICHEN_CHECKIN_ERR_TRUNCATED;
		}
		*value = ((uint64_t)r->buf[r->pos] << 24) |
			 ((uint64_t)r->buf[r->pos + 1U] << 16) |
			 ((uint64_t)r->buf[r->pos + 2U] << 8) |
			 r->buf[r->pos + 3U];
		r->pos += 4U;
		return LICHEN_CHECKIN_OK;
	}
	if (ai == 27U) {
		if (!cbor_reader_has(r, 8U)) {
			return LICHEN_CHECKIN_ERR_TRUNCATED;
		}
		*value = ((uint64_t)r->buf[r->pos] << 56) |
			 ((uint64_t)r->buf[r->pos + 1U] << 48) |
			 ((uint64_t)r->buf[r->pos + 2U] << 40) |
			 ((uint64_t)r->buf[r->pos + 3U] << 32) |
			 ((uint64_t)r->buf[r->pos + 4U] << 24) |
			 ((uint64_t)r->buf[r->pos + 5U] << 16) |
			 ((uint64_t)r->buf[r->pos + 6U] << 8) |
			 r->buf[r->pos + 7U];
		r->pos += 8U;
		return LICHEN_CHECKIN_OK;
	}
	return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
}

/**
 * @brief Read a text string into a fixed buffer.
 *
 * @param out      Output buffer
 * @param out_max  Buffer size including NUL
 * @param long_err Error to return when the string exceeds out_max - 1
 * @return 0 or an error code
 */
static int cbor_read_tstr(struct cbor_reader *r, char *out, size_t out_max,
			  int long_err)
{
	uint8_t major;
	uint64_t len;
	int err = cbor_read_header(r, &major, &len);

	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 3U) {
		return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
	}
	if (!cbor_reader_has(r, (size_t)len)) {
		return LICHEN_CHECKIN_ERR_TRUNCATED;
	}
	if (len >= (uint64_t)out_max) {
		return long_err;
	}
	memcpy(out, &r->buf[r->pos], (size_t)len);
	out[len] = '\0';
	r->pos += (size_t)len;
	return LICHEN_CHECKIN_OK;
}

static int cbor_read_uint(struct cbor_reader *r, uint64_t *value)
{
	uint8_t major;
	int err = cbor_read_header(r, &major, value);

	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 0U) {
		return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
	}
	return LICHEN_CHECKIN_OK;
}

/**
 * @brief Read a numeric value that may be uint, negative int, float32, or
 *        float64 (per the Python oracle's int/float acceptance for
 *        coordinates). Bools, half floats, and other scalars are rejected.
 */
static int cbor_read_number(struct cbor_reader *r, double *value)
{
	uint8_t major;
	uint8_t ai;
	uint64_t raw;
	int err;

	if (!cbor_reader_has(r, 1U)) {
		return LICHEN_CHECKIN_ERR_TRUNCATED;
	}

	ai = (uint8_t)(r->buf[r->pos] & 0x1fU);

	err = cbor_read_header(r, &major, &raw);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major == 0U) {
		*value = (double)raw;
		return LICHEN_CHECKIN_OK;
	}
	if (major == 1U) {
		if (raw == UINT64_MAX) {
			return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
		}
		*value = -(double)(raw + 1U);
		return LICHEN_CHECKIN_OK;
	}
	if (major == 7U && ai == 26U) {
		uint32_t bits = (uint32_t)raw;
		float f;

		memcpy(&f, &bits, sizeof(f));
		*value = (double)f;
		return LICHEN_CHECKIN_OK;
	}
	if (major == 7U && ai == 27U) {
		memcpy(value, &raw, sizeof(*value));
		return LICHEN_CHECKIN_OK;
	}
	return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
}

static int cbor_read_bool(struct cbor_reader *r, bool *value)
{
	if (!cbor_reader_has(r, 1U)) {
		return LICHEN_CHECKIN_ERR_TRUNCATED;
	}

	switch (r->buf[r->pos]) {
	case 0xf4U:
		*value = false;
		r->pos++;
		return LICHEN_CHECKIN_OK;
	case 0xf5U:
		*value = true;
		r->pos++;
		return LICHEN_CHECKIN_OK;
	default:
		return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
	}
}

/**
 * @brief Decimal-encode a uint64 into dst (NUL-terminated, no padding).
 * @return Length written, or 0 if dst is too small.
 */
static size_t u64_to_dec(uint64_t value, char *dst, size_t cap)
{
	char tmp[20];
	size_t n = 0;
	size_t total;

	do {
		tmp[n++] = (char)('0' + (int)(value % 10U));
		value /= 10U;
	} while (value != 0U && n < sizeof(tmp));

	total = n;
	if (total + 1U > cap) {
		return 0U;
	}
	for (size_t i = 0; i < n; i++) {
		dst[i] = tmp[n - 1U - i];
	}
	dst[n] = '\0';
	return n;
}

static size_t u64_dec_len(uint64_t value)
{
	size_t n = 1U;

	while (value >= 10U) {
		value /= 10U;
		n++;
	}
	return n;
}

/**
 * @brief Format a signed integer id (uint or negative) into dst.
 * @return Length, or 0 if dst too small.
 */
static size_t id_to_str(int64_t value, char *dst, size_t cap)
{
	uint64_t magnitude;
	size_t total;

	if (value >= 0) {
		return u64_to_dec((uint64_t)value, dst, cap);
	}
	if (value == INT64_MIN) {
		magnitude = (uint64_t)INT64_MAX + 1U;
	} else {
		magnitude = (uint64_t)(-(value + 1)) + 1U;
	}
	total = u64_dec_len(magnitude) + 1U;
	if (total + 1U > cap) {
		return 0U;
	}
	dst[0] = '-';
	(void)u64_to_dec(magnitude, &dst[1], cap - 1U);
	return total;
}

/* ── Check-in codec (18.6.1) ───────────────────────────────────────────── */

int lichen_checkin_to_cbor(const struct lichen_checkin *c,
			   uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;
	size_t fields = 3U + (c->has_location ? 2U : 0U) + (c->has_msg ? 1U : 0U);
	size_t node_len = strlen(c->node);
	size_t status_len = strlen(lichen_checkin_status_str(c->status) == NULL
				  ? "" : lichen_checkin_status_str(c->status));

	if (lichen_checkin_status_str(c->status) == NULL) {
		return -LICHEN_CHECKIN_ERR_INVALID_STATUS;
	}

	n = cbor_encode_header(p, rem, 5, fields);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "node", 4U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, c->node, node_len);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "ts", 2U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 0, c->ts);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	if (c->has_location) {
		n = cbor_encode_tstr(p, rem, "lat", 3U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_double(p, rem, c->lat);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "lon", 3U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_double(p, rem, c->lon);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	n = cbor_encode_tstr(p, rem, "status", 6U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, lichen_checkin_status_str(c->status),
			     status_len);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	if (c->has_msg) {
		n = cbor_encode_tstr(p, rem, "msg", 3U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, c->msg, strlen(c->msg));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

/**
 * @brief Field flags for duplicate-key detection.
 */
struct checkin_seen {
	bool node;
	bool ts;
	bool lat;
	bool lon;
	bool status;
	bool msg;
};

int lichen_checkin_from_cbor(const uint8_t *buf, size_t len,
			     struct lichen_checkin *c)
{
	struct cbor_reader r = { buf, len, 0U };
	struct checkin_seen seen = { false, false, false, false, false, false };
	uint8_t major;
	uint64_t count;
	int err;

	memset(c, 0, sizeof(*c));

	err = cbor_read_header(&r, &major, &count);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 5U) {
		return LICHEN_CHECKIN_ERR_NOT_A_MAP;
	}

	for (uint64_t i = 0; i < count; i++) {
		char key[24];

		err = cbor_read_tstr(&r, key, sizeof(key),
				     LICHEN_CHECKIN_ERR_UNKNOWN_KEY);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}

		if (strcmp(key, "node") == 0) {
			if (seen.node) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.node = true;
			err = cbor_read_tstr(&r, c->node, sizeof(c->node),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "ts") == 0) {
			if (seen.ts) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.ts = true;
			err = cbor_read_uint(&r, &c->ts);
			if (err != LICHEN_CHECKIN_OK) {
				if (err == LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE) {
					return LICHEN_CHECKIN_ERR_INVALID_TS;
				}
				return err;
			}
		} else if (strcmp(key, "lat") == 0) {
			if (seen.lat) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.lat = true;
			err = cbor_read_number(&r, &c->lat);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			c->has_location = true;
		} else if (strcmp(key, "lon") == 0) {
			if (seen.lon) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.lon = true;
			err = cbor_read_number(&r, &c->lon);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			c->has_location = true;
		} else if (strcmp(key, "status") == 0) {
			char value[16];

			if (seen.status) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.status = true;
			err = cbor_read_tstr(&r, value, sizeof(value),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			err = lichen_checkin_status_parse(value, &c->status);
			if (err != LICHEN_CHECKIN_OK) {
				return LICHEN_CHECKIN_ERR_INVALID_STATUS;
			}
		} else if (strcmp(key, "msg") == 0) {
			if (seen.msg) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.msg = true;
			err = cbor_read_tstr(&r, c->msg, sizeof(c->msg),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			c->has_msg = true;
		} else {
			return LICHEN_CHECKIN_ERR_UNKNOWN_KEY;
		}
	}

	if (r.pos != r.len) {
		return LICHEN_CHECKIN_ERR_TRAILING_DATA;
	}

	if (!seen.node) {
		return LICHEN_CHECKIN_ERR_MISSING_NODE;
	}
	if (!seen.ts) {
		return LICHEN_CHECKIN_ERR_MISSING_TS;
	}
	if (!seen.status) {
		return LICHEN_CHECKIN_ERR_MISSING_STATUS;
	}
	if ((seen.lat != seen.lon)) {
		return LICHEN_CHECKIN_ERR_COORD_PAIR;
	}
	if (seen.lat && lichen_checkin_coord_valid(c->lat, c->lon) != 0) {
		return LICHEN_CHECKIN_ERR_COORD_RANGE;
	}
	if (lichen_checkin_addr_valid(c->node) != 0) {
		return LICHEN_CHECKIN_ERR_NODE_FORMAT;
	}
	return LICHEN_CHECKIN_OK;
}

/* ── Roll-call request codec (18.6.2) ──────────────────────────────────── */

int lichen_rollcall_req_to_cbor(const struct lichen_rollcall_req *r,
				uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;
	size_t fields = 1U + (r->has_from ? 1U : 0U) +
			(r->has_ts ? 1U : 0U) + (r->has_timeout ? 1U : 0U);

	n = cbor_encode_header(p, rem, 5, (uint64_t)fields);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "id", 2U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, r->id, strlen(r->id));
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	if (r->has_from) {
		n = cbor_encode_tstr(p, rem, "from", 4U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, r->from, strlen(r->from));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	if (r->has_ts) {
		n = cbor_encode_tstr(p, rem, "ts", 2U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_header(p, rem, 0, r->ts);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	if (r->has_timeout) {
		n = cbor_encode_tstr(p, rem, "timeout_s", 9U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_header(p, rem, 0, (uint64_t)r->timeout_s);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

struct rollcall_req_seen {
	bool id;
	bool from;
	bool ts;
	bool timeout;
};

/**
 * @brief Read and coerce a roll-call id (tstr, uint, or negative int).
 */
static int rollcall_read_id(struct cbor_reader *r, char *id, size_t cap)
{
	uint8_t major;
	uint64_t n;
	int err;

	if (!cbor_reader_has(r, 1U)) {
		return LICHEN_CHECKIN_ERR_TRUNCATED;
	}

	if ((r->buf[r->pos] >> 5) == 3U) {
		return cbor_read_tstr(r, id, cap,
				      LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
	}

	err = cbor_read_header(r, &major, &n);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major == 0U) {
		if (u64_to_dec(n, id, cap) == 0U) {
			return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
		}
		return LICHEN_CHECKIN_OK;
	}
	if (major == 1U) {
		if (n >= (uint64_t)INT64_MAX) {
			return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
		}
		if (id_to_str(-(int64_t)(n + 1U), id, cap) == 0U) {
			return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
		}
		return LICHEN_CHECKIN_OK;
	}
	return LICHEN_CHECKIN_ERR_INVALID_ID;
}

int lichen_rollcall_req_from_cbor(const uint8_t *buf, size_t len,
				  struct lichen_rollcall_req *r_out)
{
	struct cbor_reader r = { buf, len, 0U };
	struct rollcall_req_seen seen = { false, false, false, false };
	uint8_t major;
	uint64_t count;
	int err;

	memset(r_out, 0, sizeof(*r_out));

	err = cbor_read_header(&r, &major, &count);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 5U) {
		return LICHEN_CHECKIN_ERR_NOT_A_MAP;
	}

	for (uint64_t i = 0; i < count; i++) {
		char key[16];

		err = cbor_read_tstr(&r, key, sizeof(key),
				     LICHEN_CHECKIN_ERR_UNKNOWN_KEY);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}

		if (strcmp(key, "id") == 0) {
			if (seen.id) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.id = true;
			err = rollcall_read_id(&r, r_out->id,
					       sizeof(r_out->id));
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "from") == 0) {
			if (seen.from) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.from = true;
			err = cbor_read_tstr(&r, r_out->from,
					     sizeof(r_out->from),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			r_out->has_from = true;
		} else if (strcmp(key, "ts") == 0) {
			if (seen.ts) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.ts = true;
			err = cbor_read_uint(&r, &r_out->ts);
			if (err != LICHEN_CHECKIN_OK) {
				if (err == LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE) {
					return LICHEN_CHECKIN_ERR_INVALID_TS;
				}
				return err;
			}
			r_out->has_ts = true;
		} else if (strcmp(key, "timeout_s") == 0) {
			uint64_t timeout;

			if (seen.timeout) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.timeout = true;
			err = cbor_read_uint(&r, &timeout);
			if (err != LICHEN_CHECKIN_OK) {
				if (err == LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE) {
					return LICHEN_CHECKIN_ERR_INVALID_TIMEOUT;
				}
				return err;
			}
			if (timeout == 0U) {
				return LICHEN_CHECKIN_ERR_INVALID_TIMEOUT;
			}
			if (timeout > (uint64_t)LICHEN_ROLLCALL_TIMEOUT_MAX_S) {
				return LICHEN_CHECKIN_ERR_TIMEOUT_MAX;
			}
			r_out->timeout_s = (uint32_t)timeout;
			r_out->has_timeout = true;
		} else {
			return LICHEN_CHECKIN_ERR_UNKNOWN_KEY;
		}
	}

	if (r.pos != r.len) {
		return LICHEN_CHECKIN_ERR_TRAILING_DATA;
	}
	if (!seen.id) {
		return LICHEN_CHECKIN_ERR_MISSING_ID;
	}
	return LICHEN_CHECKIN_OK;
}

/* ── Roll-call status codec (18.6.3) ───────────────────────────────────── */

struct rollcall_status_seen {
	bool id;
	bool started;
	bool timeout;
	bool responded;
	bool missing;
};

/**
 * @brief Read one responded/missing track entry.
 */
static int rollcall_read_track(struct cbor_reader *r,
			       struct lichen_rollcall_track *track,
			       bool responded)
{
	uint8_t major;
	uint64_t count;
	char key[16];
	char status_str[16];
	bool have_node = false;
	bool have_ts = false;
	bool have_status = false;
	int err;

	err = cbor_read_header(r, &major, &count);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 5U) {
		return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
	}

	for (uint64_t i = 0; i < count; i++) {
		err = cbor_read_tstr(r, key, sizeof(key),
				     LICHEN_CHECKIN_ERR_UNKNOWN_KEY);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}

		if (strcmp(key, "node") == 0) {
			if (have_node) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			have_node = true;
			err = cbor_read_tstr(r, track->node,
					     sizeof(track->node),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "ts") == 0 && responded) {
			if (have_ts) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			have_ts = true;
			err = cbor_read_uint(r, &track->ts);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "last_seen") == 0 && !responded) {
			if (have_ts) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			have_ts = true;
			err = cbor_read_uint(r, &track->ts);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "status") == 0 && responded) {
			if (have_status) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			have_status = true;
			err = cbor_read_tstr(r, status_str,
					     sizeof(status_str),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			err = lichen_checkin_status_parse(status_str,
							  &track->status);
			if (err != LICHEN_CHECKIN_OK) {
				return LICHEN_CHECKIN_ERR_INVALID_STATUS;
			}
		} else {
			return LICHEN_CHECKIN_ERR_UNKNOWN_KEY;
		}
	}

	if (!have_node || !have_ts || (responded && !have_status)) {
		return LICHEN_CHECKIN_ERR_MISSING_FIELD;
	}
	return LICHEN_CHECKIN_OK;
}

/**
 * @brief Read a responded/missing array into its fixed-capacity store.
 */
static int rollcall_read_tracks(struct cbor_reader *r,
				struct lichen_rollcall_track *tracks,
				size_t max, size_t *count, bool responded)
{
	uint8_t major;
	uint64_t n;
	int err;

	err = cbor_read_header(r, &major, &n);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 4U) {
		return LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE;
	}
	if (n > (uint64_t)max) {
		return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
	}

	for (uint64_t i = 0; i < n; i++) {
		err = rollcall_read_track(r, &tracks[*count], responded);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}
		(*count)++;
	}
	return LICHEN_CHECKIN_OK;
}

int lichen_rollcall_status_from_cbor(const uint8_t *buf, size_t len,
				     struct lichen_rollcall_status *s)
{
	struct cbor_reader r = { buf, len, 0U };
	struct rollcall_status_seen seen = { false, false, false,
					     false, false };
	uint8_t major;
	uint64_t count;
	int err;

	memset(s, 0, sizeof(*s));

	err = cbor_read_header(&r, &major, &count);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 5U) {
		return LICHEN_CHECKIN_ERR_NOT_A_MAP;
	}

	for (uint64_t i = 0; i < count; i++) {
		char key[16];

		err = cbor_read_tstr(&r, key, sizeof(key),
				     LICHEN_CHECKIN_ERR_UNKNOWN_KEY);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}

		if (strcmp(key, "id") == 0) {
			if (seen.id) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.id = true;
			err = cbor_read_tstr(&r, s->id, sizeof(s->id),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "started") == 0) {
			if (seen.started) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.started = true;
			err = cbor_read_uint(&r, &s->started);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "timeout_s") == 0) {
			uint64_t timeout;

			if (seen.timeout) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.timeout = true;
			err = cbor_read_uint(&r, &timeout);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			if (timeout == 0U ||
			    timeout > (uint64_t)LICHEN_ROLLCALL_TIMEOUT_MAX_S) {
				return LICHEN_CHECKIN_ERR_INVALID_TIMEOUT;
			}
			s->timeout_s = (uint32_t)timeout;
		} else if (strcmp(key, "responded") == 0) {
			if (seen.responded) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.responded = true;
			err = rollcall_read_tracks(&r, s->responded,
						   LICHEN_ROLLCALL_TRACK_MAX,
						   &s->responded_count, true);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "missing") == 0) {
			if (seen.missing) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.missing = true;
			err = rollcall_read_tracks(&r, s->missing,
						   LICHEN_ROLLCALL_TRACK_MAX,
						   &s->missing_count, false);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else {
			return LICHEN_CHECKIN_ERR_UNKNOWN_KEY;
		}
	}

	if (r.pos != r.len) {
		return LICHEN_CHECKIN_ERR_TRAILING_DATA;
	}
	if (!seen.id) {
		return LICHEN_CHECKIN_ERR_MISSING_ID;
	}
	if (!seen.started || !seen.timeout) {
		return LICHEN_CHECKIN_ERR_MISSING_FIELD;
	}
	return LICHEN_CHECKIN_OK;
}

int lichen_rollcall_status_to_cbor(const struct lichen_rollcall_status *s,
				   uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;

	n = cbor_encode_header(p, rem, 5, 5U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "id", 2U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, s->id, strlen(s->id));
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "started", 7U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 0, s->started);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "timeout_s", 9U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 0, (uint64_t)s->timeout_s);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "responded", 9U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 4, (uint64_t)s->responded_count);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	for (size_t i = 0; i < s->responded_count; i++) {
		const struct lichen_rollcall_track *t = &s->responded[i];
		const char *status_str = lichen_checkin_status_str(t->status);

		if (status_str == NULL) {
			return -LICHEN_CHECKIN_ERR_INVALID_STATUS;
		}

		n = cbor_encode_header(p, rem, 5, 3U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "node", 4U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, t->node, strlen(t->node));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "ts", 2U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_header(p, rem, 0, t->ts);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "status", 6U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, status_str, strlen(status_str));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	n = cbor_encode_tstr(p, rem, "missing", 7U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 4, (uint64_t)s->missing_count);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	for (size_t i = 0; i < s->missing_count; i++) {
		const struct lichen_rollcall_track *t = &s->missing[i];

		n = cbor_encode_header(p, rem, 5, 2U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "node", 4U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, t->node, strlen(t->node));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, "last_seen", 9U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_header(p, rem, 0, t->ts);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

/* ── Scheduled check-in config codec (18.6.4) ──────────────────────────── */

int lichen_checkin_config_to_cbor(const struct lichen_checkin_config *cfg,
				  uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;
	size_t fields = 1U + (cfg->has_target ? 1U : 0U) + 1U +
			1U; /* enabled, target, interval_s, include_location */

	n = cbor_encode_header(p, rem, 5, (uint64_t)fields);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "enabled", 7U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	if (cap - (size_t)(p - buf) < 1U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	*p = cfg->enabled ? 0xf5U : 0xf4U;
	p++;
	rem--;

	if (cfg->has_target) {
		n = cbor_encode_tstr(p, rem, "target", 6U);
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;

		n = cbor_encode_tstr(p, rem, cfg->target, strlen(cfg->target));
		if (n == 0U) {
			return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
		}
		p += n;
		rem -= n;
	}

	n = cbor_encode_tstr(p, rem, "interval_s", 10U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 0, (uint64_t)cfg->interval_s);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "include_location", 16U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	if (rem < 1U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	*p = cfg->include_location ? 0xf5U : 0xf4U;
	p++;

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

struct config_seen {
	bool enabled;
	bool target;
	bool interval;
	bool include_location;
};

int lichen_checkin_config_from_cbor(const uint8_t *buf, size_t len,
				    struct lichen_checkin_config *cfg)
{
	struct cbor_reader r = { buf, len, 0U };
	struct config_seen seen = { false, false, false, false };
	uint8_t major;
	uint64_t count;
	int err;

	memset(cfg, 0, sizeof(*cfg));

	err = cbor_read_header(&r, &major, &count);
	if (err != LICHEN_CHECKIN_OK) {
		return err;
	}
	if (major != 5U) {
		return LICHEN_CHECKIN_ERR_NOT_A_MAP;
	}

	for (uint64_t i = 0; i < count; i++) {
		char key[24];

		err = cbor_read_tstr(&r, key, sizeof(key),
				     LICHEN_CHECKIN_ERR_UNKNOWN_KEY);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}

		if (strcmp(key, "enabled") == 0) {
			if (seen.enabled) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.enabled = true;
			err = cbor_read_bool(&r, &cfg->enabled);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else if (strcmp(key, "target") == 0) {
			if (seen.target) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.target = true;
			err = cbor_read_tstr(&r, cfg->target,
					     sizeof(cfg->target),
					     LICHEN_CHECKIN_ERR_OUT_OF_RANGE);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			cfg->has_target = true;
		} else if (strcmp(key, "interval_s") == 0) {
			uint64_t interval;

			if (seen.interval) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.interval = true;
			err = cbor_read_uint(&r, &interval);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
			if (interval > (uint64_t)UINT32_MAX) {
				return LICHEN_CHECKIN_ERR_OUT_OF_RANGE;
			}
			cfg->interval_s = (uint32_t)interval;
		} else if (strcmp(key, "include_location") == 0) {
			if (seen.include_location) {
				return LICHEN_CHECKIN_ERR_DUPLICATE_KEY;
			}
			seen.include_location = true;
			err = cbor_read_bool(&r, &cfg->include_location);
			if (err != LICHEN_CHECKIN_OK) {
				return err;
			}
		} else {
			return LICHEN_CHECKIN_ERR_UNKNOWN_KEY;
		}
	}

	if (r.pos != r.len) {
		return LICHEN_CHECKIN_ERR_TRAILING_DATA;
	}
	if (cfg->has_target && lichen_checkin_addr_valid(cfg->target) != 0) {
		return LICHEN_CHECKIN_ERR_NODE_FORMAT;
	}
	return LICHEN_CHECKIN_OK;
}

/* ── Service (18.6.1–18.6.4) ───────────────────────────────────────────── */

void lichen_checkin_service_init(struct lichen_checkin_service *svc,
				 struct lichen_checkin_entry *checkins,
				 size_t checkin_cap,
				 struct lichen_rollcall *rollcalls,
				 size_t rollcall_cap)
{
	memset(svc, 0, sizeof(*svc));
	svc->checkins = checkins;
	svc->checkin_cap = checkin_cap;
	svc->rollcalls = rollcalls;
	svc->rollcall_cap = rollcall_cap;
}

void lichen_checkin_service_set_time(struct lichen_checkin_service *svc,
				     uint64_t now)
{
	svc->now = now;
}

uint8_t lichen_checkin_post(struct lichen_checkin_service *svc,
			    const uint8_t *buf, size_t len,
			    enum lichen_checkin_error *detail)
{
	struct lichen_checkin decoded;
	struct lichen_checkin_entry *entry = NULL;
	size_t oldest = 0U;
	int err;

	if (detail != NULL) {
		*detail = LICHEN_CHECKIN_OK;
	}

	err = lichen_checkin_from_cbor(buf, len, &decoded);
	if (err != LICHEN_CHECKIN_OK) {
		if (detail != NULL) {
			*detail = (enum lichen_checkin_error)err;
		}
		return LICHEN_CHECKIN_CODE_BAD_REQUEST;
	}

	for (size_t i = 0; i < svc->checkin_count; i++) {
		if (strcmp(svc->checkins[i].checkin.node, decoded.node) == 0) {
			entry = &svc->checkins[i];
			break;
		}
	}

	if (entry == NULL && svc->checkin_cap == 0U) {
		/* NULL store with cap 0 is documented-legal (checkin.h);
		 * fail closed like the roll-call capacity policy (5.03)
		 * instead of indexing a NULL store. */
		return LICHEN_CHECKIN_CODE_UNAVAILABLE;
	}

	if (entry == NULL && svc->checkin_count >= svc->checkin_cap) {
		/* Evict the entry with the smallest ts (first minimal). */
		for (size_t i = 1U; i < svc->checkin_count; i++) {
			if (svc->checkins[i].checkin.ts <
			    svc->checkins[oldest].checkin.ts) {
				oldest = i;
			}
		}
		entry = &svc->checkins[oldest];
		svc->checkin_count--;
		memmove(&svc->checkins[oldest], &svc->checkins[oldest + 1U],
			(svc->checkin_count - oldest) *
			sizeof(svc->checkins[0]));
		entry = NULL;
	}

	if (entry == NULL) {
		entry = &svc->checkins[svc->checkin_count++];
	}

	entry->checkin = decoded;
	entry->received_at = svc->now;
	return LICHEN_CHECKIN_CODE_CHANGED;
}

/**
 * @brief Remove roll calls whose timeout has elapsed (strictly past).
 *
 * Signed-safe: a roll call started slightly in the future (within the
 * far-future slack) is never treated as expired via unsigned wraparound.
 */
static void rollcall_prune_expired(struct lichen_checkin_service *svc)
{
	size_t i = 0U;

	while (i < svc->rollcall_count) {
		struct lichen_rollcall *rc = &svc->rollcalls[i];

		if (svc->now > rc->started &&
		    svc->now - rc->started > (uint64_t)rc->timeout_s) {
			memmove(&svc->rollcalls[i], &svc->rollcalls[i + 1U],
				(svc->rollcall_count - i - 1U) *
				sizeof(svc->rollcalls[0]));
			svc->rollcall_count--;
		} else {
			i++;
		}
	}
}

uint8_t lichen_rollcall_post(struct lichen_checkin_service *svc,
			     const uint8_t *buf, size_t len,
			     enum lichen_checkin_error *detail)
{
	struct lichen_rollcall_req req;
	struct lichen_rollcall *rc = NULL;
	uint64_t started;
	uint32_t timeout_s;
	int err;

	if (detail != NULL) {
		*detail = LICHEN_CHECKIN_OK;
	}

	err = lichen_rollcall_req_from_cbor(buf, len, &req);
	if (err != LICHEN_CHECKIN_OK) {
		if (detail != NULL) {
			*detail = (enum lichen_checkin_error)err;
		}
		return LICHEN_CHECKIN_CODE_BAD_REQUEST;
	}

	if (req.has_ts && req.ts > svc->now + LICHEN_ROLLCALL_FUTURE_SLACK_S) {
		if (detail != NULL) {
			*detail = LICHEN_CHECKIN_ERR_TS_FUTURE;
		}
		return LICHEN_CHECKIN_CODE_BAD_REQUEST;
	}

	rollcall_prune_expired(svc);

	for (size_t i = 0; i < svc->rollcall_count; i++) {
		if (strcmp(svc->rollcalls[i].id, req.id) == 0) {
			rc = &svc->rollcalls[i];
			break;
		}
	}

	if (rc == NULL && svc->rollcall_count >= svc->rollcall_cap) {
		return LICHEN_CHECKIN_CODE_UNAVAILABLE;
	}

	started = req.has_ts ? req.ts : svc->now;
	timeout_s = req.has_timeout ? req.timeout_s
				    : LICHEN_ROLLCALL_TIMEOUT_DEFAULT_S;

	if (rc == NULL) {
		rc = &svc->rollcalls[svc->rollcall_count++];
		memset(rc, 0, sizeof(*rc));
		strcpy(rc->id, req.id);
	}
	rc->started = started;
	rc->timeout_s = timeout_s;
	rc->responded_count = 0U;
	rc->missing_count = 0U;

	return LICHEN_CHECKIN_CODE_CREATED;
}

struct lichen_rollcall *lichen_rollcall_find(struct lichen_checkin_service *svc,
					     const char *id)
{
	rollcall_prune_expired(svc);

	for (size_t i = 0; i < svc->rollcall_count; i++) {
		if (strcmp(svc->rollcalls[i].id, id) == 0) {
			return &svc->rollcalls[i];
		}
	}
	return NULL;
}

/**
 * @brief Move a track between the responded and missing lists.
 */
static int rollcall_move_track(struct lichen_rollcall_track *dst,
			       size_t *dst_count, size_t dst_max,
			       struct lichen_rollcall_track *other,
			       size_t *other_count,
			       const struct lichen_rollcall_track *track)
{
	/* Remove an existing entry from the other list (preserve order). */
	for (size_t i = 0; i < *other_count; i++) {
		if (strcmp(other[i].node, track->node) == 0) {
			memmove(&other[i], &other[i + 1U],
				(*other_count - i - 1U) * sizeof(other[0]));
			(*other_count)--;
			break;
		}
	}

	/* Update or append in the destination list. */
	for (size_t i = 0; i < *dst_count; i++) {
		if (strcmp(dst[i].node, track->node) == 0) {
			dst[i] = *track;
			return 0;
		}
	}
	if (*dst_count >= dst_max) {
		return -ENOSPC;
	}
	dst[*dst_count] = *track;
	(*dst_count)++;
	return 0;
}

int lichen_rollcall_record_responded(struct lichen_rollcall *rc,
				     const struct lichen_rollcall_track *track)
{
	/* A track may move back to responded later, where its status is
	 * rendered; reject out-of-range values at the public entry. */
	if (lichen_checkin_status_str(track->status) == NULL) {
		return -LICHEN_CHECKIN_ERR_INVALID_STATUS;
	}
	return rollcall_move_track(rc->responded, &rc->responded_count,
				   LICHEN_ROLLCALL_TRACK_MAX,
				   rc->missing, &rc->missing_count, track);
}

int lichen_rollcall_record_missing(struct lichen_rollcall *rc,
				   const struct lichen_rollcall_track *track)
{
	if (lichen_checkin_status_str(track->status) == NULL) {
		return -LICHEN_CHECKIN_ERR_INVALID_STATUS;
	}
	return rollcall_move_track(rc->missing, &rc->missing_count,
				   LICHEN_ROLLCALL_TRACK_MAX,
				   rc->responded, &rc->responded_count, track);
}

int lichen_rollcall_render(const struct lichen_rollcall *rc,
			   uint8_t *buf, size_t cap, size_t *out_len)
{
	struct lichen_rollcall_status s;

	memset(&s, 0, sizeof(s));
	memcpy(s.id, rc->id, sizeof(s.id));
	s.started = rc->started;
	s.timeout_s = rc->timeout_s;
	memcpy(s.responded, rc->responded, sizeof(rc->responded));
	s.responded_count = rc->responded_count;
	memcpy(s.missing, rc->missing, sizeof(rc->missing));
	s.missing_count = rc->missing_count;

	return lichen_rollcall_status_to_cbor(&s, buf, cap, out_len);
}

int lichen_checkin_list_encode(const struct lichen_checkin_service *svc,
			       uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;
	int err;

	n = cbor_encode_header(p, rem, 5, 1U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "checkins", 8U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 4, (uint64_t)svc->checkin_count);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	for (size_t i = 0; i < svc->checkin_count; i++) {
		size_t item_len = 0U;

		err = lichen_checkin_to_cbor(&svc->checkins[i].checkin, p, rem,
					     &item_len);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}
		p += item_len;
		rem -= item_len;
	}

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

int lichen_rollcall_list_encode(const struct lichen_checkin_service *svc,
				uint8_t *buf, size_t cap, size_t *out_len)
{
	uint8_t *p = buf;
	size_t rem = cap;
	size_t n;
	int err;

	n = cbor_encode_header(p, rem, 5, 1U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_tstr(p, rem, "rollcalls", 9U);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	n = cbor_encode_header(p, rem, 4, (uint64_t)svc->rollcall_count);
	if (n == 0U) {
		return -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL;
	}
	p += n;
	rem -= n;

	for (size_t i = 0; i < svc->rollcall_count; i++) {
		size_t item_len = 0U;

		err = lichen_rollcall_render(&svc->rollcalls[i], p, rem,
					     &item_len);
		if (err != LICHEN_CHECKIN_OK) {
			return err;
		}
		p += item_len;
		rem -= item_len;
	}

	*out_len = (size_t)(p - buf);
	return LICHEN_CHECKIN_OK;
}

void lichen_checkin_config_apply(struct lichen_checkin_service *svc,
				 const struct lichen_checkin_config *cfg)
{
	svc->config = *cfg;
}

bool lichen_checkin_due(const struct lichen_checkin_service *svc)
{
	if (!svc->config.enabled || !svc->config.has_target ||
	    svc->config.interval_s == 0U) {
		return false;
	}
	return svc->now - svc->last_checkin_at >=
	       (uint64_t)svc->config.interval_s;
}

void lichen_checkin_mark_sent(struct lichen_checkin_service *svc)
{
	svc->last_checkin_at = svc->now;
}
