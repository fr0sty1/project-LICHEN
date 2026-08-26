/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sos_alert.c
 * @brief SOS alert CBOR encoding (spec section 18.4.2)
 *
 * Implements CBOR encoding/decoding for SOS alert payloads.
 * Wire format matches test/vectors/sos_cbor.json.
 */

#include <lichen/sos_alert.h>
#include <string.h>
#include <limits.h>
#include <math.h>

/* Alert type wire strings */
static const char *const ALERT_TYPE_STRINGS[] = {
	"sos",
	"medical",
	"security",
	"fire",
	"cancel",
};

/* CBOR map key strings */
static const char KEY_TYPE[] = "type";
static const char KEY_NODE[] = "node";
static const char KEY_TS[] = "ts";
static const char KEY_LAT[] = "lat";
static const char KEY_LON[] = "lon";
static const char KEY_MSG[] = "msg";
static const char KEY_SEQ[] = "seq";

/*
 * CBOR encoding helpers (inline, no external dependencies).
 * Major types per RFC 8949:
 *   0: unsigned integer
 *   2: byte string
 *   3: text string
 *   5: map
 *   7: floating-point / simple
 */

/**
 * @brief Encode CBOR type and length header.
 * @return Bytes written, or 0 if buffer too small.
 */
static size_t cbor_encode_header(uint8_t *buf, size_t buf_len, uint8_t major, uint64_t n)
{
	uint8_t mt = (uint8_t)(major << 5);

	if (n < 24) {
		if (buf_len < 1) return 0;
		buf[0] = mt | (uint8_t)n;
		return 1;
	}
	if (n <= 0xff) {
		if (buf_len < 2) return 0;
		buf[0] = mt | 24;
		buf[1] = (uint8_t)n;
		return 2;
	}
	if (n <= 0xffff) {
		if (buf_len < 3) return 0;
		buf[0] = mt | 25;
		buf[1] = (uint8_t)(n >> 8);
		buf[2] = (uint8_t)n;
		return 3;
	}
	if (n <= 0xffffffffULL) {
		if (buf_len < 5) return 0;
		buf[0] = mt | 26;
		buf[1] = (uint8_t)(n >> 24);
		buf[2] = (uint8_t)(n >> 16);
		buf[3] = (uint8_t)(n >> 8);
		buf[4] = (uint8_t)n;
		return 5;
	}
	if (buf_len < 9) return 0;
	buf[0] = mt | 27;
	buf[1] = (uint8_t)(n >> 56);
	buf[2] = (uint8_t)(n >> 48);
	buf[3] = (uint8_t)(n >> 40);
	buf[4] = (uint8_t)(n >> 32);
	buf[5] = (uint8_t)(n >> 24);
	buf[6] = (uint8_t)(n >> 16);
	buf[7] = (uint8_t)(n >> 8);
	buf[8] = (uint8_t)n;
	return 9;
}

/**
 * @brief Encode CBOR text string.
 * @return Bytes written, or 0 if buffer too small.
 */
static size_t cbor_encode_tstr(uint8_t *buf, size_t buf_len, const char *str)
{
	size_t str_len = strlen(str);
	size_t hdr_len = cbor_encode_header(buf, buf_len, 3, str_len);

	if (hdr_len == 0 || hdr_len + str_len > buf_len) {
		return 0;
	}
	memcpy(buf + hdr_len, str, str_len);
	return hdr_len + str_len;
}

/**
 * @brief Encode CBOR unsigned integer.
 * @return Bytes written, or 0 if buffer too small.
 */
static size_t cbor_encode_uint(uint8_t *buf, size_t buf_len, uint64_t n)
{
	return cbor_encode_header(buf, buf_len, 0, n);
}

/**
 * @brief Encode CBOR float64.
 * @return Bytes written (9), or 0 if buffer too small.
 */
static size_t cbor_encode_float64(uint8_t *buf, size_t buf_len, double value)
{
	if (buf_len < 9) return 0;

	union {
		double d;
		uint64_t u;
	} conv;
	conv.d = value;

	buf[0] = 0xfb; /* float64 */
	buf[1] = (uint8_t)(conv.u >> 56);
	buf[2] = (uint8_t)(conv.u >> 48);
	buf[3] = (uint8_t)(conv.u >> 40);
	buf[4] = (uint8_t)(conv.u >> 32);
	buf[5] = (uint8_t)(conv.u >> 24);
	buf[6] = (uint8_t)(conv.u >> 16);
	buf[7] = (uint8_t)(conv.u >> 8);
	buf[8] = (uint8_t)conv.u;
	return 9;
}

/*
 * CBOR decoding helpers.
 */

struct cbor_reader {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static bool cbor_reader_has(const struct cbor_reader *r, size_t n)
{
	return r->pos + n <= r->len;
}

static int cbor_read_header(struct cbor_reader *r, uint8_t *major, uint64_t *value)
{
	if (!cbor_reader_has(r, 1)) {
		return SOS_ALERT_ERR_TRUNCATED;
	}

	uint8_t first = r->buf[r->pos++];
	*major = first >> 5;
	uint8_t ai = first & 0x1f;

	if (ai < 24) {
		*value = ai;
		return 0;
	}
	if (ai == 24) {
		if (!cbor_reader_has(r, 1)) return SOS_ALERT_ERR_TRUNCATED;
		*value = r->buf[r->pos++];
		return 0;
	}
	if (ai == 25) {
		if (!cbor_reader_has(r, 2)) return SOS_ALERT_ERR_TRUNCATED;
		*value = ((uint64_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1];
		r->pos += 2;
		return 0;
	}
	if (ai == 26) {
		if (!cbor_reader_has(r, 4)) return SOS_ALERT_ERR_TRUNCATED;
		*value = ((uint64_t)r->buf[r->pos] << 24) |
			 ((uint64_t)r->buf[r->pos + 1] << 16) |
			 ((uint64_t)r->buf[r->pos + 2] << 8) |
			 r->buf[r->pos + 3];
		r->pos += 4;
		return 0;
	}
	if (ai == 27) {
		if (!cbor_reader_has(r, 8)) return SOS_ALERT_ERR_TRUNCATED;
		*value = ((uint64_t)r->buf[r->pos] << 56) |
			 ((uint64_t)r->buf[r->pos + 1] << 48) |
			 ((uint64_t)r->buf[r->pos + 2] << 40) |
			 ((uint64_t)r->buf[r->pos + 3] << 32) |
			 ((uint64_t)r->buf[r->pos + 4] << 24) |
			 ((uint64_t)r->buf[r->pos + 5] << 16) |
			 ((uint64_t)r->buf[r->pos + 6] << 8) |
			 r->buf[r->pos + 7];
		r->pos += 8;
		return 0;
	}
	return SOS_ALERT_ERR_UNEXPECTED_TYPE;
}

static int cbor_read_tstr(struct cbor_reader *r, char *out, size_t out_max, size_t *out_len)
{
	uint8_t major;
	uint64_t len;
	int err = cbor_read_header(r, &major, &len);
	if (err) return err;
	if (major != 3) return SOS_ALERT_ERR_UNEXPECTED_TYPE;
	if (len > SIZE_MAX || !cbor_reader_has(r, (size_t)len)) {
		return SOS_ALERT_ERR_TRUNCATED;
	}
	if (len >= out_max) {
		return SOS_ALERT_ERR_OUT_OF_RANGE;
	}
	memcpy(out, r->buf + r->pos, (size_t)len);
	out[(size_t)len] = '\0';
	*out_len = (size_t)len;
	r->pos += (size_t)len;
	return 0;
}

static int cbor_read_uint(struct cbor_reader *r, uint64_t *value)
{
	uint8_t major;
	int err = cbor_read_header(r, &major, value);
	if (err) return err;
	if (major != 0) return SOS_ALERT_ERR_UNEXPECTED_TYPE;
	return 0;
}

static int cbor_read_float64(struct cbor_reader *r, double *value)
{
	if (!cbor_reader_has(r, 1)) {
		return SOS_ALERT_ERR_TRUNCATED;
	}

	uint8_t first = r->buf[r->pos];

	/* Accept f16, f32, or f64 */
	if (first == 0xf9) { /* float16 */
		if (!cbor_reader_has(r, 3)) return SOS_ALERT_ERR_TRUNCATED;
		r->pos++;
		uint16_t bits = ((uint16_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1];
		r->pos += 2;

		/* Decode IEEE 754 half-precision */
		uint16_t sign = (bits >> 15) & 1;
		uint16_t exp = (bits >> 10) & 0x1f;
		uint16_t frac = bits & 0x3ff;

		double result;
		if (exp == 0) {
			if (frac == 0) {
				result = 0.0;
			} else {
				/* Subnormal */
				result = (double)frac / 1024.0 / 16384.0;
			}
		} else if (exp == 31) {
			result = frac ? NAN : INFINITY;
		} else {
			/* Use ldexp to avoid undefined behavior from negative shift */
			result = ldexp(1.0 + (double)frac / 1024.0, exp - 15);
		}
		*value = sign ? -result : result;
		return 0;
	}
	if (first == 0xfa) { /* float32 */
		if (!cbor_reader_has(r, 5)) return SOS_ALERT_ERR_TRUNCATED;
		r->pos++;
		union {
			uint32_t u;
			float f;
		} conv;
		conv.u = ((uint32_t)r->buf[r->pos] << 24) |
			 ((uint32_t)r->buf[r->pos + 1] << 16) |
			 ((uint32_t)r->buf[r->pos + 2] << 8) |
			 r->buf[r->pos + 3];
		r->pos += 4;
		*value = (double)conv.f;
		return 0;
	}
	if (first == 0xfb) { /* float64 */
		if (!cbor_reader_has(r, 9)) return SOS_ALERT_ERR_TRUNCATED;
		r->pos++;
		union {
			uint64_t u;
			double d;
		} conv;
		conv.u = ((uint64_t)r->buf[r->pos] << 56) |
			 ((uint64_t)r->buf[r->pos + 1] << 48) |
			 ((uint64_t)r->buf[r->pos + 2] << 40) |
			 ((uint64_t)r->buf[r->pos + 3] << 32) |
			 ((uint64_t)r->buf[r->pos + 4] << 24) |
			 ((uint64_t)r->buf[r->pos + 5] << 16) |
			 ((uint64_t)r->buf[r->pos + 6] << 8) |
			 r->buf[r->pos + 7];
		r->pos += 8;
		*value = conv.d;
		return 0;
	}

	return SOS_ALERT_ERR_UNEXPECTED_TYPE;
}

/* Validate IPv6 full notation (8 colon-separated hex groups) */
static bool validate_node_id(const char *node)
{
	int groups = 0;
	const char *p = node;

	while (*p) {
		int digits = 0;
		while (*p && *p != ':') {
			char c = *p++;
			if (!((c >= '0' && c <= '9') ||
			      (c >= 'a' && c <= 'f') ||
			      (c >= 'A' && c <= 'F'))) {
				return false;
			}
			digits++;
		}
		if (digits == 0 || digits > 4) {
			return false;
		}
		groups++;
		if (*p == ':') {
			p++;
		}
	}

	return groups == 8;
}

/*
 * Public API implementation.
 */

void sos_alert_init(struct sos_alert *alert,
		    enum sos_alert_type type,
		    const char *node,
		    uint64_t ts,
		    uint32_t seq)
{
	memset(alert, 0, sizeof(*alert));
	alert->type = type;
	strncpy(alert->node, node, SOS_ALERT_NODE_MAX_LEN - 1);
	alert->node[SOS_ALERT_NODE_MAX_LEN - 1] = '\0';
	alert->ts = ts;
	alert->seq = seq;
	alert->has_location = false;
	alert->has_msg = false;
}

void sos_alert_set_location(struct sos_alert *alert, double lat, double lon)
{
	alert->has_location = true;
	alert->lat = lat;
	alert->lon = lon;
}

void sos_alert_set_message(struct sos_alert *alert, const char *msg)
{
	alert->has_msg = true;
	strncpy(alert->msg, msg, SOS_ALERT_MSG_MAX_LEN - 1);
	alert->msg[SOS_ALERT_MSG_MAX_LEN - 1] = '\0';
}

const char *sos_alert_type_str(enum sos_alert_type type)
{
	if (type < 0 || type > SOS_ALERT_TYPE_CANCEL) {
		return NULL;
	}
	return ALERT_TYPE_STRINGS[type];
}

int sos_alert_type_parse(const char *str, enum sos_alert_type *type)
{
	for (int i = 0; i <= SOS_ALERT_TYPE_CANCEL; i++) {
		if (strcmp(str, ALERT_TYPE_STRINGS[i]) == 0) {
			*type = (enum sos_alert_type)i;
			return 0;
		}
	}
	return -1;
}

int sos_alert_to_cbor(const struct sos_alert *alert,
		      uint8_t *buf,
		      size_t buf_len,
		      size_t *out_len)
{
	size_t pos = 0;
	size_t written;

	/* Count fields: type, node, ts, seq always; lat/lon/msg optional */
	int field_count = 4;
	if (alert->has_location) field_count += 2;
	if (alert->has_msg) field_count += 1;

	/* Map header */
	written = cbor_encode_header(buf + pos, buf_len - pos, 5, (uint64_t)field_count);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	/* type */
	const char *type_str = sos_alert_type_str(alert->type);
	if (!type_str) return SOS_ALERT_ERR_INVALID_VALUE;

	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_TYPE);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	written = cbor_encode_tstr(buf + pos, buf_len - pos, type_str);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	/* node */
	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_NODE);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	written = cbor_encode_tstr(buf + pos, buf_len - pos, alert->node);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	/* ts */
	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_TS);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	written = cbor_encode_uint(buf + pos, buf_len - pos, alert->ts);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	/* lat (optional) */
	if (alert->has_location) {
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_LAT);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;

		written = cbor_encode_float64(buf + pos, buf_len - pos, alert->lat);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;

		/* lon */
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_LON);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;

		written = cbor_encode_float64(buf + pos, buf_len - pos, alert->lon);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;
	}

	/* msg (optional) */
	if (alert->has_msg) {
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_MSG);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;

		written = cbor_encode_tstr(buf + pos, buf_len - pos, alert->msg);
		if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
		pos += written;
	}

	/* seq */
	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_SEQ);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	written = cbor_encode_uint(buf + pos, buf_len - pos, alert->seq);
	if (written == 0) return SOS_ALERT_ERR_BUFFER_TOO_SMALL;
	pos += written;

	*out_len = pos;
	return 0;
}

int sos_alert_from_cbor(const uint8_t *buf,
			size_t buf_len,
			struct sos_alert *alert)
{
	struct cbor_reader r = { .buf = buf, .len = buf_len, .pos = 0 };

	/* Read map header */
	uint8_t major;
	uint64_t count;
	int err = cbor_read_header(&r, &major, &count);
	if (err) return err;
	if (major != 5) return SOS_ALERT_ERR_NOT_A_MAP;
	if (count > 16) return SOS_ALERT_ERR_OUT_OF_RANGE;

	/* Initialize to absent */
	memset(alert, 0, sizeof(*alert));
	bool has_type = false, has_node = false, has_ts = false, has_seq = false;
	bool has_lat = false, has_lon = false;

	/* Parse key-value pairs */
	for (uint64_t i = 0; i < count; i++) {
		char key[16];
		size_t key_len;
		err = cbor_read_tstr(&r, key, sizeof(key), &key_len);
		if (err) return err;

		if (strcmp(key, KEY_TYPE) == 0) {
			if (has_type) return SOS_ALERT_ERR_DUPLICATE_KEY;
			char type_str[16];
			size_t type_len;
			err = cbor_read_tstr(&r, type_str, sizeof(type_str), &type_len);
			if (err) return err;
			if (sos_alert_type_parse(type_str, &alert->type) != 0) {
				return SOS_ALERT_ERR_INVALID_VALUE;
			}
			has_type = true;
		} else if (strcmp(key, KEY_NODE) == 0) {
			if (has_node) return SOS_ALERT_ERR_DUPLICATE_KEY;
			size_t node_len;
			err = cbor_read_tstr(&r, alert->node, SOS_ALERT_NODE_MAX_LEN, &node_len);
			if (err) return err;
			if (!validate_node_id(alert->node)) {
				return SOS_ALERT_ERR_INVALID_VALUE;
			}
			has_node = true;
		} else if (strcmp(key, KEY_TS) == 0) {
			if (has_ts) return SOS_ALERT_ERR_DUPLICATE_KEY;
			err = cbor_read_uint(&r, &alert->ts);
			if (err) return err;
			has_ts = true;
		} else if (strcmp(key, KEY_LAT) == 0) {
			if (has_lat) return SOS_ALERT_ERR_DUPLICATE_KEY;
			err = cbor_read_float64(&r, &alert->lat);
			if (err) return err;
			has_lat = true;
			alert->has_location = true;
		} else if (strcmp(key, KEY_LON) == 0) {
			if (has_lon) return SOS_ALERT_ERR_DUPLICATE_KEY;
			err = cbor_read_float64(&r, &alert->lon);
			if (err) return err;
			has_lon = true;
			alert->has_location = true;
		} else if (strcmp(key, KEY_MSG) == 0) {
			if (alert->has_msg) return SOS_ALERT_ERR_DUPLICATE_KEY;
			size_t msg_len;
			err = cbor_read_tstr(&r, alert->msg, SOS_ALERT_MSG_MAX_LEN, &msg_len);
			if (err) return err;
			alert->has_msg = true;
		} else if (strcmp(key, KEY_SEQ) == 0) {
			if (has_seq) return SOS_ALERT_ERR_DUPLICATE_KEY;
			uint64_t seq64;
			err = cbor_read_uint(&r, &seq64);
			if (err) return err;
			if (seq64 > UINT32_MAX) return SOS_ALERT_ERR_OUT_OF_RANGE;
			alert->seq = (uint32_t)seq64;
			has_seq = true;
		} else {
			return SOS_ALERT_ERR_UNKNOWN_KEY;
		}
	}

	/* Verify required fields */
	if (!has_type || !has_node || !has_ts || !has_seq) {
		return SOS_ALERT_ERR_MISSING_FIELD;
	}

	/* Verify no trailing data */
	if (r.pos != r.len) {
		return SOS_ALERT_ERR_TRAILING_DATA;
	}

	return 0;
}
