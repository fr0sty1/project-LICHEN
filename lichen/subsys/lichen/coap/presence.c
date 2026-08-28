/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file presence.c
 * @brief Presence CBOR encoding (spec section 18.5)
 *
 * Implements CBOR encoding/decoding for presence payloads.
 * Wire format matches test/vectors/presence_cbor.json.
 */

#include <lichen/presence.h>
#include <string.h>
#include <limits.h>

/* Status wire strings */
static const char *const STATUS_STRINGS[] = {
	"available",
	"busy",
	"away",
	"offline",
	"emergency",
};
#define STATUS_COUNT (sizeof(STATUS_STRINGS) / sizeof(STATUS_STRINGS[0]))

/* Activity wire strings (index 0 = none, not encoded) */
static const char *const ACTIVITY_STRINGS[] = {
	NULL,         /* NONE - never encoded */
	"stationary",
	"moving",
	"resting",
	"working",
};
#define ACTIVITY_COUNT (sizeof(ACTIVITY_STRINGS) / sizeof(ACTIVITY_STRINGS[0]))

/* CBOR map key strings */
static const char KEY_STATUS[] = "status";
static const char KEY_ACTIVITY[] = "activity";
static const char KEY_MSG[] = "msg";
static const char KEY_BATTERY[] = "battery";
static const char KEY_LOW_BATTERY[] = "low_battery";
static const char KEY_TS[] = "ts";
static const char KEY_NODES[] = "nodes";
static const char KEY_ADDR[] = "addr";
static const char KEY_AGE_S[] = "age_s";

/*
 * CBOR encoding helpers (inline, no external dependencies).
 * Major types per RFC 8949:
 *   0: unsigned integer
 *   2: byte string
 *   3: text string
 *   4: array
 *   5: map
 *   7: floating-point / simple
 */

/**
 * @brief Encode CBOR type and length header.
 * @return Bytes written, or 0 if buffer too small.
 */
static size_t cbor_encode_header(uint8_t *buf, size_t buf_len,
				 uint8_t major, uint64_t n)
{
	uint8_t mt = (uint8_t)(major << 5);

	if (n < 24) {
		if (buf_len < 1) {
			return 0;
		}
		buf[0] = mt | (uint8_t)n;
		return 1;
	}
	if (n <= 0xff) {
		if (buf_len < 2) {
			return 0;
		}
		buf[0] = mt | 24;
		buf[1] = (uint8_t)n;
		return 2;
	}
	if (n <= 0xffff) {
		if (buf_len < 3) {
			return 0;
		}
		buf[0] = mt | 25;
		buf[1] = (uint8_t)(n >> 8);
		buf[2] = (uint8_t)n;
		return 3;
	}
	if (n <= 0xffffffffULL) {
		if (buf_len < 5) {
			return 0;
		}
		buf[0] = mt | 26;
		buf[1] = (uint8_t)(n >> 24);
		buf[2] = (uint8_t)(n >> 16);
		buf[3] = (uint8_t)(n >> 8);
		buf[4] = (uint8_t)n;
		return 5;
	}
	if (buf_len < 9) {
		return 0;
	}
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
 * @brief Encode CBOR boolean.
 * @return Bytes written, or 0 if buffer too small.
 */
static size_t cbor_encode_bool(uint8_t *buf, size_t buf_len, bool value)
{
	if (buf_len < 1) {
		return 0;
	}
	buf[0] = value ? 0xf5 : 0xf4;
	return 1;
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

static int cbor_read_header(struct cbor_reader *r, uint8_t *major,
			    uint64_t *value)
{
	if (!cbor_reader_has(r, 1)) {
		return PRESENCE_ERR_TRUNCATED;
	}

	uint8_t first = r->buf[r->pos++];
	*major = first >> 5;
	uint8_t ai = first & 0x1f;

	if (ai < 24) {
		*value = ai;
		return 0;
	}
	if (ai == 24) {
		if (!cbor_reader_has(r, 1)) {
			return PRESENCE_ERR_TRUNCATED;
		}
		*value = r->buf[r->pos++];
		return 0;
	}
	if (ai == 25) {
		if (!cbor_reader_has(r, 2)) {
			return PRESENCE_ERR_TRUNCATED;
		}
		*value = ((uint64_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1];
		r->pos += 2;
		return 0;
	}
	if (ai == 26) {
		if (!cbor_reader_has(r, 4)) {
			return PRESENCE_ERR_TRUNCATED;
		}
		*value = ((uint64_t)r->buf[r->pos] << 24) |
			 ((uint64_t)r->buf[r->pos + 1] << 16) |
			 ((uint64_t)r->buf[r->pos + 2] << 8) |
			 r->buf[r->pos + 3];
		r->pos += 4;
		return 0;
	}
	if (ai == 27) {
		if (!cbor_reader_has(r, 8)) {
			return PRESENCE_ERR_TRUNCATED;
		}
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
	return PRESENCE_ERR_UNEXPECTED_TYPE;
}

static int cbor_read_tstr(struct cbor_reader *r, char *out, size_t out_max,
			  size_t *out_len)
{
	uint8_t major;
	uint64_t len;
	int err = cbor_read_header(r, &major, &len);

	if (err) {
		return err;
	}
	if (major != 3) {
		return PRESENCE_ERR_UNEXPECTED_TYPE;
	}
	if (len > SIZE_MAX || !cbor_reader_has(r, (size_t)len)) {
		return PRESENCE_ERR_TRUNCATED;
	}
	if (len >= out_max) {
		return PRESENCE_ERR_OUT_OF_RANGE;
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

	if (err) {
		return err;
	}
	if (major != 0) {
		return PRESENCE_ERR_UNEXPECTED_TYPE;
	}
	return 0;
}

static int cbor_read_bool(struct cbor_reader *r, bool *value)
{
	if (!cbor_reader_has(r, 1)) {
		return PRESENCE_ERR_TRUNCATED;
	}

	uint8_t byte = r->buf[r->pos];

	if (byte == 0xf4) {
		*value = false;
		r->pos++;
		return 0;
	}
	if (byte == 0xf5) {
		*value = true;
		r->pos++;
		return 0;
	}
	return PRESENCE_ERR_UNEXPECTED_TYPE;
}

/*
 * Public API implementation.
 */

void presence_init(struct presence *p, enum presence_status status, uint64_t ts)
{
	if (p == NULL) {
		return;
	}
	memset(p, 0, sizeof(*p));
	p->status = status;
	p->ts = ts;
	p->has_activity = false;
	p->has_msg = false;
	p->has_battery = false;
	p->has_low_battery = false;
}

void presence_set_activity(struct presence *p, enum presence_activity activity)
{
	if (p == NULL) {
		return;
	}
	if (activity == PRESENCE_ACTIVITY_NONE) {
		p->has_activity = false;
	} else {
		p->has_activity = true;
		p->activity = activity;
	}
}

void presence_set_message(struct presence *p, const char *msg)
{
	if (p == NULL || msg == NULL) {
		return;
	}
	p->has_msg = true;
	strncpy(p->msg, msg, PRESENCE_MSG_MAX_LEN - 1);
	p->msg[PRESENCE_MSG_MAX_LEN - 1] = '\0';
}

int presence_set_battery(struct presence *p, uint8_t battery)
{
	if (p == NULL) {
		return -1;
	}
	if (battery > 100) {
		return -1;
	}
	p->has_battery = true;
	p->battery = battery;

	/* Per spec 18.5.3: low_battery == true iff battery < 10 */
	if (battery < PRESENCE_LOW_BATTERY_PCT) {
		p->has_low_battery = true;
		p->low_battery = true;
	} else {
		p->has_low_battery = false;
	}
	return 0;
}

const char *presence_status_str(enum presence_status status)
{
	if (status < 0 || (size_t)status >= STATUS_COUNT) {
		return NULL;
	}
	return STATUS_STRINGS[status];
}

int presence_status_parse(const char *str, enum presence_status *status)
{
	for (size_t i = 0; i < STATUS_COUNT; i++) {
		if (strcmp(str, STATUS_STRINGS[i]) == 0) {
			*status = (enum presence_status)i;
			return 0;
		}
	}
	return -1;
}

const char *presence_activity_str(enum presence_activity activity)
{
	if (activity < 0 || (size_t)activity >= ACTIVITY_COUNT) {
		return NULL;
	}
	return ACTIVITY_STRINGS[activity];
}

int presence_activity_parse(const char *str, enum presence_activity *activity)
{
	for (size_t i = 1; i < ACTIVITY_COUNT; i++) {
		if (ACTIVITY_STRINGS[i] != NULL &&
		    strcmp(str, ACTIVITY_STRINGS[i]) == 0) {
			*activity = (enum presence_activity)i;
			return 0;
		}
	}
	return -1;
}

int presence_to_cbor(const struct presence *p,
		     uint8_t *buf,
		     size_t buf_len,
		     size_t *out_len)
{
	size_t pos = 0;
	size_t written;

	/* Count fields: status, ts always; activity, msg, battery, low_battery optional */
	int field_count = 2; /* status + ts */
	if (p->has_activity && p->activity != PRESENCE_ACTIVITY_NONE) {
		field_count++;
	}
	if (p->has_msg) {
		field_count++;
	}
	if (p->has_battery) {
		field_count++;
	}
	if (p->has_low_battery) {
		field_count++;
	}

	/* Map header */
	written = cbor_encode_header(buf + pos, buf_len - pos, 5,
				     (uint64_t)field_count);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	/* status (required) */
	const char *status_str = presence_status_str(p->status);

	if (!status_str) {
		return PRESENCE_ERR_INVALID_VALUE;
	}

	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_STATUS);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	written = cbor_encode_tstr(buf + pos, buf_len - pos, status_str);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	/* activity (optional) */
	if (p->has_activity && p->activity != PRESENCE_ACTIVITY_NONE) {
		const char *activity_str = presence_activity_str(p->activity);

		if (!activity_str) {
			return PRESENCE_ERR_INVALID_VALUE;
		}

		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   KEY_ACTIVITY);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   activity_str);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;
	}

	/* msg (optional) */
	if (p->has_msg) {
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_MSG);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_tstr(buf + pos, buf_len - pos, p->msg);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;
	}

	/* battery (optional) */
	if (p->has_battery) {
		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   KEY_BATTERY);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_uint(buf + pos, buf_len - pos,
					   p->battery);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;
	}

	/* low_battery (optional) */
	if (p->has_low_battery) {
		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   KEY_LOW_BATTERY);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_bool(buf + pos, buf_len - pos,
					   p->low_battery);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;
	}

	/* ts (required) */
	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_TS);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	written = cbor_encode_uint(buf + pos, buf_len - pos, p->ts);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	*out_len = pos;
	return 0;
}

int presence_from_cbor(const uint8_t *buf, size_t buf_len, struct presence *p)
{
	struct cbor_reader r = { .buf = buf, .len = buf_len, .pos = 0 };

	/* Read map header */
	uint8_t major;
	uint64_t count;
	int err = cbor_read_header(&r, &major, &count);

	if (err) {
		return err;
	}
	if (major != 5) {
		return PRESENCE_ERR_NOT_A_MAP;
	}
	if (count > 16) {
		return PRESENCE_ERR_OUT_OF_RANGE;
	}

	/* Initialize to absent */
	memset(p, 0, sizeof(*p));
	bool has_status = false;
	bool has_ts = false;

	/* Parse key-value pairs */
	for (uint64_t i = 0; i < count; i++) {
		char key[16];
		size_t key_len;

		err = cbor_read_tstr(&r, key, sizeof(key), &key_len);
		if (err) {
			return err;
		}

		if (strcmp(key, KEY_STATUS) == 0) {
			if (has_status) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			char status_str[16];
			size_t status_len;

			err = cbor_read_tstr(&r, status_str, sizeof(status_str),
					     &status_len);
			if (err) {
				return err;
			}
			if (presence_status_parse(status_str, &p->status) != 0) {
				return PRESENCE_ERR_INVALID_VALUE;
			}
			has_status = true;
		} else if (strcmp(key, KEY_ACTIVITY) == 0) {
			if (p->has_activity) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			char activity_str[16];
			size_t activity_len;

			err = cbor_read_tstr(&r, activity_str,
					     sizeof(activity_str),
					     &activity_len);
			if (err) {
				return err;
			}
			if (presence_activity_parse(activity_str,
						    &p->activity) != 0) {
				return PRESENCE_ERR_INVALID_VALUE;
			}
			p->has_activity = true;
		} else if (strcmp(key, KEY_MSG) == 0) {
			if (p->has_msg) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			size_t msg_len;

			err = cbor_read_tstr(&r, p->msg, PRESENCE_MSG_MAX_LEN,
					     &msg_len);
			if (err) {
				return err;
			}
			p->has_msg = true;
		} else if (strcmp(key, KEY_BATTERY) == 0) {
			if (p->has_battery) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			uint64_t battery64;

			err = cbor_read_uint(&r, &battery64);
			if (err) {
				return err;
			}
			if (battery64 > 100) {
				return PRESENCE_ERR_OUT_OF_RANGE;
			}
			p->battery = (uint8_t)battery64;
			p->has_battery = true;
		} else if (strcmp(key, KEY_LOW_BATTERY) == 0) {
			if (p->has_low_battery) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			err = cbor_read_bool(&r, &p->low_battery);
			if (err) {
				return err;
			}
			p->has_low_battery = true;
		} else if (strcmp(key, KEY_TS) == 0) {
			if (has_ts) {
				return PRESENCE_ERR_DUPLICATE_KEY;
			}
			err = cbor_read_uint(&r, &p->ts);
			if (err) {
				return err;
			}
			has_ts = true;
		} else {
			return PRESENCE_ERR_UNKNOWN_KEY;
		}
	}

	/* Verify required fields */
	if (!has_status || !has_ts) {
		return PRESENCE_ERR_MISSING_FIELD;
	}

	/* Verify no trailing data */
	if (r.pos != r.len) {
		return PRESENCE_ERR_TRAILING_DATA;
	}

	return 0;
}

void presence_cache_init(struct presence_cache *cache)
{
	if (cache == NULL) {
		return;
	}
	memset(cache, 0, sizeof(*cache));
}

int presence_cache_to_cbor(const struct presence_cache *cache,
			   uint8_t *buf,
			   size_t buf_len,
			   size_t *out_len)
{
	size_t pos = 0;
	size_t written;

	/* Outer map with "nodes" key */
	written = cbor_encode_header(buf + pos, buf_len - pos, 5, 1);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_NODES);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	/* Array of node entries */
	written = cbor_encode_header(buf + pos, buf_len - pos, 4, cache->count);
	if (written == 0) {
		return PRESENCE_ERR_BUFFER_TOO_SMALL;
	}
	pos += written;

	/* Each cache entry */
	for (size_t i = 0; i < cache->count; i++) {
		const struct presence_cache_entry *entry = &cache->entries[i];
		int field_count = 3; /* addr, status, age_s always */

		if (entry->has_battery) {
			field_count++;
		}

		/* Entry map header */
		written = cbor_encode_header(buf + pos, buf_len - pos, 5,
					     (uint64_t)field_count);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		/* addr */
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_ADDR);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   entry->addr);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		/* status */
		const char *status_str = presence_status_str(entry->status);

		if (!status_str) {
			return PRESENCE_ERR_INVALID_VALUE;
		}

		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   KEY_STATUS);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_tstr(buf + pos, buf_len - pos,
					   status_str);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		/* battery (optional) */
		if (entry->has_battery) {
			written = cbor_encode_tstr(buf + pos, buf_len - pos,
						   KEY_BATTERY);
			if (written == 0) {
				return PRESENCE_ERR_BUFFER_TOO_SMALL;
			}
			pos += written;

			written = cbor_encode_uint(buf + pos, buf_len - pos,
						   entry->battery);
			if (written == 0) {
				return PRESENCE_ERR_BUFFER_TOO_SMALL;
			}
			pos += written;
		}

		/* age_s */
		written = cbor_encode_tstr(buf + pos, buf_len - pos, KEY_AGE_S);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;

		written = cbor_encode_uint(buf + pos, buf_len - pos,
					   entry->age_s);
		if (written == 0) {
			return PRESENCE_ERR_BUFFER_TOO_SMALL;
		}
		pos += written;
	}

	*out_len = pos;
	return 0;
}

int presence_cache_from_cbor(const uint8_t *buf, size_t buf_len,
			     struct presence_cache *cache)
{
	struct cbor_reader r = { .buf = buf, .len = buf_len, .pos = 0 };

	/* Read outer map header */
	uint8_t major;
	uint64_t count;
	int err = cbor_read_header(&r, &major, &count);

	if (err) {
		return err;
	}
	if (major != 5) {
		return PRESENCE_ERR_NOT_A_MAP;
	}
	if (count != 1) {
		return PRESENCE_ERR_INVALID_VALUE;
	}

	/* Read "nodes" key */
	char key[16];
	size_t key_len;

	err = cbor_read_tstr(&r, key, sizeof(key), &key_len);
	if (err) {
		return err;
	}
	if (strcmp(key, KEY_NODES) != 0) {
		return PRESENCE_ERR_UNKNOWN_KEY;
	}

	/* Read nodes array */
	uint64_t node_count;

	err = cbor_read_header(&r, &major, &node_count);
	if (err) {
		return err;
	}
	if (major != 4) {
		return PRESENCE_ERR_UNEXPECTED_TYPE;
	}
	if (node_count > PRESENCE_CACHE_MAX_ENTRIES) {
		return PRESENCE_ERR_OUT_OF_RANGE;
	}

	memset(cache, 0, sizeof(*cache));
	cache->count = (size_t)node_count;

	/* Parse each entry */
	for (size_t i = 0; i < cache->count; i++) {
		struct presence_cache_entry *entry = &cache->entries[i];
		uint64_t entry_count;

		err = cbor_read_header(&r, &major, &entry_count);
		if (err) {
			return err;
		}
		if (major != 5) {
			return PRESENCE_ERR_NOT_A_MAP;
		}
		if (entry_count > 8) {
			return PRESENCE_ERR_OUT_OF_RANGE;
		}

		bool has_addr = false;
		bool has_status = false;
		bool has_age_s = false;

		for (uint64_t j = 0; j < entry_count; j++) {
			err = cbor_read_tstr(&r, key, sizeof(key), &key_len);
			if (err) {
				return err;
			}

			if (strcmp(key, KEY_ADDR) == 0) {
				if (has_addr) {
					return PRESENCE_ERR_DUPLICATE_KEY;
				}
				size_t addr_len;

				err = cbor_read_tstr(&r, entry->addr,
						     PRESENCE_ADDR_MAX_LEN,
						     &addr_len);
				if (err) {
					return err;
				}
				has_addr = true;
			} else if (strcmp(key, KEY_STATUS) == 0) {
				if (has_status) {
					return PRESENCE_ERR_DUPLICATE_KEY;
				}
				char status_str[16];
				size_t status_len;

				err = cbor_read_tstr(&r, status_str,
						     sizeof(status_str),
						     &status_len);
				if (err) {
					return err;
				}
				if (presence_status_parse(status_str,
							  &entry->status) != 0) {
					return PRESENCE_ERR_INVALID_VALUE;
				}
				has_status = true;
			} else if (strcmp(key, KEY_BATTERY) == 0) {
				if (entry->has_battery) {
					return PRESENCE_ERR_DUPLICATE_KEY;
				}
				uint64_t battery64;

				err = cbor_read_uint(&r, &battery64);
				if (err) {
					return err;
				}
				if (battery64 > 100) {
					return PRESENCE_ERR_OUT_OF_RANGE;
				}
				entry->battery = (uint8_t)battery64;
				entry->has_battery = true;
			} else if (strcmp(key, KEY_AGE_S) == 0) {
				if (has_age_s) {
					return PRESENCE_ERR_DUPLICATE_KEY;
				}
				uint64_t age64;

				err = cbor_read_uint(&r, &age64);
				if (err) {
					return err;
				}
				if (age64 > UINT32_MAX) {
					return PRESENCE_ERR_OUT_OF_RANGE;
				}
				entry->age_s = (uint32_t)age64;
				has_age_s = true;
			} else {
				return PRESENCE_ERR_UNKNOWN_KEY;
			}
		}

		if (!has_addr || !has_status || !has_age_s) {
			return PRESENCE_ERR_MISSING_FIELD;
		}
	}

	/* Verify no trailing data */
	if (r.pos != r.len) {
		return PRESENCE_ERR_TRAILING_DATA;
	}

	return 0;
}
