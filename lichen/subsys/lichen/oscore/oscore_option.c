/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_option.c
 * @brief OSCORE option parsing and building
 *
 * Implements parsing and building of OSCORE CoAP option values per RFC 8613.
 */

#include <string.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"

int oscore_option_parse(const uint8_t *data, size_t len,
			struct oscore_option *option)
{
	if (option == NULL || (data == NULL && len > 0)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	memset(option, 0, sizeof(*option));

	if (len == 0) {
		/* Empty option: no PIV, no KID, no KID Context */
		return OSCORE_OK;
	}

	/*
	 * OSCORE option format (RFC 8613 Section 6.1):
	 *
	 * +-----------+-----------+------+---------+--------+-----+
	 * | 0 (1 bit) | h (1 bit) | k    | n       | PIV    | ... |
	 * |           |           |(1bit)| (3 bits)| (n B)  |     |
	 * +-----------+-----------+------+---------+--------+-----+
	 *
	 * Followed by:
	 * - If h=1: s (1 byte) || kid_context (s bytes)
	 * - If k=1: kid (rest of option)
	 */

	const uint8_t *p = data;
	size_t remaining = len;

	/* First byte: flags */
	uint8_t flags = *p++;
	remaining--;

	/* Reserved bit must be 0 */
	if (flags & 0x80) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	bool h_flag = (flags & 0x10) != 0; /* KID Context present */
	bool k_flag = (flags & 0x08) != 0; /* KID present */
	uint8_t n = flags & 0x07;          /* PIV length */

	/* Parse PIV */
	if (n > 0) {
		if (n > OSCORE_PIV_MAX_LEN || n > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->piv, p, n);
		option->piv_len = n;
		option->has_piv = true;
		p += n;
		remaining -= n;
	}

	/* Parse KID Context */
	if (h_flag) {
		if (remaining < 1) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		uint8_t s = *p++;
		remaining--;

		if (s > OSCORE_ID_CONTEXT_MAX_LEN || s > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid_context, p, s);
		option->kid_context_len = s;
		option->has_kid_context = true;
		p += s;
		remaining -= s;
	}

	/* Parse KID (rest of option if k=1) */
	if (k_flag) {
		if (remaining > OSCORE_ID_MAX_LEN) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid, p, remaining);
		option->kid_len = (uint8_t)remaining;
		option->has_kid = true;
	} else if (remaining > 0) {
		/* k_flag not set but trailing bytes present - malformed */
		return OSCORE_ERR_INVALID_PARAM;
	}

	return OSCORE_OK;
}

int oscore_option_build(const struct oscore_option *option,
			uint8_t *buf, size_t buflen)
{
	size_t off = 0;

	/* Validate parameters (python-ano.88) */
	if (option == NULL || buf == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Validate field lengths against protocol limits */
	if (option->piv_len > OSCORE_PIV_MAX_LEN ||
	    option->kid_len > OSCORE_ID_MAX_LEN ||
	    option->kid_context_len > OSCORE_ID_CONTEXT_MAX_LEN) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * Build OSCORE option value.
	 * Minimum is 1 byte (flags), plus variable parts.
	 */

	/* Flags byte */
	uint8_t flags = 0;
	if (option->has_kid_context) {
		flags |= 0x10;
	}
	if (option->has_kid) {
		flags |= 0x08;
	}
	if (option->has_piv) {
		flags |= (option->piv_len & 0x07);  /* Lower 3 bits per RFC 8613 */
	}

	if (off >= buflen) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}
	buf[off++] = flags;

	/* PIV */
	if (option->has_piv && option->piv_len > 0) {
		if (off + option->piv_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->piv, option->piv_len);
		off += option->piv_len;
	}

	/* KID Context */
	if (option->has_kid_context) {
		if (off + 1 + option->kid_context_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		buf[off++] = option->kid_context_len;
		memcpy(buf + off, option->kid_context, option->kid_context_len);
		off += option->kid_context_len;
	}

	/* KID */
	if (option->has_kid) {
		if (off + option->kid_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->kid, option->kid_len);
		off += option->kid_len;
	}

	return (int)off;
}
