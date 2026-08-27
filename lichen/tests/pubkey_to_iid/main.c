/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ipv6_addr.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct iid_vector {
	uint8_t pubkey[32];
	uint8_t iid[8];
	uint8_t native[16];
};

/* Exact literals from test/vectors/yggdrasil-derivation.json. */
static const struct iid_vector vectors[] = {
	{
		.pubkey = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
		.iid = {0x69, 0x4e, 0x6c, 0x1f, 0xe3, 0x65, 0x04, 0xe1},
		.native = {
			0x02, 0x6b, 0x4e, 0x6c, 0x1f, 0xe3, 0x65, 0x04,
			0x69, 0x4e, 0x6c, 0x1f, 0xe3, 0x65, 0x04, 0xe1,
		},
	},
	{
		.pubkey = {0},
		.iid = {0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86},
		.native = {
			0x02, 0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38,
			0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86,
		},
	},
	{
		.pubkey = {
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
			0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
			0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		},
		.iid = {0x0c, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba, 0xaa},
		.native = {
			0x02, 0x0e, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba,
			0x0c, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba, 0xaa,
		},
	},
};

int main(void)
{
	uint8_t iid[8];
	uint8_t sentinel[8];
	struct in6_addr link_local;
	struct in6_addr native;
	struct in6_addr addr_sentinel;
	static const uint8_t link_local_prefix[8] = {0xfe, 0x80};
	uint8_t scope;
	static const struct {
		uint8_t iid[8];
		uint8_t link_local[16];
	} link_local_vectors[] = {
		{
			.iid = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
			.link_local = {
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
			},
		},
		{
			/* U/L set: construction copies an IID; it does not derive one. */
			.iid = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			.link_local = {
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			.iid = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			.link_local = {
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
		},
	};

	for (size_t i = 0; i < sizeof(link_local_vectors) / sizeof(link_local_vectors[0]); i++) {
		memset(&link_local, 0xa5, sizeof(link_local));
		if (lichen_make_link_local(link_local_vectors[i].iid, &link_local) != 0 ||
		    memcmp(link_local.s6_addr, link_local_vectors[i].link_local,
			   sizeof(link_local_vectors[i].link_local)) != 0) {
			fprintf(stderr, "link-local vector %zu failed\n", i);
			return 1;
		}
	}

	/* The input IID may alias either half of the output object. */
	memcpy(link_local.s6_addr, link_local_vectors[0].iid, 8);
	if (lichen_make_link_local(link_local.s6_addr, &link_local) != 0 ||
	    memcmp(link_local.s6_addr, link_local_vectors[0].link_local,
		   sizeof(link_local_vectors[0].link_local)) != 0) {
		fprintf(stderr, "link-local leading alias failed\n");
		return 1;
	}
	memcpy(&link_local.s6_addr[8], link_local_vectors[1].iid, 8);
	if (lichen_make_link_local(&link_local.s6_addr[8], &link_local) != 0 ||
	    memcmp(link_local.s6_addr, link_local_vectors[1].link_local,
		   sizeof(link_local_vectors[1].link_local)) != 0) {
		fprintf(stderr, "link-local trailing alias failed\n");
		return 1;
	}

	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		if (lichen_pubkey_to_iid(vectors[i].pubkey, iid) != 0 ||
		    memcmp(iid, vectors[i].iid, sizeof(iid)) != 0 ||
		    (iid[0] & 0x02U) != 0U ||
		    lichen_make_link_local(iid, &link_local) != 0 ||
		    memcmp(link_local.s6_addr, link_local_prefix,
			   sizeof(link_local_prefix)) != 0 ||
		    memcmp(&link_local.s6_addr[8], iid, sizeof(iid)) != 0 ||
		    lichen_yggdrasil_addr(vectors[i].pubkey, &native) != 0 ||
		    memcmp(native.s6_addr, vectors[i].native,
			   sizeof(vectors[i].native)) != 0 ||
		    memcmp(&native.s6_addr[8], iid, sizeof(iid)) != 0) {
			fprintf(stderr, "vector %zu failed\n", i);
			return 1;
		}
	}

	if (!lichen_is_mesh_addr(&link_local) ||
	    !lichen_is_mesh_addr(&native) ||
	    lichen_is_mesh_addr(NULL)) {
		fprintf(stderr, "mesh scope classification failed\n");
		return 1;
	}
	{
		const struct in6_addr ula = {.s6_addr = {0xfd}};
		const struct in6_addr global = {.s6_addr = {0x20, 0x01}};
		const struct in6_addr multicast = {.s6_addr = {0xff, 0x03}};

		if (lichen_is_mesh_addr(&ula) || lichen_is_mesh_addr(&global) ||
		    lichen_is_mesh_addr(&multicast)) {
			fprintf(stderr, "non-mesh address accepted\n");
			return 1;
		}
	}

	{
		static const struct {
			uint8_t second_octet;
			uint8_t expected_scope;
			bool transmittable;
		} scope_vectors[] = {
			{0x00, 0, false}, {0x01, 1, false}, {0x02, 2, true},
			{0x03, 3, true},  {0x05, 5, true},  {0x0e, 14, true},
			{0x0f, 15, false}, {0x12, 2, true},
		};

		for (size_t i = 0; i < sizeof(scope_vectors) / sizeof(scope_vectors[0]); i++) {
			struct in6_addr multicast = {
				.s6_addr = {0xff, scope_vectors[i].second_octet},
			};

			scope = UINT8_MAX;
			if (lichen_ipv6_multicast_scope(&multicast, &scope) != 0 ||
			    scope != scope_vectors[i].expected_scope ||
			    lichen_ipv6_multicast_scope_is_transmittable(scope) !=
				scope_vectors[i].transmittable) {
				fprintf(stderr, "multicast scope vector %zu failed\n", i);
				return 1;
			}
		}
	}

	scope = 0xa5;
	if (lichen_ipv6_multicast_scope(&link_local, &scope) != -ENODATA ||
	    scope != 0xa5 ||
	    lichen_ipv6_multicast_scope(&native, &scope) != -ENODATA ||
	    scope != 0xa5 ||
	    lichen_ipv6_multicast_scope(NULL, &scope) != -EINVAL ||
	    scope != 0xa5 ||
	    lichen_ipv6_multicast_scope(&link_local, NULL) != -EINVAL ||
	    lichen_ipv6_multicast_scope_is_transmittable(UINT8_MAX)) {
		fprintf(stderr, "multicast scope error behavior failed\n");
		return 1;
	}

	memset(sentinel, 0xa5, sizeof(sentinel));
	memcpy(iid, sentinel, sizeof(iid));
	memset(&link_local, 0xa5, sizeof(link_local));
	addr_sentinel = link_local;
	if (lichen_pubkey_to_iid(NULL, iid) != -EINVAL ||
	    memcmp(iid, sentinel, sizeof(iid)) != 0 ||
	    lichen_pubkey_to_iid(vectors[0].pubkey, NULL) != -EINVAL ||
	    lichen_make_link_local(NULL, &link_local) != -EINVAL ||
	    memcmp(&link_local, &addr_sentinel, sizeof(link_local)) != 0 ||
	    lichen_make_link_local(iid, NULL) != -EINVAL) {
		fprintf(stderr, "NULL/error behavior failed\n");
		return 1;
	}

	memset(&addr_sentinel, 0xa5, sizeof(addr_sentinel));
	native = addr_sentinel;
	if (lichen_yggdrasil_addr(NULL, &native) != -EINVAL ||
	    memcmp(&native, &addr_sentinel, sizeof(native)) != 0 ||
	    lichen_yggdrasil_addr(vectors[0].pubkey, NULL) != -EINVAL) {
		fprintf(stderr, "native-address NULL/error behavior failed\n");
		return 1;
	}

	/*
	 * lichen_ipv6_addr_to_str truncation contract: the function either
	 * writes exactly LICHEN_IPV6_ADDR_STR_LEN - 1 hex chars plus NUL into
	 * a buffer of at least LICHEN_IPV6_ADDR_STR_LEN bytes, or fails with
	 * -EINVAL without producing a truncated address. Expected string is
	 * the documented uncompressed lowercase hex form of
	 * fe80::1234:5678:9abc:def0 (RFC 4291 bytes, 39 chars + NUL).
	 */
	{
		const struct in6_addr str_addr = {
			.s6_addr = {
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
			},
		};
		static const char expected[] =
			"fe80:0000:0000:0000:1234:5678:9abc:def0";
		char buf[LICHEN_IPV6_ADDR_STR_LEN + 2];
		char small[LICHEN_IPV6_ADDR_STR_LEN - 1];
		char one[1];
		char zero[4];

		/* Exact size: full string plus NUL, canary bytes intact. */
		memset(buf, 0xa5, sizeof(buf));
		if (lichen_ipv6_addr_to_str(&str_addr, buf,
					   LICHEN_IPV6_ADDR_STR_LEN) != 0 ||
		    strlen(buf) != LICHEN_IPV6_ADDR_STR_LEN - 1 ||
		    strcmp(buf, expected) != 0 ||
		    (unsigned char)buf[LICHEN_IPV6_ADDR_STR_LEN] != 0xa5u ||
		    (unsigned char)buf[LICHEN_IPV6_ADDR_STR_LEN + 1] != 0xa5u) {
			fprintf(stderr, "addr_to_str exact-size buffer failed\n");
			return 1;
		}

		/* One byte short: -EINVAL, terminated empty, no overrun. */
		memset(small, 0xa5, sizeof(small));
		if (lichen_ipv6_addr_to_str(&str_addr, small, sizeof(small)) !=
		    -EINVAL ||
		    small[0] != '\0') {
			fprintf(stderr, "addr_to_str short buffer failed\n");
			return 1;
		}

		/* Single byte: -EINVAL, terminated empty. */
		one[0] = 0xa5;
		if (lichen_ipv6_addr_to_str(&str_addr, one, sizeof(one)) !=
		    -EINVAL ||
		    one[0] != '\0') {
			fprintf(stderr, "addr_to_str one-byte buffer failed\n");
			return 1;
		}

		/* Zero length: -EINVAL, buffer completely untouched. */
		memset(zero, 0xa5, sizeof(zero));
		if (lichen_ipv6_addr_to_str(&str_addr, zero, 0) != -EINVAL ||
		    (unsigned char)zero[0] != 0xa5u ||
		    (unsigned char)zero[1] != 0xa5u ||
		    (unsigned char)zero[2] != 0xa5u ||
		    (unsigned char)zero[3] != 0xa5u) {
			fprintf(stderr, "addr_to_str zero-length buffer failed\n");
			return 1;
		}

		if (lichen_ipv6_addr_to_str(NULL, buf, sizeof(buf)) != -EINVAL ||
		    lichen_ipv6_addr_to_str(&str_addr, NULL,
					   sizeof(buf)) != -EINVAL) {
			fprintf(stderr, "addr_to_str NULL behavior failed\n");
			return 1;
		}
	}

	return 0;
}
