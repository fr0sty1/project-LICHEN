/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file l2_payload.h
 * @brief Authenticated L2 inner-payload dispatch constants.
 */

#ifndef LICHEN_L2_PAYLOAD_H_
#define LICHEN_L2_PAYLOAD_H_

#include <stddef.h>
#include <stdint.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_L2_DISPATCH_SCHC 0x14U
#define LICHEN_L2_DISPATCH_ROUTING 0x15U
#define LICHEN_L2_ROUTING_TYPE_ANNOUNCE 0x01U

enum lichen_l2_payload_kind {
	LICHEN_L2_PAYLOAD_UNKNOWN = 0,
	LICHEN_L2_PAYLOAD_SCHC = 1,
	LICHEN_L2_PAYLOAD_ROUTING = 2,
};

static inline enum lichen_l2_payload_kind
lichen_l2_payload_classify(const uint8_t *_Nullable payload, size_t len)
{
	if (payload == NULL || len == 0U) {
		return LICHEN_L2_PAYLOAD_UNKNOWN;
	}
	if (payload[0] == LICHEN_L2_DISPATCH_SCHC) {
		return LICHEN_L2_PAYLOAD_SCHC;
	}
	if (payload[0] == LICHEN_L2_DISPATCH_ROUTING) {
		return LICHEN_L2_PAYLOAD_ROUTING;
	}
	return LICHEN_L2_PAYLOAD_UNKNOWN;
}

static inline const uint8_t *_Nullable
lichen_l2_payload_body(const uint8_t *_Nullable payload, size_t len,
		       size_t *_Nullable body_len)
{
	if (body_len != NULL) {
		*body_len = (payload != NULL && len > 0U) ? len - 1U : 0U;
	}
	return (payload != NULL && len > 0U) ? &payload[1] : NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_L2_PAYLOAD_H_ */
