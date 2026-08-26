/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sos_resource.c
 * @brief SOS resource state machine implementation
 */

#include <lichen/sos_resource.h>
#include <string.h>
#include <errno.h>

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#include <lichen/lichen_log.h>

#ifdef __ZEPHYR__
#ifndef CONFIG_LICHEN_COAP_LOG_LEVEL
#define CONFIG_LICHEN_COAP_LOG_LEVEL LOG_LEVEL_INF
#endif
LICHEN_LOG_MODULE(sos_resource, CONFIG_LICHEN_COAP_LOG_LEVEL);
#else
LICHEN_LOG_MODULE(sos_resource, LOG_LEVEL_WRN);
#endif

/* ─── Secure zero for Zephyr/native builds ────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/toolchain.h>
#else
/* Native/host builds: inline volatile memset */
#ifndef compiler_barrier
#define compiler_barrier() __asm__ volatile("" ::: "memory")
#endif
#endif

static inline void sos_secure_zero(void *ptr, size_t len)
{
	volatile uint8_t *p = ptr;
	while (len--) {
		*p++ = 0;
	}
	compiler_barrier();
}

/* ─── State machine implementation ────────────────────────────────────────── */

void sos_resource_init(struct sos_resource *res)
{
	if (res == NULL) {
		return;
	}
	memset(res, 0, sizeof(*res));
	res->state = SOS_STATE_IDLE;
	res->originator_valid = false;
}

enum sos_state sos_resource_state(const struct sos_resource *res)
{
	if (res == NULL) {
		return SOS_STATE_IDLE;
	}
	return res->state;
}

bool sos_resource_is_active(const struct sos_resource *res)
{
	if (res == NULL) {
		return false;
	}
	return res->state == SOS_STATE_ACTIVE ||
	       res->state == SOS_STATE_ACKNOWLEDGED;
}

int sos_resource_activate(struct sos_resource *res,
			  const uint8_t iid[8],
			  uint64_t now,
			  uint32_t seq)
{
	if (res == NULL || iid == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Only allow activation from IDLE state */
	if (res->state != SOS_STATE_IDLE) {
		LOG_WRN("SOS activate rejected: already in state %s",
			sos_state_name(res->state));
		return -EALREADY;
	}

	/* SECURITY: Sequence must advance to prevent replay of old activations */
	if (seq <= res->sequence) {
		LOG_WRN("SOS activate rejected: sequence %u not > %u",
			seq, res->sequence);
		return -EALREADY;
	}

	memcpy(res->originator_iid, iid, 8);
	res->originator_valid = true;
	res->timestamp = now;
	res->sequence = seq;
	res->state = SOS_STATE_ACTIVE;

	LOG_INF("SOS activated from %02x%02x%02x%02x%02x%02x%02x%02x seq=%u",
		iid[0], iid[1], iid[2], iid[3],
		iid[4], iid[5], iid[6], iid[7], seq);

	return 0;
}

int sos_resource_acknowledge(struct sos_resource *res, uint64_t now)
{
	if (res == NULL) {
		return -EINVAL;
	}

	/* Only ACTIVE state can be acknowledged */
	if (res->state != SOS_STATE_ACTIVE) {
		LOG_WRN("SOS acknowledge rejected: not in ACTIVE state");
		return -ENOENT;
	}

	res->ack_timestamp = now;
	res->state = SOS_STATE_ACKNOWLEDGED;

	LOG_INF("SOS acknowledged at %llu", (unsigned long long)now);

	return 0;
}

int sos_resource_cancel(struct sos_resource *res,
			const uint8_t iid[8],
			uint32_t seq)
{
	if (res == NULL || iid == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Only active states can be cancelled */
	if (res->state != SOS_STATE_ACTIVE &&
	    res->state != SOS_STATE_ACKNOWLEDGED) {
		LOG_WRN("SOS cancel rejected: not in active state");
		return -ENOENT;
	}

	/* SECURITY: Only the originator can cancel their own SOS */
	if (!res->originator_valid ||
	    memcmp(res->originator_iid, iid, 8) != 0) {
		LOG_WRN("SOS cancel rejected: not originator");
		return -EACCES;
	}

	/* SECURITY: Sequence must strictly advance to prevent replay */
	if (seq <= res->sequence) {
		LOG_WRN("SOS cancel rejected: sequence %u not > %u",
			seq, res->sequence);
		return -EALREADY;
	}

	LOG_INF("SOS cancelled by originator seq=%u", seq);

	/* Update sequence before reset to track for future replay protection */
	res->sequence = seq;

	/* Transition through CANCELLED to IDLE (instantaneous per spec 18.4) */
	res->state = SOS_STATE_CANCELLED;
	sos_resource_reset(res);

	return 0;
}

void sos_resource_reset(struct sos_resource *res)
{
	if (res == NULL) {
		return;
	}

	/* SECURITY: Clear originator data to prevent information leakage */
	sos_secure_zero(res->originator_iid, sizeof(res->originator_iid));
	res->originator_valid = false;
	res->timestamp = 0;
	res->ack_timestamp = 0;
	/*
	 * SECURITY: sequence is intentionally NOT reset to prevent replay
	 * attacks across resource resets. An attacker cannot replay an old
	 * SOS activation message even after the resource is cleared.
	 */
	res->state = SOS_STATE_IDLE;

	LOG_DBG("SOS reset to idle");
}

const char *sos_state_name(enum sos_state state)
{
	switch (state) {
	case SOS_STATE_IDLE:
		return "idle";
	case SOS_STATE_ACTIVE:
		return "active";
	case SOS_STATE_ACKNOWLEDGED:
		return "acknowledged";
	case SOS_STATE_CANCELLED:
		return "cancelled";
	default:
		return "unknown";
	}
}
