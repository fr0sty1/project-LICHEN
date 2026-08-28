/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_keys_alert.h
 * @brief Authenticated operator alert sink for TOFU key mismatches
 */

#ifndef LICHEN_COAP_KEYS_ALERT_H_
#define LICHEN_COAP_KEYS_ALERT_H_

#include <stddef.h>
#include <stdint.h>

#include <lichen/coap_keys.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_KEY_ALERT_AUTH_KEY_LEN 32U
#define LICHEN_KEY_ALERT_WIRE_LEN 136U

/**
 * Bounded platform transport for one authenticated operator event.
 *
 * The callback MUST copy the payload and durably accept it before returning
 * zero. Backpressure and transient errors use negative errno values and leave
 * the event pending in the key store. It MUST NOT re-enter key-store or alert
 * sink APIs.
 */
typedef int (*lichen_key_alert_transport_cb)(
	void *user, const uint8_t payload[LICHEN_KEY_ALERT_WIRE_LEN], size_t len);

/**
 * Register the authenticated operator sink with the TOFU key store.
 *
 * The key must be device-secret material shared only with the authorized audit
 * receiver. Registration immediately retries any pending mismatch events.
 */
int lichen_key_alert_sink_init(
	const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
	lichen_key_alert_transport_cb transport, void *user);

/** Retry all pending mismatch events after transport backpressure clears. */
int lichen_key_alert_sink_retry(void);

/** Detach the sink and wipe its authentication key. */
void lichen_key_alert_sink_deinit(void);

/**
 * Verify and decode an operator event.
 *
 * Exact length, format version, authenticated tag, and semantic bounds are
 * checked before @p event is modified.
 */
int lichen_key_alert_decode(
	const uint8_t auth_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN],
	const uint8_t *payload, size_t len,
	struct lichen_key_mismatch_audit *event);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_KEYS_ALERT_H_ */
