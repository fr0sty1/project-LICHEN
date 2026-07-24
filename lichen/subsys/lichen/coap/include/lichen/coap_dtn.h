/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_dtn.h
 * @brief DTN dead drop provider API
 *
 * Defines the deaddrop provider interface for DTN (Delay-Tolerant
 * Networking) store-and-forward message buffering. Applications
 * register a provider to handle incoming DTN message storage and
 * retrieval from the deaddrop CoAP resources.
 *
 * See spec sections 9.8 and 18.3 for protocol details.
 */

#ifndef LICHEN_COAP_DTN_H_
#define LICHEN_COAP_DTN_H_

#include <stdint.h>
#include <stddef.h>
#include <lichen/routing/dtn.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Dead drop provider callbacks
 *
 * Registered via lichen_coap_deaddrop_register() to handle
 * /deaddrop resource operations. The dtn_buf field is set by
 * the registration function and should not be touched by callers.
 */
struct lichen_deaddrop_provider {
	/** Store a deaddrop message */
	int (*store)(const uint8_t *payload, size_t len);
	/** Retrieve deaddrop messages for a node */
	int (*retrieve)(uint8_t *buf, size_t buf_len, const char *node);
	/** DTN buffer (set by registration, do not modify) */
	struct lichen_dtn_buffer *dtn_buf;
};

/**
 * @brief Register a dead drop provider.
 *
 * @param[in] provider Provider callbacks (must remain valid for lifetime)
 * @return 0 on success, -EINVAL if provider is NULL
 */
int lichen_coap_deaddrop_register(const struct lichen_deaddrop_provider *provider);

/**
 * @brief Get the registered dead drop provider.
 *
 * @return Pointer to the registered provider, or NULL if none registered
 */
const struct lichen_deaddrop_provider *lichen_coap_deaddrop_provider_get(void);

/**
 * @brief Initialize the DTN CoAP subsystem.
 *
 * Called automatically by lichen_coap_deaddrop_register().
 * Call explicitly to fail-fast on init errors.
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_dtn_init(void);

/**
 * @brief Run periodic DTN expiry.
 *
 * @return Number of expired messages removed
 */
uint16_t lichen_dtn_expire_periodic(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_DTN_H_ */

