/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_dtn.h
 * @brief DTN (Delay/Disruption Tolerant Networking) for LICHEN nodes
 *
 * Provides dead drop messaging via the /deaddrop resource:
 * - POST /deaddrop - Store a message for a recipient (OSCORE or local admin)
 * - GET /deaddrop?node=<eui64> - Retrieve pending messages
 *
 * Uses RPL DTN buffer for message storage with configurable TTL and
 * rate limiting per spec 9.8.
 *
 * SECURITY: When CONFIG_LICHEN_COAP_SERVER_OSCORE is enabled, POST
 * requires OSCORE protection from mesh peers. Unprotected POST is
 * only accepted from local admin (LCI via SLIP/BLE).
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
 * @brief Dead drop message provider
 *
 * Application registers a provider to handle persistent storage and
 * retrieval of dead drop messages. The provider's dtn_buf is set
 * automatically by lichen_coap_deaddrop_register().
 */
struct lichen_deaddrop_provider {
	/**
	 * @brief Store a dead drop message
	 * @param[in] payload Message payload (CBOR SenML)
	 * @param[in] len Payload length
	 * @return 0 on success, negative errno on failure
	 */
	int (*store)(const uint8_t *payload, size_t len);

	/**
	 * @brief Retrieve dead drop messages for a node
	 * @param[out] buf Output buffer for CBOR SenML payload
	 * @param[in] buf_len Buffer size
	 * @param[in] node Recipient node identifier (or NULL for all)
	 * @return Number of bytes written, or negative errno on failure
	 */
	int (*retrieve)(uint8_t *buf, size_t buf_len, const char *node);

	/** DTN storage buffer (set automatically on register) */
	struct lichen_dtn_buffer *dtn_buf;
};

/**
 * @brief Register a dead drop message provider
 *
 * Must be called before the CoAP server handles /deaddrop requests.
 * Initializes the DTN buffer and starts periodic expiry.
 *
 * @param[in] provider Provider callbacks (must remain valid)
 * @return 0 on success, negative errno on failure
 */
int lichen_coap_deaddrop_register(const struct lichen_deaddrop_provider *provider);

/**
 * @brief Initialize DTN subsystem
 *
 * Initializes mutexes and dependencies (OSCORE, CoAP client).
 * Called automatically by lichen_coap_deaddrop_register().
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_coap_dtn_init(void);

/**
 * @brief Run periodic DTN message expiry
 *
 * @return Number of expired messages removed
 */
uint16_t lichen_dtn_expire_periodic(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_DTN_H_ */
