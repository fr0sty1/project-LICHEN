/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/checkin_resource.h
 * @brief CoAP resource handlers for Check-In / Roll Call (spec 18.6)
 *
 * Thin Zephyr glue over the pure codec/service in lichen/checkin.h.
 * Exposes:
 * - POST /checkin          (18.6.1)  -> 2.04 Changed / 4.00
 * - GET  /checkin                    -> 2.05 {"checkins":[...]}
 * - POST /rollcall         (18.6.2)  -> 2.01 Created / 4.00 / 5.03
 * - GET  /rollcall[/<id>]  (18.6.3)  -> 2.05 status document(s)
 * - PUT  /config/checkin   (18.6.4)  -> 2.04 Changed / 4.00
 *
 * The module owns a single service instance sized by
 * CONFIG_LICHEN_CHECKIN_MAX_CHECKINS / CONFIG_LICHEN_CHECKIN_MAX_ROLLCALLS
 * and serializes access with a mutex (the core service itself is
 * thread-unsafe by design). Payload encode/decode buffers are
 * CONFIG_LICHEN_CHECKIN_PAYLOAD_MAX bytes.
 *
 * GET /rollcall/<id> for an unknown id returns the full list document,
 * matching the Python reference resource (2.05 Content).
 *
 * Resource registration uses COAP_RESOURCE_DEFINE against the
 * lichen_coap_server service; enable CONFIG_LICHEN_CHECKIN_RESOURCE
 * together with CONFIG_LICHEN_COAP_SERVER_STANDALONE. The handler
 * functions themselves are always compiled so tests can exercise them
 * directly.
 */

#ifndef LICHEN_CHECKIN_RESOURCE_H_
#define LICHEN_CHECKIN_RESOURCE_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/coap.h>

#include <lichen/checkin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Access the module's service instance (read-only use recommended).
 */
struct lichen_checkin_service *
lichen_checkin_resource_service(void);

/**
 * @brief Override the service clock (seconds). Passing use_override=false
 *        restores the uptime-derived clock. Intended for tests.
 */
void lichen_checkin_resource_set_time(uint64_t now, bool use_override);

/** CoAP handler for POST /checkin (spec 18.6.1). */
int lichen_checkin_post_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len);

/** CoAP handler for GET /checkin: {"checkins":[...]} document. */
int lichen_checkin_get_handler(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len);

/** CoAP handler for POST /rollcall (spec 18.6.2). */
int lichen_rollcall_post_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len);

/** CoAP handler for GET /rollcall and GET /rollcall/<id> (spec 18.6.3). */
int lichen_rollcall_get_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len);

/** CoAP handler for PUT /config/checkin (spec 18.6.4). */
int lichen_checkin_config_put_handler(struct coap_resource *resource,
				      struct coap_packet *request,
				      struct sockaddr *addr, socklen_t addr_len);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_CHECKIN_RESOURCE_H_ */
