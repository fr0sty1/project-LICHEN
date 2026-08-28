/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_rangetest.h
 * @brief CoAP range testing resources (spec/12-apps.md section 18.7)
 *
 * Implements:
 * - POST /diag/rangetest  Extended range test (18.7.2)
 * - GET  /diag/rangetest  Continuous range test, Observable (18.7.3)
 * - GET  /diag/traceroute Mesh path discovery (18.7.4)
 *
 * Wire contract (matches the Python/Rust references and
 * test/vectors/rangetest.json):
 * - Responses for /diag/rangetest are SenML+CBOR packs (Content-Format 112)
 *   with numeric labels bn=-2, bt=-3, n=0, u=1, v=2, emitted in that order.
 *   Floating point values encode as 64-bit floats (0xfb).
 * - Responses for /diag/traceroute are a CBOR map (Content-Format 60) with
 *   text keys "hops", "total_hops", "total_rtt_ms" in that order.
 * - Request bodies are CBOR maps with text keys: "seq", "payload_len",
 *   "count" for POST; "interval_ms" for GET. Unknown keys are ignored.
 *   Values are accepted only as unsigned integers; in particular a boolean
 *   or floating point "seq"/"interval_ms" is rejected with 4.00, and
 *   "interval_ms" must be strictly positive.
 */

#ifndef LICHEN_COAP_RANGETEST_H_
#define LICHEN_COAP_RANGETEST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum test payload size per spec 18.7.2. */
#define LICHEN_RANGETEST_MAX_PAYLOAD_LEN 255U
/** Maximum response count per spec 18.7.2. */
#define LICHEN_RANGETEST_MAX_COUNT 100U
/** Default continuous-test interval in milliseconds (spec 18.7.3). */
#define LICHEN_RANGETEST_DEFAULT_INTERVAL_MS 5000U
/** Maximum traceroute hops reported by this node. */
#define LICHEN_RANGETEST_MAX_HOPS 8U
/** Maximum IPv6 text address length including NUL (INET6_ADDRSTRLEN). */
#define LICHEN_RANGETEST_ADDR_MAX 46U
/** EUI-64 length in bytes. */
#define LICHEN_RANGETEST_EUI64_LEN 8U
/** SenML base name buffer size: "urn:dev:mac:" + 16 hex + ':' + NUL. */
#define LICHEN_RANGETEST_BN_MAX 31U
/** Content-Format application/senml+cbor (RFC 8428). */
#define LICHEN_RANGETEST_CF_SENML_CBOR 112U
/** Content-Format application/cbor (RFC 8949). */
#define LICHEN_RANGETEST_CF_CBOR 60U

/** Radio link quality metrics reported by a range test. */
struct lichen_rangetest_metrics {
	double rssi; /**< Received signal strength in dBm (negative). */
	double snr;  /**< Signal-to-noise ratio in dB. */
	uint8_t sf;  /**< LoRa spreading factor. */
	double freq; /**< Center frequency in MHz. */
};

/** One hop of a mesh traceroute. */
struct lichen_rangetest_hop {
	char addr[LICHEN_RANGETEST_ADDR_MAX]; /**< Next-hop IPv6 address. */
	double rssi;                          /**< Hop link RSSI in dBm. */
	double rtt_ms;                        /**< Hop round-trip time in ms. */
};

/** Provider configuration (all members optional; see lichen_rangetest_init). */
struct lichen_rangetest_config {
	const uint8_t *eui64; /**< 8 node EUI-64 bytes; NULL = all-zero. */
	uint32_t (*now)(void); /**< Unix seconds; NULL = 0. */
	void (*get_metrics)(
		struct lichen_rangetest_metrics *metrics); /**< NULL = defaults. */
	size_t (*get_hops)(struct lichen_rangetest_hop *hops,
			   size_t max_hops); /**< NULL = no hops. */
};

/** Decoded POST /diag/rangetest request body. */
struct lichen_rangetest_request {
	bool has_seq;
	uint32_t seq;
	bool has_payload_len;
	uint32_t payload_len;
	bool has_count;
	uint32_t count;
};

/** Decoded GET /diag/rangetest request body. */
struct lichen_rangetest_interval {
	bool has_interval_ms;
	uint32_t interval_ms;
};

/**
 * @brief Initialize the range test resource state.
 *
 * Copies @p config and resets seq to 0 and interval to
 * LICHEN_RANGETEST_DEFAULT_INTERVAL_MS. Defaults for unset providers:
 * all-zero EUI-64, time 0, static metrics {-85.0 dBm, 7.5 dB, SF9,
 * 906.875 MHz}, no traceroute hops.
 *
 * @return 0 on success, -EINVAL if @p config is NULL.
 */
int lichen_rangetest_init(const struct lichen_rangetest_config *config);

/** @brief Current range test sequence number. */
uint32_t lichen_rangetest_seq(void);

/** @brief Current continuous-test interval in milliseconds. */
uint32_t lichen_rangetest_interval_ms(void);

/**
 * @brief Advance the sequence number and notify observers (spec 18.7.3).
 *
 * Mirrors the reference update(): increments the sequence number and pushes
 * a fresh reading to registered observers.
 */
void lichen_rangetest_update(void);

/**
 * @brief Encode the SenML pack for a range test reading (spec 18.7.2).
 *
 * Produces exactly the canonical bytes: array of six records with labels
 * bn/bt/n/u/v in ascending numeric order, 64-bit float encoding for
 * rssi/snr/freq, minimal-length unsigned integers for bt/seq/sf.
 *
 * @return Encoded length, or -EINVAL/-ENOBUFS/-ERANGE on error.
 */
int lichen_rangetest_senml_encode(uint8_t *buf, size_t buf_size,
				  const char *base_name, uint32_t base_time,
				  uint32_t seq,
				  const struct lichen_rangetest_metrics *metrics);

/**
 * @brief Strictly decode a POST /diag/rangetest body.
 *
 * The body must be a single CBOR map of text keys. "seq" must be an
 * unsigned integer, "payload_len" in 0..=255, "count" in 1..=100.
 * Unknown keys are ignored. Decoding is atomic: on failure @p req is
 * left unmodified.
 *
 * @return 0 on success (empty @p len yields an all-clear request),
 *	   -EBADMSG/-EINVAL on error.
 */
int lichen_rangetest_request_decode(const uint8_t *buf, size_t len,
				    struct lichen_rangetest_request *req);

/**
 * @brief Strictly decode a GET /diag/rangetest body.
 *
 * Same map rules as lichen_rangetest_request_decode(); "interval_ms" must
 * be an unsigned integer > 0 when present.
 *
 * @return 0 on success, -EBADMSG/-EINVAL on error.
 */
int lichen_rangetest_interval_decode(const uint8_t *buf, size_t len,
				     struct lichen_rangetest_interval *out);

/**
 * @brief Encode the traceroute response map (spec 18.7.4).
 *
 * Emits {"hops":[...],"total_hops":N,"total_rtt_ms":X} where total_rtt_ms
 * is the last hop's RTT as a 64-bit float (0.0 when there are no hops).
 *
 * @return Encoded length, or -EINVAL/-ENOBUFS on error.
 */
int lichen_traceroute_encode(uint8_t *buf, size_t buf_size,
			     const struct lichen_rangetest_hop *hops,
			     size_t hop_count);

/** @brief GET /diag/rangetest handler (continuous test, spec 18.7.3). */
int lichen_rangetest_get_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len);

/** @brief POST /diag/rangetest handler (extended test, spec 18.7.2). */
int lichen_rangetest_post_handler(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len);

/** @brief GET /diag/traceroute handler (spec 18.7.4). */
int lichen_traceroute_get_handler(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len);

/** @brief Observer notification callback for /diag/rangetest. */
void lichen_rangetest_notify_cb(struct coap_resource *resource,
				struct coap_observer *observer);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_RANGETEST_H_ */
