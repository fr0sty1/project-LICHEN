/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file kiss_transport.h
 * @brief KISS TNC transport for LICHEN
 *
 * Implements the KISS TNC protocol (KA9Q/K3MC) for host interface connectivity.
 * KISS provides byte-stuffed framing over serial links, compatible with legacy
 * amateur radio applications (APRSDroid, Direwolf, Xastir, Linux AX.25 stack).
 *
 * Reference: http://www.ka9q.net/papers/kiss.html
 *
 * Port assignments per spec/kiss-framing.md:
 * - Port 0: AX.25/APRS frames (legacy TNC app compatibility)
 * - Port 1: Raw LICHEN link frames (debugging, native apps, packet injection)
 * - Ports 2-15: Reserved for future use
 *
 * Frame format:
 *   FEND | CMD | DATA... | FEND
 *   0xC0 | 1B  | 0-N     | 0xC0
 *
 * CMD byte: high nibble = port (0-15), low nibble = command (0-15)
 */

#ifndef LICHEN_TRANSPORT_KISS_TRANSPORT_H_
#define LICHEN_TRANSPORT_KISS_TRANSPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── KISS protocol constants ─────────────────────────────────────────────── */

/** KISS special byte values */
#define KISS_FEND       0xC0u   /**< Frame delimiter */
#define KISS_FESC       0xDBu   /**< Escape prefix */
#define KISS_TFEND      0xDCu   /**< Escaped FEND (after FESC) */
#define KISS_TFESC      0xDDu   /**< Escaped FESC (after FESC) */

/** KISS command types (low nibble of CMD byte) */
#define KISS_CMD_DATA        0x00u  /**< Data frame */
#define KISS_CMD_TXDELAY     0x01u  /**< TX key-up delay (10ms units) */
#define KISS_CMD_PERSISTENCE 0x02u  /**< CSMA p-value (0-255 -> 0.0-1.0) */
#define KISS_CMD_SLOTTIME    0x03u  /**< CSMA slot interval (10ms units) */
#define KISS_CMD_TXTAIL      0x04u  /**< TX tail time (obsolete) */
#define KISS_CMD_FULLDUPLEX  0x05u  /**< 0=half, 1=full duplex */
#define KISS_CMD_SETHARDWARE 0x06u  /**< TNC-specific commands */
#define KISS_CMD_RETURN      0x0Fu  /**< Exit KISS mode (ignored by LICHEN) */

/** KISS port numbers for LICHEN (updated per codereview project-LICHEN-9bnm)
 *
 * Per spec/kiss-framing.md:3.3 and LCI spec 11-lci.md:17.3:
 * - 0: AX.25/APRS (legacy TNC app compatibility)
 * - 1: Raw LICHEN link frames (debug, injection)
 * - 2: LCI IPv6 datagrams (Meshtastic uMB4.2-style LCI mapping)
 * - 3: LCI control plane (config, status, keys, CoAP)
 *
 * **Error Mapping Table** (LCI errors returned via port 3; uses SenML-CBOR ct=112 per 11-lci.md for status compatibility):
 * | Code | Type                | Payload (SenML-CBOR)                     | Notes |
 * |------|---------------------|------------------------------------------|-------|
 * | 0x00 | Success             | {"bn":"urn:dev:mac:...", "s":0}         | Standard ACK; aligns with LCI status |
 * | 0x01 | Framing/Parse Error | {"bn":"...", "e":"framing","v":1}       | Matches KISS decode errors (see kiss_decode_byte) |
 * | 0x02 | Unsupported         | {"bn":"...", "e":"unsupported","port":N}| For ports >3 or unknown cmd; tools ignore per KISS |
 * | 0x03 | Overflow            | {"bn":"...", "e":"overflow","v":1024}   | KISS_MAX_PAYLOAD exceeded; stats updated |
 * | 0x04 | Security/OSCORE     | {"bn":"...", "e":"auth","v":"oscore"}   | OSCORE failures mapped for LCI security |
 * | 0xFF | Generic             | {"bn":"...", "e":"generic","vs":"msg"}  | Catch-all; prefers SenML for LCI consistency |
 *
 * **Compatibility Notes with Existing KISS Tools:** (see standards/ham-radio.md:43 and kiss-framing.md:2.1)
 * - kissparms/kissutil/Direwolf/Xastir/APRSDroid: port 0 only; ports 2/3 + error payloads on 3 safely ignored (KISS spec allows).
 * - Meshtastic serial (uMB4.2+ protobuf over KISS port 0): LCI ports 2/3 are extensions; no conflict as clients filter by port/cmd. Error table ensures graceful fallback.
 * - No breakage for legacy AX.25; port 3 errors use SenML-CBOR for easy parsing by modern clients.
 * - SetHardware (cmd=6) on any port; responses use cmd|0x80 on port 0 per KA9Q spec.
 * - Unknown port: stats.unknown_port++, LOG_WRN; optional lci_ctrl_cb error 0x02 per table.
 *
 * Cross-refs updated. Parallel Rust impl in lichen-kiss/src/bridge.rs:287 should adopt same table for interop.
 */
#define KISS_PORT_AX25       0u     /**< AX.25/APRS frames */
#define KISS_PORT_LICHEN_RAW 1u     /**< Raw LICHEN link frames */
#define KISS_PORT_LCI_IPV6   2u     /**< IPv6 datagrams for LCI (Meshtastic-style LCI mapping) */
#define KISS_PORT_LCI_CTRL   3u     /**< Control (config, status, keys) for LCI */
#define KISS_PORT_MAX        15u    /**< Maximum port number */

/** Extract port and command from CMD byte */
#define KISS_CMD_PORT(cmd)    (((cmd) >> 4u) & 0x0Fu)
#define KISS_CMD_TYPE(cmd)    ((cmd) & 0x0Fu)
#define KISS_CMD_MAKE(port, type) ((((port) & 0x0Fu) << 4u) | ((type) & 0x0Fu))

/** Maximum frame payload size (after unescaping) */
#define KISS_MAX_PAYLOAD     1024u

/** Maximum raw LICHEN link frame carried on port 1 */
#define KISS_RAW_MAX_PAYLOAD 255u

/** Default KISS timing parameters (10ms units) */
#define KISS_DEFAULT_TXDELAY     50u   /**< 500ms */
#define KISS_DEFAULT_PERSISTENCE 63u   /**< p=0.25 */
#define KISS_DEFAULT_SLOTTIME    10u   /**< 100ms */

/* ─── BLE KISS GATT UUIDs ─────────────────────────────────────────────────── */

/**
 * BLE KISS GATT service UUIDs per spec/kiss-framing.md section 5.5
 *
 * Service:   00000001-ba2a-46c9-ae49-01b0961f68bb
 * TX to dev: 00000002-ba2a-46c9-ae49-01b0961f68bb (Write)
 * RX from:   00000003-ba2a-46c9-ae49-01b0961f68bb (Notify, Read)
 *
 * These are raw 128-bit UUIDs in little-endian byte order.
 * Use with Zephyr BT_UUID_DECLARE_128() or equivalent.
 */
#define KISS_BLE_UUID_SVC  { 0xbb, 0x68, 0x1f, 0x96, 0xb0, 0x01, 0x49, 0xae, \
			     0xc9, 0x46, 0x2a, 0xba, 0x01, 0x00, 0x00, 0x00 }
#define KISS_BLE_UUID_TX   { 0xbb, 0x68, 0x1f, 0x96, 0xb0, 0x01, 0x49, 0xae, \
			     0xc9, 0x46, 0x2a, 0xba, 0x02, 0x00, 0x00, 0x00 }
#define KISS_BLE_UUID_RX   { 0xbb, 0x68, 0x1f, 0x96, 0xb0, 0x01, 0x49, 0xae, \
			     0xc9, 0x46, 0x2a, 0xba, 0x03, 0x00, 0x00, 0x00 }

/* ─── KISS timing parameters ──────────────────────────────────────────────── */

/**
 * @brief KISS timing parameters
 *
 * These map to LICHEN's channel access mechanism:
 * - txdelay: Post-preamble settling time (LoRa uses CAD, not carrier detect)
 * - persistence: Probability of transmitting when channel is clear
 * - slottime: Backoff slot duration
 */
struct kiss_params {
	uint8_t txdelay;     /**< TX delay in 10ms units */
	uint8_t persistence; /**< CSMA p-value (0-255) */
	uint8_t slottime;    /**< Slot time in 10ms units */
	uint8_t txtail;      /**< TX tail in 10ms units (stored but ignored) */
	bool fullduplex;     /**< Full duplex mode (stored but ignored for LoRa) */
};

/* ─── Statistics ──────────────────────────────────────────────────────────── */

/**
 * @brief KISS transport statistics
 */
struct kiss_transport_stats {
	uint32_t rx_frames;         /**< Total frames received */
	uint32_t tx_frames;         /**< Total frames transmitted */
	uint32_t rx_data_port0;     /**< Data frames received on port 0 (AX.25) */
	uint32_t rx_data_port1;     /**< Data frames received on port 1 (raw LICHEN) */
	uint32_t rx_data_lci_ipv6;  /**< LCI IPv6 datagrams (port 2) */
	uint32_t rx_data_lci_ctrl;  /**< LCI control (port 3: config/status/keys) */
	uint32_t tx_data_port0;     /**< Data frames transmitted on port 0 */
	uint32_t tx_data_port1;     /**< Data frames transmitted on port 1 */
	uint32_t tx_data_lci_ipv6;  /**< LCI IPv6 transmitted */
	uint32_t tx_data_lci_ctrl;  /**< LCI control transmitted */
	uint32_t rx_commands;       /**< Control commands received */
	uint32_t rx_bytes;          /**< Total bytes received */
	uint32_t tx_bytes;          /**< Total bytes transmitted */
	uint32_t frame_errors;      /**< Framing/escape errors */
	uint32_t overflow_errors;   /**< Buffer overflow errors */
	uint32_t unknown_port;      /**< Frames on unknown ports */
};

/* ─── Callbacks ───────────────────────────────────────────────────────────── */

/**
 * @brief Callback for received AX.25/APRS frames (port 0)
 *
 * @param data Pointer to AX.25 frame data (after KISS unframing)
 * @param len  Length of frame data
 * @param user_ctx User context pointer
 */
typedef void (*kiss_ax25_rx_cb_t)(const uint8_t *data, size_t len, void *user_ctx);

/**
 * @brief Callback for received raw LICHEN frames (port 1)
 *
 * @param data Pointer to raw LICHEN frame data
 * @param len  Length of frame data (max KISS_MAX_PAYLOAD)
 * @param user_ctx User context pointer
 */
typedef void (*kiss_raw_rx_cb_t)(const uint8_t *data, size_t len, void *user_ctx);

/**
 * @brief Callback for LCI IPv6 datagrams (port 2, Meshtastic-style mapping)
 */
typedef void (*kiss_lci_ipv6_rx_cb_t)(const uint8_t *data, size_t len, void *user_ctx);

/**
 * @brief Callback for LCI control messages (port 3: config, status, keys)
 */
typedef void (*kiss_lci_ctrl_rx_cb_t)(const uint8_t *data, size_t len, void *user_ctx);

/**
 * @brief Callback for SetHardware commands (cmd 6)
 *
 * @param data Pointer to hardware command data
 * @param len  Length of command data
 * @param user_ctx User context pointer
 * @return Response data length (0 = no response), or negative errno
 */
typedef int (*kiss_hw_cmd_cb_t)(const uint8_t *data, size_t len,
				uint8_t *response, size_t max_response,
				void *user_ctx);

/**
 * @brief KISS transport configuration
 */
struct kiss_transport_config {
	kiss_ax25_rx_cb_t ax25_rx_cb;      /**< Callback for AX.25 frames (port 0) */
	kiss_raw_rx_cb_t raw_rx_cb;        /**< Callback for raw frames (port 1) */
	kiss_lci_ipv6_rx_cb_t lci_ipv6_cb; /**< Callback for LCI IPv6 (port 2, Meshtastic-style) */
	kiss_lci_ctrl_rx_cb_t lci_ctrl_cb; /**< Callback for LCI control (port 3: config/status/keys) */
	kiss_hw_cmd_cb_t hw_cmd_cb;        /**< Optional SetHardware callback */
	void *user_ctx;                    /**< User context for callbacks */
};

/* ─── Public API ──────────────────────────────────────────────────────────── */

/**
 * @brief Initialize the KISS transport
 *
 * Sets up the UART device, RX ring buffer, and processing thread.
 * The UART device is selected via devicetree:
 *   chosen { lichen,kiss-uart = &uart1; };
 *
 * @param config Transport configuration with callbacks
 * @return 0 on success
 * @return -EINVAL if config is NULL or missing required callbacks
 * @return -ENODEV if UART device not found or not ready
 * @return -EALREADY if already initialized
 */
int kiss_transport_init(const struct kiss_transport_config *config);

/**
 * @brief Deinitialize the KISS transport
 *
 * Stops the RX thread and releases resources.
 */
void kiss_transport_deinit(void);

/**
 * @brief Check if KISS transport is initialized and ready
 *
 * @return true if transport is ready
 */
bool kiss_transport_is_ready(void);

/**
 * @brief Send an AX.25/APRS frame (port 0)
 *
 * Encodes the frame with KISS framing and transmits over the serial link.
 *
 * @param data Pointer to AX.25 frame data
 * @param len  Length of frame data (max KISS_MAX_PAYLOAD)
 * @return 0 on success
 * @return -EINVAL if data is NULL with len > 0
 * @return -EMSGSIZE if len > KISS_MAX_PAYLOAD
 * @return -ENODEV if transport not initialized
 */
int kiss_transport_send_ax25(const uint8_t *data, size_t len);

/**
 * @brief Send a raw LICHEN frame (port 1)
 *
 * Encodes the frame with KISS framing and transmits over the serial link.
 *
 * @param data Pointer to raw LICHEN frame data
 * @param len  Length of frame data (max KISS_RAW_MAX_PAYLOAD)
 * @return 0 on success
 * @return -EINVAL if data is NULL with len > 0
 * @return -EMSGSIZE if len > KISS_RAW_MAX_PAYLOAD
 * @return -ENODEV if transport not initialized
 */
int kiss_transport_send_raw(const uint8_t *data, size_t len);

/**
 * @brief Send a KISS frame on a specific port
 *
 * Low-level send function for arbitrary port numbers.
 *
 * @param port KISS port number (0-15)
 * @param data Pointer to frame data
 * @param len  Length of frame data
 * @return 0 on success, negative errno on failure
 */
int kiss_transport_send(uint8_t port, const uint8_t *data, size_t len);

/**
 * @brief Get current KISS timing parameters
 *
 * @param params Output structure for parameters
 * @return 0 on success
 * @return -EINVAL if params is NULL
 */
int kiss_transport_get_params(struct kiss_params *params);

/**
 * @brief Set KISS timing parameters
 *
 * @param params New timing parameters
 * @return 0 on success
 * @return -EINVAL if params is NULL
 */
int kiss_transport_set_params(const struct kiss_params *params);

/**
 * @brief Get transport statistics
 *
 * @param stats Output structure for statistics
 * @return 0 on success
 * @return -EINVAL if stats is NULL
 */
int kiss_transport_get_stats(struct kiss_transport_stats *stats);

/**
 * @brief Reset transport statistics
 */
void kiss_transport_reset_stats(void);

/* ─── KISS framing utilities (for use by other transports) ────────────────── */

/**
 * @brief Encode data with KISS framing
 *
 * Adds FEND delimiters and escapes special bytes (FEND/FESC only).
 * Uses incremental buffer checks (exact size, not conservative worst-case).
 * Matches Rust lichen-kiss::kiss_encode_raw and kiss_escape.
 *
 * @param port    KISS port number (0-15)
 * @param cmd     Command type (KISS_CMD_DATA for data frames)
 * @param data    Input data to encode
 * @param data_len Length of input data
 * @param frame   Output buffer for KISS frame
 * @param frame_max Maximum output buffer size
 * @param frame_len Output: actual frame length
 * @return 0 on success
 * @return -EINVAL if arguments invalid
 * @return -ENOMEM if output buffer too small for actual encoded frame
 */
int kiss_encode(uint8_t port, uint8_t cmd,
		const uint8_t *data, size_t data_len,
		uint8_t *frame, size_t frame_max, size_t *frame_len);

/**
 * @brief Decode state for streaming KISS decoding
 */
struct kiss_decode_ctx {
	uint8_t buf[KISS_MAX_PAYLOAD];
	size_t len;
	uint8_t cmd;
	bool in_frame;
	bool escape_next;
	bool has_cmd;
};

/**
 * @brief Initialize a KISS decode context
 *
 * @param ctx Decode context to initialize
 */
void kiss_decode_init(struct kiss_decode_ctx *ctx);

/**
 * @brief Process one byte through KISS decoder
 *
 * @param ctx  Decode context
 * @param byte Received byte
 * @return 1 if a complete frame is ready (check ctx->cmd, ctx->buf, ctx->len)
 * @return 0 if more data needed
 * @return -EOVERFLOW if frame exceeds buffer size
 * @return -EILSEQ if invalid escape sequence
 */
int kiss_decode_byte(struct kiss_decode_ctx *ctx, uint8_t byte);

/* ─── Test hooks ──────────────────────────────────────────────────────────── */

#ifdef CONFIG_ZTEST
/**
 * @brief Test helper: inject raw bytes as if received from UART
 *
 * @param data Raw bytes to inject
 * @param len  Length of data
 * @return Number of complete frames processed
 */
int kiss_transport_test_inject_rx(const uint8_t *data, size_t len);

/**
 * @brief Test helper: get last transmitted KISS frame
 *
 * @param buf   Output buffer for frame data
 * @param max   Maximum bytes to copy
 * @param len   Output: actual frame length
 * @return 0 on success
 * @return -EINVAL if buf or len is NULL
 */
int kiss_transport_test_get_last_tx(uint8_t *buf, size_t max, size_t *len);

/**
 * @brief Test helper: reset transport state for test isolation
 */
void kiss_transport_test_reset(void);
#endif /* CONFIG_ZTEST */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_TRANSPORT_KISS_TRANSPORT_H_ */
