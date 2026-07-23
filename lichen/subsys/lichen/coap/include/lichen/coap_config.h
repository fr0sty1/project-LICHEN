/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_config.h
 * @brief LCI /config resource handlers per spec/11-lci.md section 17.5.2
 *
 * Provides CoAP server resources for node configuration:
 * - GET/PUT /config - node name and role
 * - GET/PUT /config/radio - radio parameters
 * - GET /config/identity - read-only identity info (EUI-64, pubkey, addresses)
 *
 * Configuration is persisted via Zephyr settings subsystem when available.
 * CBOR payloads use string keys per LCI spec.
 */

#ifndef LICHEN_COAP_CONFIG_H_
#define LICHEN_COAP_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum node name length (including NUL terminator) */
#define LICHEN_CONFIG_NAME_MAX_LEN 32

/** Maximum role string length */
#define LICHEN_CONFIG_ROLE_MAX_LEN 16

/** Maximum IPv6 address string length */
#define LICHEN_CONFIG_ADDR_MAX_LEN 46

/**
 * @brief Node role values per LCI spec
 */
enum lichen_config_role {
	LICHEN_CONFIG_ROLE_LEAF = 0,
	LICHEN_CONFIG_ROLE_ROUTER = 1,
	LICHEN_CONFIG_ROLE_BORDER_ROUTER = 2,
};

/**
 * @brief Radio coding rate values
 */
enum lichen_config_coding_rate {
	LICHEN_CONFIG_CR_4_5 = 0, /* 4/5 */
	LICHEN_CONFIG_CR_4_6 = 1, /* 4/6 */
	LICHEN_CONFIG_CR_4_7 = 2, /* 4/7 */
	LICHEN_CONFIG_CR_4_8 = 3, /* 4/8 */
};

/**
 * @brief Node configuration structure
 */
struct lichen_config_node {
	char name[LICHEN_CONFIG_NAME_MAX_LEN];
	enum lichen_config_role role;
};

/**
 * @brief Radio configuration structure
 *
 * freq_khz uses kHz units (e.g., 906875 for 906.875 MHz) to avoid floating point.
 */
struct lichen_config_radio {
	uint32_t freq_khz;           /* Frequency in kHz */
	uint16_t bw_khz;             /* Bandwidth in kHz */
	uint8_t sf;                  /* Spreading factor (6-12) */
	enum lichen_config_coding_rate cr;
	int8_t tx_power_dbm;         /* TX power in dBm */
	uint16_t sync_word;          /* Sync word */
};

/**
 * @brief Identity information structure (read-only)
 */
struct lichen_config_identity {
	uint8_t eui64[8];                            /* EUI-64 address */
	uint8_t pubkey[32];                          /* Ed25519 public key */
	bool pubkey_valid;                           /* True if pubkey is set */
	char link_local[LICHEN_CONFIG_ADDR_MAX_LEN]; /* fe80::... */
	char primary[LICHEN_CONFIG_ADDR_MAX_LEN];    /* primary 02xx mesh address */
	char gua[LICHEN_CONFIG_ADDR_MAX_LEN];        /* GUA address or empty */
};

/**
 * @brief Configuration provider callbacks
 *
 * The application must implement these to provide actual configuration values.
 * The CoAP handlers call these to get/set configuration.
 */
struct lichen_config_provider {
	/**
	 * @brief Get current node configuration
	 * @param[out] config Output buffer for configuration
	 * @return 0 on success, negative errno on failure
	 */
	int (*node_get)(struct lichen_config_node *config);

	/**
	 * @brief Set node configuration
	 * @param[in] config New configuration values
	 * @return 0 on success, -EINVAL on validation failure, other negative errno
	 */
	int (*node_set)(const struct lichen_config_node *config);

	/**
	 * @brief Get current radio configuration
	 * @param[out] config Output buffer for configuration
	 * @return 0 on success, negative errno on failure
	 */
	int (*radio_get)(struct lichen_config_radio *config);

	/**
	 * @brief Set radio configuration
	 * @param[in] config New configuration values
	 * @return 0 on success, -EINVAL on validation failure, other negative errno
	 */
	int (*radio_set)(const struct lichen_config_radio *config);

	/**
	 * @brief Get identity information (read-only)
	 * @param[out] identity Output buffer for identity
	 * @return 0 on success, negative errno on failure
	 */
	int (*identity_get)(struct lichen_config_identity *identity);
};

/**
 * @brief Register configuration provider
 *
 * Must be called before the CoAP server starts handling /config requests.
 * Typically called from application init.
 *
 * @param[in] provider Provider callbacks (must remain valid)
 * @return 0 on success, -EINVAL if provider is NULL
 */
int lichen_coap_config_register(const struct lichen_config_provider *provider);

/**
 * @brief Get the registered configuration provider
 *
 * @return Pointer to provider, or NULL if not registered
 */
const struct lichen_config_provider *lichen_coap_config_provider_get(void);

/**
 * @brief Encode node configuration as CBOR
 *
 * Output format (per LCI spec 17.5.2):
 * {
 *   "name": "my-node",
 *   "role": "router",
 *   "radio": "/config/radio",
 *   "identity": "/config/identity"
 * }
 *
 * @param[out] buf Output buffer
 * @param[in] buf_size Buffer size
 * @param[in] config Configuration to encode
 * @return Encoded length on success, 0 on error
 */
size_t lichen_config_encode_node_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_config_node *config);

/**
 * @brief Decode node configuration from CBOR
 *
 * Accepts partial updates (missing fields retain current values).
 *
 * @param[in] buf CBOR data
 * @param[in] len Data length
 * @param[in,out] config Configuration (input: current values, output: updated values)
 * @return 0 on success, -EINVAL on parse error
 */
int lichen_config_decode_node_cbor(const uint8_t *buf, size_t len,
				   struct lichen_config_node *config);

/**
 * @brief Encode radio configuration as CBOR
 *
 * Output format (per LCI spec 17.5.2):
 * {
 *   "freq_mhz": 906.875,
 *   "bw_khz": 125,
 *   "sf": 9,
 *   "cr": "4/5",
 *   "tx_power_dbm": 20,
 *   "sync_word": "0x34"
 * }
 *
 * Note: freq_mhz is encoded as a scaled integer (freq_khz / 1000.0) using
 * CBOR float16/32 for spec compliance.
 *
 * @param[out] buf Output buffer
 * @param[in] buf_size Buffer size
 * @param[in] config Configuration to encode
 * @return Encoded length on success, 0 on error
 */
size_t lichen_config_encode_radio_cbor(uint8_t *buf, size_t buf_size,
				       const struct lichen_config_radio *config);

/**
 * @brief Decode radio configuration from CBOR
 *
 * Accepts partial updates (missing fields retain current values).
 *
 * @param[in] buf CBOR data
 * @param[in] len Data length
 * @param[in,out] config Configuration (input: current values, output: updated values)
 * @return 0 on success, -EINVAL on parse error
 */
int lichen_config_decode_radio_cbor(const uint8_t *buf, size_t len,
				    struct lichen_config_radio *config);

/**
 * @brief Encode identity information as CBOR
 *
 * Output format (per LCI spec 17.5.2):
 * {
 *   "eui64": "0x0011223344556677",
 *   "pubkey": "<base64 Ed25519 public key>",
 *   "pubkey_fingerprint": "SHA256:xY7...",
  *   "addrs": {
  *     "link_local": "fe80::0211:22ff:fe33:4455",
  *     "primary": "0200:1234:5678:9abc::0211:22ff:fe33:4455",
  *     "gua": null
  *   }

 * }
 *
 * @param[out] buf Output buffer
 * @param[in] buf_size Buffer size
 * @param[in] identity Identity to encode
 * @return Encoded length on success, 0 on error
 */
size_t lichen_config_encode_identity_cbor(uint8_t *buf, size_t buf_size,
					  const struct lichen_config_identity *identity);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_CONFIG_H_ */
