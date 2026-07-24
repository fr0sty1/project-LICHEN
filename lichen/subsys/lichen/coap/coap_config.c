/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_config.c
 * @brief LCI /config resource handlers per spec/11-lci.md section 17.5.2
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <zcbor_decode.h>
#include <zcbor_encode.h>

#include <lichen/coap_config.h>
#include <lichen/coap_keys.h>

#if IS_ENABLED(CONFIG_SETTINGS)
#include <zephyr/settings/settings.h>
#endif

LOG_MODULE_REGISTER(lichen_coap_config, CONFIG_LICHEN_COAP_CONFIG_LOG_LEVEL);

/* CBOR content-format code (RFC 7252) */
#define CBOR_CONTENT_FORMAT 60

/* Maximum CBOR response size */
#define CONFIG_CBOR_MAX_SIZE 256

/* String key constants */
#define KEY_NAME "name"
#define KEY_ROLE "role"
#define KEY_RADIO "radio"
#define KEY_IDENTITY "identity"
#define KEY_FREQ_MHZ "freq_mhz"
#define KEY_BW_KHZ "bw_khz"
#define KEY_SF "sf"
#define KEY_CR "cr"
#define KEY_TX_POWER_DBM "tx_power_dbm"
#define KEY_SYNC_WORD "sync_word"
#define KEY_EUI64 "eui64"
#define KEY_PUBKEY "pubkey"
#define KEY_PUBKEY_FINGERPRINT "pubkey_fingerprint"
#define KEY_ADDRS "addrs"
#define KEY_LINK_LOCAL "link_local"
#define KEY_PRIMARY "primary"
#define KEY_GUA "gua"

/* Role string constants */
#define ROLE_LEAF "leaf"
#define ROLE_ROUTER "router"
#define ROLE_BORDER_ROUTER "border-router"

/* Coding rate string constants */
#define CR_4_5 "4/5"
#define CR_4_6 "4/6"
#define CR_4_7 "4/7"
#define CR_4_8 "4/8"

/* Resource paths */
#define PATH_CONFIG_RADIO "/config/radio"
#define PATH_CONFIG_IDENTITY "/config/identity"

/* Provider registration */
static const struct lichen_config_provider *s_provider;
static K_MUTEX_DEFINE(s_provider_mutex);

int lichen_coap_config_register(const struct lichen_config_provider *provider)
{
	if (provider == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	s_provider = provider;
	k_mutex_unlock(&s_provider_mutex);
	LOG_INF("Config provider registered");
	return 0;
}

const struct lichen_config_provider *lichen_coap_config_provider_get(void)
{
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	const struct lichen_config_provider *p = s_provider;
	k_mutex_unlock(&s_provider_mutex);
	return p;
}

/* CBOR encoding helpers - use zcbor_tstr_put_term for keys since they are
 * passed as function arguments (not string literals). */

static bool put_tstr_kv(zcbor_state_t *state, const char *key, const char *val)
{
	return zcbor_tstr_put_term(state, key, 32) &&
	       zcbor_tstr_put_term(state, val, 128);
}

static bool put_int_kv(zcbor_state_t *state, const char *key, int64_t val)
{
	return zcbor_tstr_put_term(state, key, 32) && zcbor_int64_put(state, val);
}

static bool put_uint_kv(zcbor_state_t *state, const char *key, uint64_t val)
{
	return zcbor_tstr_put_term(state, key, 32) && zcbor_uint64_put(state, val);
}

static const char *role_to_str(enum lichen_config_role role)
{
	switch (role) {
	case LICHEN_CONFIG_ROLE_LEAF:
		return ROLE_LEAF;
	case LICHEN_CONFIG_ROLE_ROUTER:
		return ROLE_ROUTER;
	case LICHEN_CONFIG_ROLE_BORDER_ROUTER:
		return ROLE_BORDER_ROUTER;
	default:
		return ROLE_LEAF;
	}
}

static bool str_to_role(const char *str, size_t len, enum lichen_config_role *role)
{
	if (len == sizeof(ROLE_LEAF) - 1 &&
	    memcmp(str, ROLE_LEAF, len) == 0) {
		*role = LICHEN_CONFIG_ROLE_LEAF;
		return true;
	}
	if (len == sizeof(ROLE_ROUTER) - 1 &&
	    memcmp(str, ROLE_ROUTER, len) == 0) {
		*role = LICHEN_CONFIG_ROLE_ROUTER;
		return true;
	}
	if (len == sizeof(ROLE_BORDER_ROUTER) - 1 &&
	    memcmp(str, ROLE_BORDER_ROUTER, len) == 0) {
		*role = LICHEN_CONFIG_ROLE_BORDER_ROUTER;
		return true;
	}
	return false;
}

static const char *cr_to_str(enum lichen_config_coding_rate cr)
{
	switch (cr) {
	case LICHEN_CONFIG_CR_4_5:
		return CR_4_5;
	case LICHEN_CONFIG_CR_4_6:
		return CR_4_6;
	case LICHEN_CONFIG_CR_4_7:
		return CR_4_7;
	case LICHEN_CONFIG_CR_4_8:
		return CR_4_8;
	default:
		return CR_4_5;
	}
}

static bool str_to_cr(const char *str, size_t len, enum lichen_config_coding_rate *cr)
{
	if (len == sizeof(CR_4_5) - 1 && memcmp(str, CR_4_5, len) == 0) {
		*cr = LICHEN_CONFIG_CR_4_5;
		return true;
	}
	if (len == sizeof(CR_4_6) - 1 && memcmp(str, CR_4_6, len) == 0) {
		*cr = LICHEN_CONFIG_CR_4_6;
		return true;
	}
	if (len == sizeof(CR_4_7) - 1 && memcmp(str, CR_4_7, len) == 0) {
		*cr = LICHEN_CONFIG_CR_4_7;
		return true;
	}
	if (len == sizeof(CR_4_8) - 1 && memcmp(str, CR_4_8, len) == 0) {
		*cr = LICHEN_CONFIG_CR_4_8;
		return true;
	}
	return false;
}

/* Format EUI-64 as hex string "0x0011223344556677" */
static int eui64_to_hex(const uint8_t eui64[8], char *buf, size_t buf_size)
{
	if (buf_size < 19) { /* "0x" + 16 hex chars + NUL */
		return -EINVAL;
	}
	buf[0] = '0';
	buf[1] = 'x';
	for (int i = 0; i < 8; i++) {
		int pr = snprintf(&buf[2 + i * 2], 3, "%02x", eui64[i]);
		if (pr < 0 || (size_t)pr >= 3) {
			return -EINVAL;
		}
	}
	return 0;
}

/* Encode node configuration */
size_t lichen_config_encode_node_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_config_node *config)
{
	if (buf == NULL || config == NULL) {
		return 0;
	}

	ZCBOR_STATE_E(state, 1, buf, buf_size, 0);

	if (!zcbor_map_start_encode(state, 4)) {
		return 0;
	}

	/* "name": "..." */
	if (!put_tstr_kv(state, KEY_NAME, config->name)) {
		return 0;
	}

	/* "role": "..." */
	if (!put_tstr_kv(state, KEY_ROLE, role_to_str(config->role))) {
		return 0;
	}

	/* "radio": "/config/radio" */
	if (!put_tstr_kv(state, KEY_RADIO, PATH_CONFIG_RADIO)) {
		return 0;
	}

	/* "identity": "/config/identity" */
	if (!put_tstr_kv(state, KEY_IDENTITY, PATH_CONFIG_IDENTITY)) {
		return 0;
	}

	if (!zcbor_map_end_encode(state, 4)) {
		return 0;
	}

	return (size_t)(state->payload - buf);
}

/* Decode node configuration */
int lichen_config_decode_node_cbor(const uint8_t *buf, size_t len,
				   struct lichen_config_node *config)
{
	if (buf == NULL || len == 0 || config == NULL) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(state, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(state)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(state)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(state, &key)) {
			(void)zcbor_list_map_end_force_decode(state);
			return -EINVAL;
		}

		if (key.len == sizeof(KEY_NAME) - 1 &&
		    memcmp(key.value, KEY_NAME, key.len) == 0) {
			struct zcbor_string val;

			if (!zcbor_tstr_decode(state, &val) ||
			    val.len >= LICHEN_CONFIG_NAME_MAX_LEN) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			memcpy(config->name, val.value, val.len);
			config->name[val.len] = '\0';
		} else if (key.len == sizeof(KEY_ROLE) - 1 &&
			   memcmp(key.value, KEY_ROLE, key.len) == 0) {
			struct zcbor_string val;

			if (!zcbor_tstr_decode(state, &val) ||
			    !str_to_role((const char *)val.value, val.len,
					 &config->role)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		} else {
			/* Skip unknown keys */
			if (!zcbor_any_skip(state, NULL)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		}
	}

	if (!zcbor_map_end_decode(state)) {
		return -EINVAL;
	}

	return 0;
}

/* Encode radio configuration */
size_t lichen_config_encode_radio_cbor(uint8_t *buf, size_t buf_size,
				       const struct lichen_config_radio *config)
{
	if (buf == NULL || config == NULL) {
		return 0;
	}

	ZCBOR_STATE_E(state, 1, buf, buf_size, 0);

	if (!zcbor_map_start_encode(state, 6)) {
		return 0;
	}

	/* "freq_mhz": as float (freq_khz / 1000.0) */
	double freq_mhz = (double)config->freq_khz / 1000.0;
	if (!zcbor_tstr_put_lit(state, KEY_FREQ_MHZ) ||
	    !zcbor_float64_put(state, freq_mhz)) {
		return 0;
	}

	/* "bw_khz": integer */
	if (!put_uint_kv(state, KEY_BW_KHZ, config->bw_khz)) {
		return 0;
	}

	/* "sf": integer */
	if (!put_uint_kv(state, KEY_SF, config->sf)) {
		return 0;
	}

	/* "cr": string */
	if (!put_tstr_kv(state, KEY_CR, cr_to_str(config->cr))) {
		return 0;
	}

	/* "tx_power_dbm": integer */
	if (!put_int_kv(state, KEY_TX_POWER_DBM, config->tx_power_dbm)) {
		return 0;
	}

	/* "sync_word": as hex string "0x34" */
	char sync_buf[8];
	int pr = snprintf(sync_buf, sizeof(sync_buf), "0x%02x", config->sync_word);
	if (pr < 0 || (size_t)pr >= sizeof(sync_buf)) {
		return 0;
	}
	if (!put_tstr_kv(state, KEY_SYNC_WORD, sync_buf)) {
		return 0;
	}

	if (!zcbor_map_end_encode(state, 6)) {
		return 0;
	}

	return (size_t)(state->payload - buf);
}

/* Decode radio configuration */
int lichen_config_decode_radio_cbor(const uint8_t *buf, size_t len,
				    struct lichen_config_radio *config)
{
	if (buf == NULL || len == 0 || config == NULL) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(state, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(state)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(state)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(state, &key)) {
			(void)zcbor_list_map_end_force_decode(state);
			return -EINVAL;
		}

		if (key.len == sizeof(KEY_FREQ_MHZ) - 1 &&
		    memcmp(key.value, KEY_FREQ_MHZ, key.len) == 0) {
			double val;
			if (!zcbor_float64_decode(state, &val) || val <= 0.0 || val > 10000.0) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			uint32_t freq_khz = (uint32_t)(val * 1000.0 + 0.5);
			if (freq_khz == 0 || freq_khz > 10000000UL) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			config->freq_khz = freq_khz;
		} else if (key.len == sizeof(KEY_BW_KHZ) - 1 &&
			   memcmp(key.value, KEY_BW_KHZ, key.len) == 0) {
			uint32_t val;
			if (!zcbor_uint32_decode(state, &val) ||
			    val == 0 || val > 5000) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			config->bw_khz = (uint16_t)val;
		} else if (key.len == sizeof(KEY_SF) - 1 &&
			   memcmp(key.value, KEY_SF, key.len) == 0) {
			uint32_t val;
			if (!zcbor_uint32_decode(state, &val) ||
			    val < 6 || val > 12) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			config->sf = (uint8_t)val;
		} else if (key.len == sizeof(KEY_CR) - 1 &&
			   memcmp(key.value, KEY_CR, key.len) == 0) {
			struct zcbor_string val;
			if (!zcbor_tstr_decode(state, &val) ||
			    !str_to_cr((const char *)val.value, val.len,
				       &config->cr)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		} else if (key.len == sizeof(KEY_TX_POWER_DBM) - 1 &&
			   memcmp(key.value, KEY_TX_POWER_DBM, key.len) == 0) {
			int32_t val;
			if (!zcbor_int32_decode(state, &val) ||
			    val < -20 || val > 30) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			config->tx_power_dbm = (int8_t)val;
		} else if (key.len == sizeof(KEY_SYNC_WORD) - 1 &&
			   memcmp(key.value, KEY_SYNC_WORD, key.len) == 0) {
			struct zcbor_string val;
			if (!zcbor_tstr_decode(state, &val)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			/* Parse "0x34" format - max 4 hex digits for uint16_t.
			 * Bound val.len <= 6 prevents UB on maliciously long strings.
			 * Accepts "0x34", "0x0034", "0x1234", "0xABCD" etc.
			 */
			if (val.len > 2 && val.len <= 6 && val.value[0] == '0' &&
			    (val.value[1] == 'x' || val.value[1] == 'X')) {
				unsigned long v = 0;
				for (size_t i = 2; i < val.len; i++) {
					char c = (char)val.value[i];
					v <<= 4;
					if (c >= '0' && c <= '9') {
						v |= (unsigned long)(c - '0');
					} else if (c >= 'a' && c <= 'f') {
						v |= (unsigned long)(c - 'a' + 10);
					} else if (c >= 'A' && c <= 'F') {
						v |= (unsigned long)(c - 'A' + 10);
					} else {
						(void)zcbor_list_map_end_force_decode(state);
						return -EINVAL;
					}
				}
				config->sync_word = (uint16_t)(v & 0xFFFF);
			} else {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		} else {
			/* Skip unknown keys */
			if (!zcbor_any_skip(state, NULL)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		}
	}

	if (!zcbor_map_end_decode(state)) {
		return -EINVAL;
	}

	return 0;
}

static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *src, size_t src_len,
			    char *dst, size_t dst_size)
{
	size_t needed = ((src_len + 2) / 3) * 4 + 1;
	if (dst_size < needed) {
		return 0;
	}

	size_t j = 0;
	for (size_t i = 0; i < src_len; i += 3) {
		uint32_t n = (uint32_t)src[i] << 16;
		if (i + 1 < src_len) {
			n |= (uint32_t)src[i + 1] << 8;
		}
		if (i + 2 < src_len) {
			n |= (uint32_t)src[i + 2];
		}

		dst[j++] = base64_table[(n >> 18) & 0x3F];
		dst[j++] = base64_table[(n >> 12) & 0x3F];
		dst[j++] = (char)((i + 1 < src_len) ? base64_table[(n >> 6) & 0x3F] : '=');
		dst[j++] = (char)((i + 2 < src_len) ? base64_table[n & 0x3F] : '=');
	}
	dst[j] = '\0';
	return j;
}

/* Encode identity information */
size_t lichen_config_encode_identity_cbor(uint8_t *buf, size_t buf_size,
					  const struct lichen_config_identity *identity)
{
	if (buf == NULL || identity == NULL) {
		return 0;
	}

	ZCBOR_STATE_E(state, 2, buf, buf_size, 0);

	if (!zcbor_map_start_encode(state, 4)) {
		return 0;
	}

	/* "eui64": "0x..." */
	char eui_buf[20];
	if (eui64_to_hex(identity->eui64, eui_buf, sizeof(eui_buf)) < 0) {
		return 0;
	}
	if (!put_tstr_kv(state, KEY_EUI64, eui_buf)) {
		return 0;
	}

	/* "pubkey": base64 string or null */
	if (identity->pubkey_valid) {
		char pk_buf[48];
		if (base64_encode(identity->pubkey, 32, pk_buf, sizeof(pk_buf)) == 0) {
			return 0;
		}
		if (!put_tstr_kv(state, KEY_PUBKEY, pk_buf)) {
			return 0;
		}

		char fp_buf[LICHEN_KEY_FINGERPRINT_STR_LEN];
		if (lichen_key_pubkey_fingerprint(identity->pubkey, fp_buf, sizeof(fp_buf)) < 0) {
			return 0;
		}
		if (!put_tstr_kv(state, KEY_PUBKEY_FINGERPRINT, fp_buf)) {
			return 0;
		}
	} else {
		if (!zcbor_tstr_put_lit(state, KEY_PUBKEY) ||
		    !zcbor_nil_put(state, NULL)) {
			return 0;
		}
		if (!zcbor_tstr_put_lit(state, KEY_PUBKEY_FINGERPRINT) ||
		    !zcbor_nil_put(state, NULL)) {
			return 0;
		}
	}


	/* "addrs": { "link_local": "...", "primary": "...", "gua": null } */
	if (!zcbor_tstr_put_lit(state, KEY_ADDRS) ||
	    !zcbor_map_start_encode(state, 3)) {
		return 0;
	}

	if (!put_tstr_kv(state, KEY_LINK_LOCAL, identity->link_local)) {
		return 0;
	}

	if (identity->primary[0] != '\0') {
		if (!put_tstr_kv(state, KEY_PRIMARY, identity->primary)) {
			return 0;
		}
	} else {
		if (!zcbor_tstr_put_lit(state, KEY_PRIMARY) ||
		    !zcbor_nil_put(state, NULL)) {
			return 0;
		}
	}

	if (identity->gua[0] != '\0') {
		if (!put_tstr_kv(state, KEY_GUA, identity->gua)) {
			return 0;
		}
	} else {
		if (!zcbor_tstr_put_lit(state, KEY_GUA) ||
		    !zcbor_nil_put(state, NULL)) {
			return 0;
		}
	}

	if (!zcbor_map_end_encode(state, 3)) {
		return 0;
	}

	if (!zcbor_map_end_encode(state, 4)) {
		return 0;
	}

	return (size_t)(state->payload - buf);
}

/* CoAP response helper */
static int coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code,
			const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r;

	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			     type, tkl, token, resp_code,
			     coap_header_get_id(request));
	if (r < 0) {
		return r;
	}

	if (payload != NULL && payload_len > 0) {
		r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
					   CBOR_CONTENT_FORMAT);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload(&resp, payload, (uint16_t)payload_len);
		if (r < 0) {
			return r;
		}
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

/* GET /config handler */
static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	struct lichen_config_node node_cfg;
	uint8_t cbor_buf[CONFIG_CBOR_MAX_SIZE];
	size_t len;

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->node_get == NULL) {
		LOG_WRN("No config provider registered");
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	int ret = p->node_get(&node_cfg);
	if (ret < 0) {
		LOG_ERR("node_get failed: %d", ret);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = lichen_config_encode_node_cbor(cbor_buf, sizeof(cbor_buf), &node_cfg);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

/* PUT /config handler */
static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct lichen_config_node node_cfg;
	int ret;

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->node_get == NULL ||
	    p->node_set == NULL) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	if (payload == NULL || payload_len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Get current config for partial update */
	ret = p->node_get(&node_cfg);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	/* Decode update (merges with current values) */
	ret = lichen_config_decode_node_cbor(payload, payload_len, &node_cfg);
	if (ret < 0) {
		LOG_WRN("Invalid config CBOR");
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Apply update */
	ret = p->node_set(&node_cfg);
	if (ret < 0) {
		LOG_WRN("Config validation failed: %d", ret);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	LOG_INF("Config updated: name='%s' role=%d", node_cfg.name, node_cfg.role);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);
}

/* GET /config/radio handler */
static int config_radio_get(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	struct lichen_config_radio radio_cfg;
	uint8_t cbor_buf[CONFIG_CBOR_MAX_SIZE];
	size_t len;

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->radio_get == NULL) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	int ret = p->radio_get(&radio_cfg);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = lichen_config_encode_radio_cbor(cbor_buf, sizeof(cbor_buf), &radio_cfg);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

/* PUT /config/radio handler */
static int config_radio_put(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct lichen_config_radio radio_cfg;
	int ret;

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->radio_get == NULL ||
	    p->radio_set == NULL) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	if (payload == NULL || payload_len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Get current config for partial update */
	ret = p->radio_get(&radio_cfg);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	/* Decode update */
	ret = lichen_config_decode_radio_cbor(payload, payload_len, &radio_cfg);
	if (ret < 0) {
		LOG_WRN("Invalid radio config CBOR");
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Apply update */
	ret = p->radio_set(&radio_cfg);
	if (ret < 0) {
		LOG_WRN("Radio config validation failed: %d", ret);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	LOG_INF("Radio config updated: freq=%u sf=%d tx=%d",
		radio_cfg.freq_khz, radio_cfg.sf, radio_cfg.tx_power_dbm);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);
}

/* GET /config/identity handler */
static int config_identity_get(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len)
{
	struct lichen_config_identity identity;
	uint8_t cbor_buf[CONFIG_CBOR_MAX_SIZE];
	size_t len;

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->identity_get == NULL) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	int ret = p->identity_get(&identity);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = lichen_config_encode_identity_cbor(cbor_buf, sizeof(cbor_buf), &identity);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

/* CoAP resource definitions */
#if IS_ENABLED(CONFIG_LICHEN_COAP_CONFIG)

static const char * const config_path[] = { "config", NULL };
COAP_RESOURCE_DEFINE(lichen_config, lichen_coap, {
	.get  = config_get,
	.put  = config_put,
	.path = config_path,
});

static const char * const config_radio_path[] = { "config", "radio", NULL };
COAP_RESOURCE_DEFINE(lichen_config_radio, lichen_coap, {
	.get  = config_radio_get,
	.put  = config_radio_put,
	.path = config_radio_path,
});

static const char * const config_identity_path[] = { "config", "identity", NULL };
COAP_RESOURCE_DEFINE(lichen_config_identity, lichen_coap, {
	.get  = config_identity_get,
	.path = config_identity_path,
});

#endif /* CONFIG_LICHEN_COAP_CONFIG */
