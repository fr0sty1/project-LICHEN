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
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

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

static bool put_tstr_kv_len(zcbor_state_t *state, const char *key,
			    const char *val, size_t len)
{
	return zcbor_tstr_put_term(state, key, 32) &&
	       zcbor_tstr_encode_ptr(state, val, len);
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
		return NULL;
	}
}

static bool node_config_is_valid(const struct lichen_config_node *config)
{
	return strnlen(config->name, sizeof(config->name)) < sizeof(config->name) &&
	       role_to_str(config->role) != NULL;
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
		return NULL;
	}
}

static bool radio_config_is_valid(const struct lichen_config_radio *config)
{
	return config->freq_khz > 0U && config->freq_khz <= 10000000UL &&
	       config->bw_khz > 0U && config->bw_khz <= 5000U &&
	       config->sf >= 7U && config->sf <= 12U &&
	       cr_to_str(config->cr) != NULL && config->tx_power_dbm >= -20 &&
	       config->tx_power_dbm <= 30;
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
	const char *role;
	size_t name_len;

	if (buf == NULL || config == NULL) {
		return 0;
	}

	/* Provider-owned snapshots are fixed-size fields, not trusted C strings. */
	name_len = strnlen(config->name, sizeof(config->name));
	role = role_to_str(config->role);
	if (!node_config_is_valid(config)) {
		return 0;
	}

	ZCBOR_STATE_E(state, 1, buf, buf_size, 0);

	if (!zcbor_map_start_encode(state, 4)) {
		return 0;
	}

	/* "name": "..." */
	if (!put_tstr_kv_len(state, KEY_NAME, config->name, name_len)) {
		return 0;
	}

	/* "role": "..." */
	if (!put_tstr_kv(state, KEY_ROLE, role)) {
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
	struct lichen_config_node candidate;
	bool seen_name = false;
	bool seen_role = false;

	if (buf == NULL || len == 0 || config == NULL) {
		return -EINVAL;
	}
	if (!node_config_is_valid(config)) {
		return -EINVAL;
	}

	/* Decode into a candidate so malformed later fields cannot partially
	 * mutate the caller's current configuration snapshot. */
	candidate = *config;

	ZCBOR_STATE_D(state, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(state)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(state)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(state, &key)) {
			goto invalid;
		}

		if (key.len == sizeof(KEY_NAME) - 1 &&
		    memcmp(key.value, KEY_NAME, key.len) == 0) {
			struct zcbor_string val;

			if (seen_name || !zcbor_tstr_decode(state, &val) ||
			    val.len >= LICHEN_CONFIG_NAME_MAX_LEN) {
				goto invalid;
			}
			seen_name = true;
			memcpy(candidate.name, val.value, val.len);
			candidate.name[val.len] = '\0';
		} else if (key.len == sizeof(KEY_ROLE) - 1 &&
			   memcmp(key.value, KEY_ROLE, key.len) == 0) {
			struct zcbor_string val;

			if (seen_role || !zcbor_tstr_decode(state, &val) ||
			    !str_to_role((const char *)val.value, val.len,
					 &candidate.role)) {
				goto invalid;
			}
			seen_role = true;
		} else {
			/* The embedded schema is closed: accepting a typo or a read-only
			 * link would otherwise report success without applying it. */
			goto invalid;
		}
	}

	if (!zcbor_map_end_decode(state) || state->payload != state->payload_end) {
		return -EINVAL;
	}

	*config = candidate;
	return 0;

invalid:
	(void)zcbor_list_map_end_force_decode(state);
	return -EINVAL;
}

/* Encode radio configuration */
size_t lichen_config_encode_radio_cbor(uint8_t *buf, size_t buf_size,
				       const struct lichen_config_radio *config)
{
	const char *cr;

	if (buf == NULL || config == NULL || !radio_config_is_valid(config)) {
		return 0;
	}
	if (buf_size < 1U) {
		return 0;
	}
	cr = cr_to_str(config->cr);

	/* The shared LCI vector fixes a six-entry definite-length map (0xa6).
	 * zcbor otherwise emits an indefinite map unless its entire library is
	 * built in canonical mode, so encode the fixed header explicitly. */
	buf[0] = 0xa6U;
	ZCBOR_STATE_E(state, 1, buf + 1, buf_size - 1U, 0);

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
	if (!put_tstr_kv(state, KEY_CR, cr)) {
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

	return (size_t)(state->payload - buf);
}

/* Decode radio configuration */
int lichen_config_decode_radio_cbor(const uint8_t *buf, size_t len,
				    struct lichen_config_radio *config)
{
	struct lichen_config_radio candidate;
	bool seen_freq = false;
	bool seen_bw = false;
	bool seen_sf = false;
	bool seen_cr = false;
	bool seen_tx_power = false;
	bool seen_sync_word = false;
	bool seen_any = false;

	if (buf == NULL || len == 0 || config == NULL) {
		return -EINVAL;
	}
	if (!radio_config_is_valid(config)) {
		return -EINVAL;
	}
	candidate = *config;

	ZCBOR_STATE_D(state, 2, buf, len, 1, 0);
	state->constant_state->enforce_canonical = true;

	if (!zcbor_map_start_decode(state)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(state)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(state, &key)) {
			goto invalid;
		}

		if (key.len == sizeof(KEY_FREQ_MHZ) - 1 &&
		    memcmp(key.value, KEY_FREQ_MHZ, key.len) == 0) {
			double val;
			if (seen_freq || !zcbor_float64_decode(state, &val) ||
			    val != val || val <= 0.0 || val > 10000.0) {
				goto invalid;
			}
			uint32_t freq_khz = (uint32_t)(val * 1000.0 + 0.5);
			if (freq_khz == 0 || freq_khz > 10000000UL) {
				goto invalid;
			}
			seen_freq = true;
			candidate.freq_khz = freq_khz;
		} else if (key.len == sizeof(KEY_BW_KHZ) - 1 &&
			   memcmp(key.value, KEY_BW_KHZ, key.len) == 0) {
			uint32_t val;
			if (seen_bw || !zcbor_uint32_decode(state, &val) ||
			    val == 0 || val > 5000) {
				goto invalid;
			}
			seen_bw = true;
			candidate.bw_khz = (uint16_t)val;
		} else if (key.len == sizeof(KEY_SF) - 1 &&
			   memcmp(key.value, KEY_SF, key.len) == 0) {
			uint32_t val;
			if (seen_sf || !zcbor_uint32_decode(state, &val) ||
			    val < 7 || val > 12) {
				goto invalid;
			}
			seen_sf = true;
			candidate.sf = (uint8_t)val;
		} else if (key.len == sizeof(KEY_CR) - 1 &&
			   memcmp(key.value, KEY_CR, key.len) == 0) {
			struct zcbor_string val;
			if (seen_cr || !zcbor_tstr_decode(state, &val) ||
			    !str_to_cr((const char *)val.value, val.len,
				       &candidate.cr)) {
				goto invalid;
			}
			seen_cr = true;
		} else if (key.len == sizeof(KEY_TX_POWER_DBM) - 1 &&
			   memcmp(key.value, KEY_TX_POWER_DBM, key.len) == 0) {
			int32_t val;
			if (seen_tx_power || !zcbor_int32_decode(state, &val) ||
			    val < -20 || val > 30) {
				goto invalid;
			}
			seen_tx_power = true;
			candidate.tx_power_dbm = (int8_t)val;
		} else if (key.len == sizeof(KEY_SYNC_WORD) - 1 &&
			   memcmp(key.value, KEY_SYNC_WORD, key.len) == 0) {
			struct zcbor_string val;
			if (seen_sync_word || !zcbor_tstr_decode(state, &val)) {
				goto invalid;
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
						goto invalid;
					}
				}
				seen_sync_word = true;
				candidate.sync_word = (uint16_t)v;
			} else {
				goto invalid;
			}
		} else {
			goto invalid;
		}
		seen_any = true;
	}

	if (!seen_any || !zcbor_map_end_decode(state) ||
	    state->payload != state->payload_end ||
	    !radio_config_is_valid(&candidate)) {
		return -EINVAL;
	}

	*config = candidate;
	return 0;

invalid:
	(void)zcbor_list_map_end_force_decode(state);
	return -EINVAL;
}

static size_t hex_encode(const uint8_t *src, size_t src_len,
			 char *dst, size_t dst_size)
{
	static const char hex[] = "0123456789abcdef";
	size_t needed = src_len * 2U + 1U;

	if (dst_size < needed) {
		return 0;
	}

	for (size_t i = 0U; i < src_len; i++) {
		dst[i * 2U] = hex[src[i] >> 4];
		dst[i * 2U + 1U] = hex[src[i] & 0x0fU];
	}
	dst[src_len * 2U] = '\0';
	return src_len * 2U;
}

static int base64_value(char c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	return -EINVAL;
}

static bool identity_short_fingerprint(const uint8_t pubkey[32], char out[24])
{
	char full[LICHEN_KEY_FINGERPRINT_STR_LEN];
	uint8_t prefix[9];
	int full_len;

	full_len = lichen_key_pubkey_fingerprint(pubkey, full, sizeof(full));
	if (full_len != (int)(sizeof("SHA256:") - 1U + 44U) ||
	    memcmp(full, "SHA256:", sizeof("SHA256:") - 1U) != 0 ||
	    full[full_len] != '\0' || full[full_len - 1] != '=') {
		return false;
	}

	/* The key helper exposes the complete SHA-256 digest as base64. Decode
	 * only the first three quanta: the LCI display fingerprint is the first
	 * eight digest bytes rendered as sixteen lowercase hex digits. */
	for (size_t i = 0U; i < 3U; i++) {
		const char *src = &full[sizeof("SHA256:") - 1U + i * 4U];
		int a = base64_value(src[0]);
		int b = base64_value(src[1]);
		int c = base64_value(src[2]);
		int d = base64_value(src[3]);

		if (a < 0 || b < 0 || c < 0 || d < 0) {
			return false;
		}
		prefix[i * 3U] = (uint8_t)((a << 2) | (b >> 4));
		prefix[i * 3U + 1U] = (uint8_t)((b << 4) | (c >> 2));
		prefix[i * 3U + 2U] = (uint8_t)((c << 6) | d);
	}

	memcpy(out, "SHA256:", sizeof("SHA256:") - 1U);
	return hex_encode(prefix, 8U, out + sizeof("SHA256:") - 1U,
			 24U - (sizeof("SHA256:") - 1U)) == 16U;
}

static bool identity_strings_are_bounded(
	const struct lichen_config_identity *identity)
{
	return strnlen(identity->link_local, sizeof(identity->link_local)) <
		       sizeof(identity->link_local) &&
	       strnlen(identity->primary, sizeof(identity->primary)) <
		       sizeof(identity->primary) &&
	       strnlen(identity->gua, sizeof(identity->gua)) < sizeof(identity->gua);
}

/* Encode identity information */
size_t lichen_config_encode_identity_cbor(uint8_t *buf, size_t buf_size,
					  const struct lichen_config_identity *identity)
{
	bool have_addrs;
	uint8_t field_count;

	if (buf == NULL || identity == NULL || buf_size < 1U ||
	    !identity_strings_are_bounded(identity)) {
		return 0;
	}
	have_addrs = identity->link_local[0] != '\0' ||
		     identity->primary[0] != '\0' || identity->gua[0] != '\0';
	field_count = (identity->eui64_valid ? 1U : 0U) +
		      (identity->pubkey_valid ? 2U : 0U) +
		      (have_addrs ? 1U : 0U);

	/* All identity fields are public material. The fixed definite map keeps
	 * wire output deterministic and cannot grow to include private fields. */
	buf[0] = 0xa0U | field_count;
	ZCBOR_STATE_E(state, 2, buf + 1, buf_size - 1U, 0);

	if (identity->eui64_valid) {
		char eui_buf[20];

		if (eui64_to_hex(identity->eui64, eui_buf, sizeof(eui_buf)) < 0 ||
		    !put_tstr_kv(state, KEY_EUI64, eui_buf)) {
			return 0;
		}
	}

	if (identity->pubkey_valid) {
		char pk_buf[65];
		char fp_buf[24];

		if (hex_encode(identity->pubkey, sizeof(identity->pubkey), pk_buf,
			       sizeof(pk_buf)) == 0 ||
		    !identity_short_fingerprint(identity->pubkey, fp_buf)) {
			return 0;
		}
		if (!put_tstr_kv(state, KEY_PUBKEY, pk_buf)) {
			return 0;
		}
		if (!put_tstr_kv_len(state, KEY_PUBKEY_FINGERPRINT, fp_buf,
				     sizeof(fp_buf) - 1U)) {
			return 0;
		}
	}

	if (have_addrs) {
		uint8_t addr_count = (identity->link_local[0] != '\0' ? 1U : 0U) +
				     (identity->primary[0] != '\0' ? 1U : 0U) +
				     (identity->gua[0] != '\0' ? 1U : 0U);

		if (!zcbor_tstr_put_lit(state, KEY_ADDRS) ||
		    state->payload >= state->payload_end) {
			return 0;
		}
		*state->payload_mut++ = 0xa0U | addr_count;

		if (identity->link_local[0] != '\0' &&
		    !put_tstr_kv(state, KEY_LINK_LOCAL, identity->link_local)) {
			return 0;
		}
		if (identity->primary[0] != '\0' &&
		    !put_tstr_kv(state, KEY_PRIMARY, identity->primary)) {
			return 0;
		}
		if (identity->gua[0] != '\0' &&
		    !put_tstr_kv(state, KEY_GUA, identity->gua)) {
			return 0;
		}
	}

	return (size_t)(state->payload - buf);
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
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}

	int ret = p->node_get(&node_cfg);
	if (ret < 0) {
		LOG_ERR("node_get failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_config_encode_node_cbor(cbor_buf, sizeof(cbor_buf), &node_cfg);
	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}

/* PUT /config handler */
static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_config_node node_cfg;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_PUT,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->node_get == NULL ||
	    p->node_set == NULL) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_NOT_FOUND,
						    0, NULL, 0);
	}

	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	/* Get current config for partial update */
	ret = p->node_get(&node_cfg);
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}
	if (!node_config_is_valid(&node_cfg)) {
		LOG_ERR("node_get returned invalid configuration");
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}

	/* Decode update (merges with current values) */
	ret = lichen_config_decode_node_cbor(oscore.payload, oscore.payload_len,
					     &node_cfg);
	if (ret < 0) {
		LOG_WRN("Invalid config CBOR");
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	/* Apply update */
	ret = p->node_set(&node_cfg);
	if (ret < 0) {
		uint8_t response_code;

		if (ret == -EINVAL || ret == -ERANGE) {
			response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
		} else if (ret == -EACCES || ret == -EPERM) {
			response_code = COAP_RESPONSE_CODE_FORBIDDEN;
		} else {
			/* Persistence, storage-capacity, and other provider failures are
			 * server errors, not malformed client requests. */
			response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
		}
		LOG_WRN("Config update failed: %d", ret);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    response_code,
						    0, NULL, 0);
	}

	LOG_INF("Config updated: name='%s' role=%d", node_cfg.name, node_cfg.role);
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0);
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
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}

	int ret = p->radio_get(&radio_cfg);
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_config_encode_radio_cbor(cbor_buf, sizeof(cbor_buf), &radio_cfg);
	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}

/* PUT /config/radio handler */
static int config_radio_put(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_config_radio radio_cfg;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_PUT,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}

	const struct lichen_config_provider *p = lichen_coap_config_provider_get();
	if (p == NULL || p->radio_get == NULL ||
	    p->radio_set == NULL) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_NOT_FOUND,
						    0, NULL, 0);
	}

	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	/* Get current config for partial update */
	ret = p->radio_get(&radio_cfg);
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}
	if (!radio_config_is_valid(&radio_cfg)) {
		LOG_ERR("radio_get returned invalid configuration");
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}

	/* Decode update */
	ret = lichen_config_decode_radio_cbor(oscore.payload, oscore.payload_len,
					      &radio_cfg);
	if (ret < 0) {
		LOG_WRN("Invalid radio config CBOR");
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	/* Apply update */
	ret = p->radio_set(&radio_cfg);
	if (ret < 0) {
		uint8_t response_code;

		if (ret == -EINVAL || ret == -ERANGE) {
			response_code = COAP_RESPONSE_CODE_BAD_REQUEST;
		} else if (ret == -EACCES || ret == -EPERM) {
			response_code = COAP_RESPONSE_CODE_FORBIDDEN;
		} else {
			response_code = COAP_RESPONSE_CODE_INTERNAL_ERROR;
		}
		LOG_WRN("Radio config update failed: %d", ret);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    response_code,
						    0, NULL, 0);
	}

	LOG_INF("Radio config updated: freq=%u sf=%d tx=%d",
		radio_cfg.freq_khz, radio_cfg.sf, radio_cfg.tx_power_dbm);
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0);
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
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}

	int ret = p->identity_get(&identity);
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_config_encode_identity_cbor(cbor_buf, sizeof(cbor_buf), &identity);
	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
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
