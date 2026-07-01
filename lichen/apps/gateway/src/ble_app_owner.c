/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ble_app_owner.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ble_app_owner, LOG_LEVEL_INF);

static K_MUTEX_DEFINE(s_owner_mutex);
static bool s_bt_enabled;
static bool s_adv_started;
static enum ble_app_owner_surface s_surface;
static struct ble_app_owner_advertising s_adv;
static struct bt_conn *s_conn;

#ifdef CONFIG_ZTEST
static int s_test_enable_ret;
static int s_test_adv_start_ret;
static int s_test_adv_stop_ret;
static uint32_t s_test_enable_count;
static uint32_t s_test_adv_start_count;
static uint32_t s_test_adv_stop_count;
static uint32_t s_test_adv_options;
static uint32_t s_test_conn_ref_count;
static uint32_t s_test_conn_unref_count;
#endif

static int owner_bt_enable(void)
{
#ifdef CONFIG_ZTEST
	s_test_enable_count++;
	return s_test_enable_ret;
#else
	return bt_enable(NULL);
#endif
}

static int owner_bt_le_adv_start(const struct bt_le_adv_param *param,
				 const struct bt_data *ad, size_t ad_len,
				 const struct bt_data *sd, size_t sd_len)
{
	ARG_UNUSED(param);
#ifdef CONFIG_ZTEST
	s_test_adv_options = param != NULL ? param->options : 0U;
	ARG_UNUSED(ad);
	ARG_UNUSED(ad_len);
	ARG_UNUSED(sd);
	ARG_UNUSED(sd_len);
	s_test_adv_start_count++;
	return s_test_adv_start_ret;
#else
	return bt_le_adv_start(param, ad, ad_len, sd, sd_len);
#endif
}

static int owner_bt_le_adv_stop(void)
{
#ifdef CONFIG_ZTEST
	s_test_adv_stop_count++;
	return s_test_adv_stop_ret;
#else
	return bt_le_adv_stop();
#endif
}

static struct bt_conn *owner_bt_conn_ref(struct bt_conn *conn)
{
#ifdef CONFIG_ZTEST
	s_test_conn_ref_count++;
	return conn;
#else
	return bt_conn_ref(conn);
#endif
}

static void owner_bt_conn_unref(struct bt_conn *conn)
{
#ifdef CONFIG_ZTEST
	ARG_UNUSED(conn);
	s_test_conn_unref_count++;
#else
	bt_conn_unref(conn);
#endif
}

static int validate_modes(bool native, bool meshtastic, bool meshcore)
{
	uint8_t count = 0U;

	count += native ? 1U : 0U;
	count += meshtastic ? 1U : 0U;
	count += meshcore ? 1U : 0U;

	return count > 1U ? -ENOTSUP : 0;
}

static int validate_advertising(const struct ble_app_owner_advertising *adv)
{
	if (adv == NULL || adv->ad == NULL || adv->ad_len == 0U ||
	    adv->name == NULL || adv->name[0] == '\0') {
		return -EINVAL;
	}
	if (adv->surface != BLE_APP_OWNER_SURFACE_NATIVE &&
	    adv->surface != BLE_APP_OWNER_SURFACE_MESHTASTIC &&
	    adv->surface != BLE_APP_OWNER_SURFACE_MESHCORE) {
		return -EINVAL;
	}
	if (adv->sd == NULL && adv->sd_len > 0U) {
		return -EINVAL;
	}

	return validate_modes(adv->surface == BLE_APP_OWNER_SURFACE_NATIVE,
			      adv->surface == BLE_APP_OWNER_SURFACE_MESHTASTIC,
			      adv->surface == BLE_APP_OWNER_SURFACE_MESHCORE);
}

static int validate_compiled_mode(enum ble_app_owner_surface surface)
{
	const bool native = IS_ENABLED(CONFIG_LORA_LICHEN_BLE);
	const bool meshtastic = IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE);
	const bool meshcore = IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_BLE);
	const bool any_surface = native || meshtastic || meshcore;
	int ret;

	ret = validate_modes(native, meshtastic, meshcore);
	if (ret < 0) {
		return ret;
	}

	if (!any_surface) {
		return 0;
	}

	if ((surface == BLE_APP_OWNER_SURFACE_NATIVE) != native ||
	    (surface == BLE_APP_OWNER_SURFACE_MESHTASTIC) != meshtastic ||
	    (surface == BLE_APP_OWNER_SURFACE_MESHCORE) != meshcore) {
		return -ENOTSUP;
	}

	return 0;
}

static void owner_connected(struct bt_conn *conn, uint8_t err)
{
	ble_app_owner_connected_fn connected;
	struct bt_conn *old_conn = NULL;
	struct bt_conn *new_conn = NULL;

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	if (err == 0U && s_adv_started && conn != NULL) {
		new_conn = owner_bt_conn_ref(conn);
		old_conn = s_conn;
		s_conn = new_conn;
	}
	connected = s_adv_started ? s_adv.connected : NULL;
	k_mutex_unlock(&s_owner_mutex);

	if (old_conn != NULL) {
		owner_bt_conn_unref(old_conn);
	}
	if (connected != NULL) {
		connected(conn, err);
	}
}

static void owner_disconnected(struct bt_conn *conn, uint8_t reason)
{
	ble_app_owner_disconnected_fn disconnected;
	struct bt_conn *old_conn = NULL;
	bool matched;

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	matched = s_conn != NULL && s_conn == conn;
	if (matched) {
		old_conn = s_conn;
		s_conn = NULL;
	}
	disconnected = (s_adv_started && matched) ? s_adv.disconnected : NULL;
	k_mutex_unlock(&s_owner_mutex);

	if (disconnected != NULL) {
		disconnected(conn, reason);
	}
	if (old_conn != NULL) {
		owner_bt_conn_unref(old_conn);
	}
}

BT_CONN_CB_DEFINE(owner_conn_callbacks) = {
	.connected = owner_connected,
	.disconnected = owner_disconnected,
};

int ble_app_owner_start(const struct ble_app_owner_advertising *adv)
{
	const struct bt_le_adv_param *param;
	int ret;

	ret = validate_advertising(adv);
	if (ret < 0) {
		return ret;
	}
	ret = validate_compiled_mode(adv->surface);
	if (ret < 0) {
		return ret;
	}

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	if (s_adv_started) {
		k_mutex_unlock(&s_owner_mutex);
		return s_surface == adv->surface ? 0 : -EALREADY;
	}
	if (!s_bt_enabled) {
		ret = owner_bt_enable();
		if (ret < 0) {
			k_mutex_unlock(&s_owner_mutex);
			LOG_ERR("bt_enable failed: %d", ret);
			return ret;
		}
		s_bt_enabled = true;
	}
	if (adv->prepare != NULL) {
		ret = adv->prepare();
		if (ret < 0) {
			k_mutex_unlock(&s_owner_mutex);
			return ret;
		}
	}

	param = BT_LE_ADV_PARAM(BT_LE_ADV_OPT_CONNECTABLE |
				(adv->surface == BLE_APP_OWNER_SURFACE_NATIVE ?
				 BT_LE_ADV_OPT_USE_NAME : 0),
				BT_GAP_ADV_FAST_INT_MIN_2,
				BT_GAP_ADV_FAST_INT_MAX_2,
				NULL);
	ret = owner_bt_le_adv_start(param, adv->ad, adv->ad_len, adv->sd,
				    adv->sd_len);
	if (ret == 0) {
		s_adv_started = true;
		s_surface = adv->surface;
		s_adv = *adv;
		LOG_INF("BLE app owner advertising as \"%s\"", adv->name);
	} else {
		LOG_ERR("BLE app owner advertising failed: %d", ret);
	}
	k_mutex_unlock(&s_owner_mutex);

	return ret;
}

int ble_app_owner_stop(enum ble_app_owner_surface surface)
{
	struct bt_conn *old_conn = NULL;
	int ret;

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	if (!s_bt_enabled || s_adv.ad == NULL || s_surface != surface) {
		k_mutex_unlock(&s_owner_mutex);
		return -EINVAL;
	}

	ret = owner_bt_le_adv_stop();
	if (ret == 0 || ret == -EALREADY) {
		s_adv_started = false;
		old_conn = s_conn;
		s_conn = NULL;
		ret = 0;
	} else {
		LOG_ERR("BLE app owner advertising stop failed: %d", ret);
	}
	k_mutex_unlock(&s_owner_mutex);

	if (old_conn != NULL) {
		owner_bt_conn_unref(old_conn);
	}

	return ret;
}

int ble_app_owner_restart(enum ble_app_owner_surface surface)
{
	const struct bt_le_adv_param *param;
	int ret;

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	if (!s_bt_enabled || s_adv.ad == NULL || s_surface != surface) {
		k_mutex_unlock(&s_owner_mutex);
		return -EINVAL;
	}

	param = BT_LE_ADV_PARAM(BT_LE_ADV_OPT_CONNECTABLE |
				(surface == BLE_APP_OWNER_SURFACE_NATIVE ?
				 BT_LE_ADV_OPT_USE_NAME : 0),
				BT_GAP_ADV_FAST_INT_MIN_2,
				BT_GAP_ADV_FAST_INT_MAX_2,
				NULL);
	ret = owner_bt_le_adv_start(param, s_adv.ad, s_adv.ad_len, s_adv.sd,
				    s_adv.sd_len);
	if (ret == 0 || ret == -EALREADY) {
		s_adv_started = true;
		ret = 0;
	} else {
		LOG_ERR("BLE app owner advertising restart failed: %d", ret);
	}
	k_mutex_unlock(&s_owner_mutex);

	return ret;
}

int ble_app_owner_conn_ref(enum ble_app_owner_surface surface,
			   struct bt_conn **conn)
{
	if (conn == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	if (!s_adv_started || s_surface != surface || s_conn == NULL) {
		*conn = NULL;
		k_mutex_unlock(&s_owner_mutex);
		return -ENOTCONN;
	}
	*conn = owner_bt_conn_ref(s_conn);
	k_mutex_unlock(&s_owner_mutex);

	return 0;
}

void ble_app_owner_conn_unref(struct bt_conn *conn)
{
	if (conn != NULL) {
		owner_bt_conn_unref(conn);
	}
}

#ifdef CONFIG_ZTEST
void ble_app_owner_test_reset(void)
{
	struct bt_conn *old_conn;

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	old_conn = s_conn;
	s_conn = NULL;
	s_bt_enabled = false;
	s_adv_started = false;
	s_surface = BLE_APP_OWNER_SURFACE_NATIVE;
	memset(&s_adv, 0, sizeof(s_adv));
	s_test_enable_ret = 0;
	s_test_adv_start_ret = 0;
	s_test_adv_stop_ret = 0;
	s_test_enable_count = 0U;
	s_test_adv_start_count = 0U;
	s_test_adv_stop_count = 0U;
	s_test_adv_options = 0U;
	s_test_conn_ref_count = 0U;
	s_test_conn_unref_count = 0U;
	k_mutex_unlock(&s_owner_mutex);

	if (old_conn != NULL) {
		ARG_UNUSED(old_conn);
	}
}

void ble_app_owner_test_set_backend(int enable_ret, int adv_start_ret,
				    int adv_stop_ret)
{
	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	s_test_enable_ret = enable_ret;
	s_test_adv_start_ret = adv_start_ret;
	s_test_adv_stop_ret = adv_stop_ret;
	k_mutex_unlock(&s_owner_mutex);
}

int ble_app_owner_test_copy_state(struct ble_app_owner_test_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_owner_mutex, K_FOREVER);
	state->enable_count = s_test_enable_count;
	state->adv_start_count = s_test_adv_start_count;
	state->adv_stop_count = s_test_adv_stop_count;
	state->adv_options = s_test_adv_options;
	state->surface = s_surface;
	state->ad = s_adv.ad;
	state->ad_len = s_adv.ad_len;
	state->sd = s_adv.sd;
	state->sd_len = s_adv.sd_len;
	state->has_surface = s_adv_started;
	state->has_connected = s_adv.connected != NULL;
	state->has_disconnected = s_adv.disconnected != NULL;
	state->has_connection = s_conn != NULL;
	state->conn_ref_count = s_test_conn_ref_count;
	state->conn_unref_count = s_test_conn_unref_count;
	k_mutex_unlock(&s_owner_mutex);

	return 0;
}

int ble_app_owner_test_validate_modes(bool native, bool meshtastic,
				      bool meshcore)
{
	return validate_modes(native, meshtastic, meshcore);
}

int ble_app_owner_test_validate_advertising(
	const struct ble_app_owner_advertising *adv)
{
	return validate_advertising(adv);
}

void ble_app_owner_test_connected(struct bt_conn *conn, uint8_t err)
{
	owner_connected(conn, err);
}

void ble_app_owner_test_disconnected(struct bt_conn *conn, uint8_t reason)
{
	owner_disconnected(conn, reason);
}

#endif
