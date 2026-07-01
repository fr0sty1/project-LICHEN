/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "gateway_identity.h"

#include <errno.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

#if IS_ENABLED(CONFIG_LICHEN_L2) || defined(CONFIG_ZTEST)
int lichen_l2_publish_app_identity(const char *display_name,
				   const char *firmware_name);
#endif

LOG_MODULE_REGISTER(gateway_identity, LOG_LEVEL_INF);

#define GATEWAY_DISPLAY_NAME "LICHEN"
#define GATEWAY_FIRMWARE_NAME "LICHEN"

int gateway_identity_publish_self(void)
{
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY) && \
	(IS_ENABLED(CONFIG_LICHEN_L2) || defined(CONFIG_ZTEST))
	int ret = lichen_l2_publish_app_identity(GATEWAY_DISPLAY_NAME,
						 GATEWAY_FIRMWARE_NAME);

	if (ret == 0) {
		LOG_INF("Published gateway app identity from L2 link context");
	} else if (ret == -ENOKEY || ret == -EAGAIN) {
		LOG_WRN("Gateway app identity not published yet: %d", ret);
	} else {
		LOG_ERR("Gateway app identity publication failed: %d", ret);
	}
	return ret;
#else
	return -ENOTSUP;
#endif
}
