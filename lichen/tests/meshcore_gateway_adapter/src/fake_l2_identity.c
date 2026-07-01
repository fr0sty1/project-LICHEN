/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <lichen/app_identity/app_identity.h>

static int s_publish_ret;
static K_MUTEX_DEFINE(s_publish_mutex);

void fake_l2_identity_set_publish_ret(int ret)
{
	k_mutex_lock(&s_publish_mutex, K_FOREVER);
	s_publish_ret = ret;
	k_mutex_unlock(&s_publish_mutex);
}

int lichen_l2_publish_app_identity(const char *display_name,
				   const char *firmware_name)
{
	struct lichen_app_identity_self identity = {
		.eui64 = { 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x19 },
		.has_public_key = true,
	};
	int ret;

	k_mutex_lock(&s_publish_mutex, K_FOREVER);
	ret = s_publish_ret;
	k_mutex_unlock(&s_publish_mutex);
	if (ret < 0) {
		return ret;
	}

	for (uint8_t i = 0U; i < sizeof(identity.public_key); i++) {
		identity.public_key[i] = (uint8_t)(0xd0U + i);
	}
	if (display_name != NULL) {
		strncpy(identity.display_name, display_name,
			sizeof(identity.display_name) - 1U);
	}
	if (firmware_name != NULL) {
		strncpy(identity.firmware_name, firmware_name,
			sizeof(identity.firmware_name) - 1U);
	}

	return lichen_app_identity_set_self(&identity);
}
