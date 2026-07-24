/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <lichen/link.h>

LOG_MODULE_REGISTER(lichen_time_sync, CONFIG_LICHEN_LINK_LOG_LEVEL);

static uint32_t s_current_sfn;
static bool s_synced;

uint32_t lichen_time_sync_get_sfn(void)
{
	return s_current_sfn;
}

int lichen_time_sync_set_sfn(uint32_t sfn)
{
	if (s_synced && sfn <= s_current_sfn) {
		return -EALREADY;
	}

	s_current_sfn = sfn;
	s_synced = true;

	return 0;
}

bool lichen_time_sync_is_synced(void)
{
	return s_synced;
}

void lichen_time_sync_advance_sfn(void)
{
	s_current_sfn++;
}

void lichen_time_sync_desync(void)
{
	s_synced = false;
}

int lichen_time_sync_init(void)
{
	s_current_sfn = 0;
	s_synced = false;

	return 0;
}
