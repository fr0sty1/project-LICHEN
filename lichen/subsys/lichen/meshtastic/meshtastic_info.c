/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "meshtastic_pb.h"

const char *info_long_name(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->long_name != NULL &&
		info->long_name[0] != '\0') ? info->long_name : "LICHEN Node";
}

const char *info_short_name(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->short_name != NULL &&
		info->short_name[0] != '\0') ? info->short_name : "LICH";
}

/*
 * SECURITY: The returned pointer is only valid while the info struct and its
 * firmware_version string remain allocated and unmodified. Callers must encode
 * or copy the result before freeing or reusing the info struct.
 */
const char *info_firmware_version(
	const struct lichen_meshtastic_local_info *info)
{
	const char *version = (info != NULL) ? info->firmware_version : NULL;
	size_t meshtastic_pos = 0U;
	size_t brand_len = strlen(LICHEN_BRAND);
	char next;

	if (version == NULL || strncmp(version, LICHEN_BRAND, brand_len) != 0) {
		return "LICHEN Zephyr compat 0.0.0+unknown";
	}

	next = version[brand_len];
	if (next != '\0' && next != ' ' && next != '-' && next != '+') {
		return "LICHEN Zephyr compat 0.0.0+unknown";
	}

	for (const char *p = version; *p != '\0'; p++) {
		char c = *p;

		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
		if (c == MESHTASTIC_BRAND[meshtastic_pos]) {
			meshtastic_pos++;
			if (MESHTASTIC_BRAND[meshtastic_pos] == '\0') {
				return "LICHEN Zephyr compat 0.0.0+unknown";
			}
		} else {
			meshtastic_pos = (c == MESHTASTIC_BRAND[0]) ? 1U : 0U;
		}
	}

	return info->firmware_version;
}

const char *info_pio_env(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->pio_env != NULL &&
		info->pio_env[0] != '\0') ? info->pio_env : "zephyr";
}

uint32_t info_node_num(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->node_num != 0U) ? info->node_num :
							0x4c494348U;
}

uint32_t info_min_app_version(
	const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->min_app_version != 0U) ?
		       info->min_app_version :
		       30200U;
}

uint32_t info_nodedb_count(
	const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->nodedb_count != 0U) ?
		       info->nodedb_count :
		       1U;
}

uint32_t info_hops_away(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->has_hops_away) ? info->hops_away : 0U;
}

uint32_t info_excluded_modules(
	const struct lichen_meshtastic_local_info *info)
{
	uint32_t excluded = EXCLUDED_MODULES_MVP;

	if (info == NULL || !info->has_bluetooth) {
		excluded |= EXCLUDED_BLUETOOTH_CONFIG;
	}

	return excluded;
}

bool info_has_position(const struct lichen_meshtastic_local_info *info)
{
	/* Meshtastic Position is location-bearing. Do not emit a partial
	 * Position for time-only, altitude-only, or satellites-only metadata:
	 * many clients interpret the message as map-ready once present.
	 */
	return info != NULL && info->has_latitude_e7 && info->has_longitude_e7;
}
