/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_INTERFACE_HAL_BRIDGE_H_
#define LICHEN_APP_INTERFACE_HAL_BRIDGE_H_

#include <lichen/app_interface/app_interface.h>
#include <lichen/hal.h>

#ifdef __cplusplus
extern "C" {
#endif

int lichen_app_location_time_from_hal(
	struct lichen_app_location_time_snapshot *app,
	const struct lichen_hal_location_time_snapshot *hal);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_INTERFACE_HAL_BRIDGE_H_ */
