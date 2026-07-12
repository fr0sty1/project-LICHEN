/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_INTERFACE_HAL_BRIDGE_H_
#define LICHEN_APP_INTERFACE_HAL_BRIDGE_H_

#include <lichen/app_interface/app_interface.h>
#include <lichen/hal.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

int lichen_app_location_time_from_hal(
	struct lichen_app_location_time_snapshot *_Nonnull app,
	const struct lichen_hal_location_time_snapshot *_Nonnull hal);
int lichen_app_time_from_hal(struct lichen_app_time_snapshot *_Nonnull app,
			     const struct lichen_hal_time_snapshot *_Nonnull hal);
int lichen_app_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *_Nonnull app);
int lichen_app_network_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *_Nonnull app);
int lichen_app_network_location_clear_from_hal(void);
int lichen_app_manual_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *_Nonnull app);
int lichen_app_time_submit_to_hal(const struct lichen_app_time_snapshot *_Nonnull app);
int lichen_app_network_time_submit_to_hal(
	const struct lichen_app_time_snapshot *_Nonnull app);
int lichen_app_manual_time_submit_to_hal(
	const struct lichen_app_time_snapshot *_Nonnull app);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_INTERFACE_HAL_BRIDGE_H_ */
