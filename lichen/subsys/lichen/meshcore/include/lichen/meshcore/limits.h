/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHCORE_LIMITS_H_
#define LICHEN_MESHCORE_LIMITS_H_

#include <zephyr/sys/util.h>

#define LICHEN_MESHCORE_FRAME_MAX CONFIG_LICHEN_MESHCORE_MAX_FRAME

/* MeshCore BLE transport inner frame maximum. This is the protocol limit
 * for BLE GATT operations in the MeshCore compatibility layer (176 bytes
 * chosen to fit typical BLE MTU constraints while leaving room for headers).
 * Kconfig ranges are coupled to this via BUILD_ASSERT below.
 */
#define LICHEN_MESHCORE_BLE_FRAME_MAX 176U

#endif /* LICHEN_MESHCORE_LIMITS_H_ */
