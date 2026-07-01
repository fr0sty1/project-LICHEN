/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

int ble_ingress_ipv6_default(const uint8_t *ipv6, size_t len)
{
	ARG_UNUSED(ipv6);
	ARG_UNUSED(len);

	return -ENODEV;
}
