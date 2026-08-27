/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_PUBKEY_TO_IID_TEST_COMPAT_H_
#define LICHEN_PUBKEY_TO_IID_TEST_COMPAT_H_

#include <stddef.h>
#include <stdint.h>

int lichen_iid_to_human_address(const uint8_t *iid, char *buf, size_t buflen);

#endif
