/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COAP_DTN_H_
#define LICHEN_COAP_DTN_H_

#include <lichen/coap_server.h>

int lichen_coap_dtn_init(void);
int lichen_coap_deaddrop_register(struct lichen_deaddrop_provider *provider);
uint16_t lichen_dtn_expire_periodic(void);

#endif

