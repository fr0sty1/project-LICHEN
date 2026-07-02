/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef GATEWAY_INBOUND_COAP_H_
#define GATEWAY_INBOUND_COAP_H_

#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>

int gateway_inbound_text_post(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len);
int gateway_inbound_status_post(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len);
int gateway_inbound_location_post(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len);

#endif /* GATEWAY_INBOUND_COAP_H_ */
