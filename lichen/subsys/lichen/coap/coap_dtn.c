/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#include <lichen/coap_server.h>
#include <lichen/oscore.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>
#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
static struct lichen_dtn_buffer s_dtn_buf;
static struct senml_pack s_senml_pack;
int lichen_coap_deaddrop_register(void) {
	int r = oscore_init();
	if (r < 0) return r;
	r = lichen_dtn_init(&s_dtn_buf);
	if (r < 0) return r;
	r = senml_pack_init(&s_senml_pack, "", 0);
	if (r < 0) return r;
	return 0;
}
int lichen_coap_deaddrop_post(struct coap_packet *req, struct coap_packet *resp, uint8_t *data, size_t len) {
	uint8_t *payload;
	uint16_t payload_len;
	coap_packet_get_payload(req, &payload, &payload_len);
	int r = senml_encode_cbor(&s_senml_pack, payload, payload_len);
	if (r < 0) return r;
	return 0;
}
