/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <lichen/oscore.h>
#include <lichen/coap_server.h>
#include <lichen/coap_dtn.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>
#include <errno.h>

static struct lichen_dtn_buffer s_dtn_buf;
static struct k_mutex s_dtn_mutex;
static uint64_t s_last_rate;

int lichen_coap_deaddrop_register(void) {
	oscore_init();
	lichen_coap_client_init();
	k_mutex_init(&s_dtn_mutex);
	lichen_dtn_init(&s_dtn_buf);
	lichen_dtn_expire_old(&s_dtn_buf,0);
	return 0;
}

int lichen_coap_dtn_init(void) {
	return lichen_coap_deaddrop_register();
}

static int deaddrop_get(struct coap_resource *r,struct coap_packet *req,struct sockaddr *addr,socklen_t alen) {
	k_mutex_lock(&s_dtn_mutex,K_FOREVER);
	uint8_t out[256];
	size_t olen=0;
	uint64_t now=k_uptime_get_64();
	if (now-s_last_rate<5000) {
		k_mutex_unlock(&s_dtn_mutex);
		return lichen_coap_respond(r,req,addr,alen,COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,0,NULL,0);
	}
	s_last_rate=now;
	lichen_dtn_expire_old(&s_dtn_buf,0);
	uint16_t pending = lichen_dtn_pending_count(&s_dtn_buf);
	olen = senml_encode_deaddrop(NULL, now/1000, pending, out, sizeof(out));
	k_mutex_unlock(&s_dtn_mutex);
	if (olen < 0) {
		return lichen_coap_respond(r,req,addr,alen,COAP_RESPONSE_CODE_INTERNAL_ERROR,0,NULL,0);
	}
	return lichen_coap_respond(r,req,addr,alen,COAP_RESPONSE_CODE_CONTENT,112,out,(size_t)olen);
}

uint16_t lichen_dtn_expire_periodic(void) {
	k_mutex_lock(&s_dtn_mutex,K_FOREVER);
	uint16_t n=lichen_dtn_expire_old(&s_dtn_buf,0);
	k_mutex_unlock(&s_dtn_mutex);
	return n;
}
