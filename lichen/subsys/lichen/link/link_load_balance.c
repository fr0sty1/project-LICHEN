/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link_load_balance.h>
#include <stddef.h>

/* Forward declaration: declared in <lichen/link.h> (Zephyr environment) */
uint32_t lichen_hash_32(const uint8_t *data, size_t len);

void lichen_lb_metrics_init(struct lichen_lb_metrics *m)
{
	m->packets_tx = 0;
	m->packets_rx = 0;
	m->tx_failures = 0;
	m->snr.min = 127;
	m->snr.max = -128;
	m->snr.avg_fp = 0;
	m->snr.count = 0;
	m->density = 0;
	m->load_factor_fp = 0;
}

void lichen_lb_record_tx(struct lichen_lb_metrics *m)
{
	if (m->packets_tx < 0xFFFFFFFFu) {
		m->packets_tx++;
	}
}

void lichen_lb_update_snr(struct lichen_lb_snr_stats *s, int8_t snr)
{
	int32_t snr_fp = (int32_t)snr << 16;
	if (s->count == 0) {
		s->avg_fp = snr_fp;
	} else {
		int32_t diff = snr_fp - s->avg_fp;
		s->avg_fp += diff >> (int32_t)LICHEN_LB_EMA_ALPHA_SHIFT;
	}
	if (snr < s->min) s->min = snr;
	if (snr > s->max) s->max = snr;
	s->count++;
	if (s->count == 0) s->count--;
}

void lichen_lb_record_rx(struct lichen_lb_metrics *m, int8_t snr)
{
	if (m->packets_rx < 0xFFFFFFFFu) {
		m->packets_rx++;
	}
	lichen_lb_update_snr(&m->snr, snr);
}

void lichen_lb_record_tx_fail(struct lichen_lb_metrics *m)
{
	if (m->tx_failures < 0xFFFFFFFFu) {
		m->tx_failures++;
	}
}

void lichen_lb_record_density(struct lichen_lb_metrics *m, uint8_t density)
{
	m->density = density;
}

void lichen_lb_record_load_factor(struct lichen_lb_metrics *m, uint32_t load_fp)
{
	m->load_factor_fp = (load_fp <= LICHEN_LB_FP_SCALE) ? load_fp : LICHEN_LB_FP_SCALE;
}

uint8_t lichen_lb_packet_loss_pct(const struct lichen_lb_metrics *m)
{
	if (m->packets_tx == 0) return 0;
	uint64_t num = (uint64_t)m->tx_failures * 100u;
	uint64_t pct = num / (uint64_t)m->packets_tx;
	return (pct > 100u) ? 100u : (uint8_t)pct;
}

uint32_t lichen_lb_packet_loss_fp(const struct lichen_lb_metrics *m)
{
	if (m->packets_tx == 0) return 0;
	uint64_t num = (uint64_t)m->tx_failures * 100u * (uint64_t)LICHEN_LB_FP_SCALE;
	uint64_t rate = num / (uint64_t)m->packets_tx;
	return (rate > (uint64_t)0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)rate;
}

uint8_t lichen_lb_adaptive_sf(const struct lichen_lb_metrics *m)
{
	int8_t snr_ema = (m->snr.count == 0) ? 0 : (int8_t)((m->snr.avg_fp + (1 << 15)) >> 16);
	bool load_high = m->load_factor_fp > LICHEN_LB_LOAD_HIGH;

	if (m->density > LICHEN_LB_DENSITY_CRITICAL || snr_ema < LICHEN_LB_SNR_CRITICAL) {
		return 12;
	}
	if (m->density > LICHEN_LB_DENSITY_HIGH || snr_ema < LICHEN_LB_SNR_POOR || load_high) {
		return 11;
	}
	if (m->density < LICHEN_LB_DENSITY_LOW && snr_ema > LICHEN_LB_SNR_GOOD) {
		return 9;
	}
	return 10;
}

bool lichen_lb_should_rebalance(const struct lichen_lb_metrics *m)
{
	if (m->density > LICHEN_LB_DENSITY_HIGH) return true;
	if (m->load_factor_fp > LICHEN_LB_LOAD_REBALANCE) return true;
	if (lichen_lb_packet_loss_pct(m) > 40) return true;
	return false;
}

uint8_t lichen_lb_select_channel(const struct lichen_lb_metrics *m,
				 const uint8_t eui64[8], uint32_t epoch,
				 uint8_t n_channels)
{
	if (m->density > LICHEN_LB_DENSITY_HIGH) {
		return 0;
	}
	uint8_t data[12];
	for (int i = 0; i < 8; i++) {
		data[i] = eui64[i];
	}
	for (int i = 0; i < 4; i++) {
		data[8 + i] = (uint8_t)(epoch >> (i * 8));
	}
	uint32_t hash = lichen_hash_32(data, 12);
	uint8_t n = (n_channels < 3) ? 3 : n_channels;
	return 1 + (uint8_t)(hash % (uint32_t)n);
}
