/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rf_health.h>

#define FP_SCALE (1 << 16)
#define FP_ROUND (1 << 15)

void lichen_rf_health_init(struct lichen_rf_health *h)
{
	h->packets_tx = 0;
	h->packets_rx = 0;
	h->tx_failures = 0;
	h->snr.min = INT8_MAX;
	h->snr.max = INT8_MIN;
	h->snr.avg_fp = 0;
	h->snr.count = 0;
	h->density = 0;
	h->load_factor_fp = 0;
}

void lichen_rf_health_record_tx(struct lichen_rf_health *h)
{
	h->packets_tx++;
}

void lichen_rf_health_record_rx(struct lichen_rf_health *h, int8_t snr)
{
	h->packets_rx++;
	if (snr < h->snr.min) h->snr.min = snr;
	if (snr > h->snr.max) h->snr.max = snr;

	int32_t snr_fp = (int32_t)snr << 16;
	if (h->snr.count == 0) {
		h->snr.avg_fp = snr_fp;
	} else {
		int32_t diff = snr_fp - h->snr.avg_fp;
		h->snr.avg_fp += diff >> LICHEN_RF_EMA_ALPHA_SHIFT;
	}
	h->snr.count++;
}

void lichen_rf_health_record_tx_fail(struct lichen_rf_health *h)
{
	h->tx_failures++;
}

void lichen_rf_health_record_density(struct lichen_rf_health *h, uint8_t density)
{
	h->density = density;
}

void lichen_rf_health_record_load_factor(struct lichen_rf_health *h, uint32_t load_fp)
{
	h->load_factor_fp = load_fp < FP_SCALE ? load_fp : FP_SCALE;
}

uint32_t lichen_rf_health_packet_loss_rate_fp(const struct lichen_rf_health *h)
{
	if (h->packets_tx == 0) return 0;
	uint64_t numerator = (uint64_t)h->tx_failures * 100 * FP_SCALE;
	return (uint32_t)(numerator / h->packets_tx);
}

uint8_t lichen_rf_health_packet_loss_rate_pct(const struct lichen_rf_health *h)
{
	uint32_t fp = lichen_rf_health_packet_loss_rate_fp(h);
	uint32_t pct = fp >> 16;
	return (uint8_t)(pct > 100 ? 100 : pct);
}

uint16_t lichen_rf_health_packet_loss_permille(const struct lichen_rf_health *h)
{
	uint32_t fp = lichen_rf_health_packet_loss_rate_fp(h);
	uint64_t permille = ((uint64_t)fp * 10) >> 16;
	return (uint16_t)(permille > 1000 ? 1000 : permille);
}

int8_t lichen_rf_health_snr_avg(const struct lichen_rf_health *h)
{
	if (h->snr.count == 0) return 0;
	return (int8_t)((h->snr.avg_fp + FP_ROUND) >> 16);
}

uint8_t lichen_rf_health_adaptive_sf(const struct lichen_rf_health *h)
{
	int8_t snr_ema = lichen_rf_health_snr_avg(h);
	bool load_high = h->load_factor_fp > LICHEN_RF_LOAD_HIGH_FP;

	if (h->density > LICHEN_RF_DENSITY_CRITICAL || snr_ema < LICHEN_RF_SNR_CRITICAL) {
		return 12;
	}
	if (h->density > LICHEN_RF_DENSITY_HIGH || snr_ema < LICHEN_RF_SNR_POOR || load_high) {
		return 11;
	}
	if (h->density < LICHEN_RF_DENSITY_LOW && snr_ema > LICHEN_RF_SNR_GOOD) {
		return 9;
	}
	return 10;
}

bool lichen_rf_health_should_rebalance(const struct lichen_rf_health *h)
{
	return h->density > LICHEN_RF_DENSITY_HIGH
		|| h->load_factor_fp > LICHEN_RF_LOAD_REBALANCE_FP
		|| lichen_rf_health_packet_loss_rate_pct(h) > 40;
}

void lichen_rf_health_reset(struct lichen_rf_health *h)
{
	lichen_rf_health_init(h);
}
