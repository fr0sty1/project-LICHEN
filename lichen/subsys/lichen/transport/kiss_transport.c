/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file kiss_transport.c
 * @brief KISS TNC transport for LICHEN
 *
 * Implements KISS protocol framing over UART/USB-CDC for TNC compatibility.
 * Supports port multiplexing: Port 0 for AX.25/APRS, Port 1 for raw LICHEN.
 *
 * Reference: http://www.ka9q.net/papers/kiss.html
 */

#include <lichen/transport/kiss_transport.h>

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/atomic.h>

LOG_MODULE_REGISTER(kiss_transport, CONFIG_KISS_TRANSPORT_LOG_LEVEL);

/* Configuration from Kconfig */
#define RX_RING_SIZE CONFIG_KISS_TRANSPORT_RX_RING_SIZE
#define RX_THREAD_STACK_SIZE CONFIG_KISS_TRANSPORT_RX_THREAD_STACK_SIZE
#define RX_THREAD_PRIORITY CONFIG_KISS_TRANSPORT_RX_THREAD_PRIORITY

/* ─── Transport context ───────────────────────────────────────────────────── */

struct kiss_transport_ctx {
	const struct device *uart_dev;
	bool initialized;
	atomic_t shutdown;
	struct kiss_transport_config config;

	/* KISS timing parameters */
	struct kiss_params params;
	struct k_mutex params_mutex;

	/* TX state */
	struct k_mutex tx_mutex;
	uint8_t tx_frame[KISS_MAX_PAYLOAD * 2u + 4u]; /* Worst case: all escaped + delimiters + cmd */
#ifdef CONFIG_ZTEST
	uint8_t last_tx[KISS_MAX_PAYLOAD * 2u + 4u];
	size_t last_tx_len;
#endif

	/* RX state */
	struct kiss_decode_ctx rx_ctx;

	/* RX ring buffer for interrupt-to-thread transfer */
	uint8_t rx_ring_buf[RX_RING_SIZE];
	struct ring_buf rx_ring;
	struct k_sem rx_sem;

	/* Statistics */
	struct kiss_transport_stats stats;
	struct k_mutex stats_mutex;
};

static struct kiss_transport_ctx s_ctx;

/* Forward declarations */
static void kiss_rx_thread_fn(void *p1, void *p2, void *p3);

/* RX thread */
static K_THREAD_STACK_DEFINE(s_rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread s_rx_thread;

/* ─── KISS framing utilities ──────────────────────────────────────────────── */

void kiss_decode_init(struct kiss_decode_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

int kiss_decode_byte(struct kiss_decode_ctx *ctx, uint8_t byte)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

	if (byte == KISS_FEND) {
		if (ctx->in_frame && ctx->has_cmd && ctx->len > 0) {
			/* Complete frame ready */
			ctx->in_frame = false;
			return 1;
		}
		/* Start of new frame or empty frame */
		ctx->in_frame = true;
		ctx->has_cmd = false;
		ctx->len = 0;
		ctx->escape_next = false;
		return 0;
	}

	if (!ctx->in_frame) {
		/* Data before first FEND - start frame implicitly */
		ctx->in_frame = true;
		ctx->has_cmd = false;
		ctx->len = 0;
		ctx->escape_next = false;
	}

	if (ctx->escape_next) {
		ctx->escape_next = false;
		if (byte == KISS_TFEND) {
			byte = KISS_FEND;
		} else if (byte == KISS_TFESC) {
			byte = KISS_FESC;
		} else {
			/* Invalid escape sequence - reset frame */
			LOG_WRN("KISS: invalid escape sequence 0x%02x", byte);
			ctx->in_frame = false;
			ctx->len = 0;
			return -EILSEQ;
		}
	} else if (byte == KISS_FESC) {
		ctx->escape_next = true;
		return 0;
	}

	/* First byte after FEND is the command byte */
	if (!ctx->has_cmd) {
		ctx->cmd = byte;
		ctx->has_cmd = true;
		return 0;
	}

	/* Store data byte */
	if (ctx->len < sizeof(ctx->buf)) {
		ctx->buf[ctx->len++] = byte;
	} else {
		LOG_WRN("KISS: frame overflow");
		ctx->in_frame = false;
		ctx->len = 0;
		return -EOVERFLOW;
	}

	return 0;
}

int kiss_encode(uint8_t port, uint8_t cmd,
		const uint8_t *data, size_t data_len,
		uint8_t *frame, size_t frame_max, size_t *frame_len)
{
	size_t fi = 0;
	uint8_t cmd_byte;

	if ((data == NULL && data_len > 0) || frame == NULL || frame_len == NULL) {
		return -EINVAL;
	}

	if (port > KISS_PORT_MAX) {
		return -EINVAL;
	}

	if (frame_max < 3u) {
		return -ENOMEM;
	}

	frame[fi++] = KISS_FEND;

	cmd_byte = KISS_CMD_MAKE(port, cmd);
	if (cmd_byte == KISS_FEND) {
		if (fi + 2 > frame_max) {
			return -ENOMEM;
		}
		frame[fi++] = KISS_FESC;
		frame[fi++] = KISS_TFEND;
	} else if (cmd_byte == KISS_FESC) {
		if (fi + 2 > frame_max) {
			return -ENOMEM;
		}
		frame[fi++] = KISS_FESC;
		frame[fi++] = KISS_TFESC;
	} else {
		frame[fi++] = cmd_byte;
	}

	for (size_t i = 0; i < data_len; i++) {
		uint8_t b = data[i];

		if (b == KISS_FEND) {
			if (fi + 2 > frame_max) {
				return -ENOMEM;
			}
			frame[fi++] = KISS_FESC;
			frame[fi++] = KISS_TFEND;
		} else if (b == KISS_FESC) {
			if (fi + 2 > frame_max) {
				return -ENOMEM;
			}
			frame[fi++] = KISS_FESC;
			frame[fi++] = KISS_TFESC;
		} else {
			if (fi + 1 > frame_max) {
				return -ENOMEM;
			}
			frame[fi++] = b;
		}
	}

	if (fi + 1 > frame_max) {
		return -ENOMEM;
	}
	frame[fi++] = KISS_FEND;

	*frame_len = fi;
	return 0;
}

/* ─── Command handling ────────────────────────────────────────────────────── */

static void handle_timing_command(struct kiss_transport_ctx *ctx,
				  uint8_t cmd, const uint8_t *data, size_t len)
{
	if (len < 1) {
		LOG_WRN("KISS: timing command without parameter");
		return;
	}

	k_mutex_lock(&ctx->params_mutex, K_FOREVER);

	switch (cmd) {
	case KISS_CMD_TXDELAY:
		ctx->params.txdelay = data[0];
		LOG_DBG("KISS: TxDelay set to %u (=%ums)", data[0], data[0] * 10u);
		break;

	case KISS_CMD_PERSISTENCE:
		ctx->params.persistence = data[0];
		LOG_DBG("KISS: Persistence set to %u (%u/255)",
			data[0], data[0]);
		break;

	case KISS_CMD_SLOTTIME:
		ctx->params.slottime = data[0];
		LOG_DBG("KISS: SlotTime set to %u (=%ums)", data[0], data[0] * 10u);
		break;

	case KISS_CMD_TXTAIL:
		/* Accept but ignore - LoRa handles TX tail automatically */
		ctx->params.txtail = data[0];
		LOG_DBG("KISS: TxTail set to %u (ignored for LoRa)", data[0]);
		break;

	case KISS_CMD_FULLDUPLEX:
		/* Accept but ignore - LoRa is always half-duplex */
		ctx->params.fullduplex = (data[0] != 0);
		LOG_DBG("KISS: FullDuplex set to %u (ignored for LoRa)", data[0]);
		break;

	default:
		break;
	}

	k_mutex_unlock(&ctx->params_mutex);
}

static void handle_sethardware(struct kiss_transport_ctx *ctx,
			       const uint8_t *data, size_t len)
{
	uint8_t response[64];
	int resp_len;

	if (ctx->config.hw_cmd_cb == NULL) {
		LOG_DBG("KISS: SetHardware command ignored (no handler)");
		return;
	}

	resp_len = ctx->config.hw_cmd_cb(data, len, response, sizeof(response),
					 ctx->config.user_ctx);
	if (resp_len > 0) {
		uint8_t resp_frame[132];
		size_t resp_frame_len;
		uint8_t resp_cmd = KISS_CMD_SETHARDWARE | 0x80u;

		if (kiss_encode(0, resp_cmd, response, (size_t)resp_len,
				resp_frame, sizeof(resp_frame), &resp_frame_len) == 0) {
			k_mutex_lock(&ctx->tx_mutex, K_FOREVER);
			if (ctx->uart_dev != NULL) {
				for (size_t i = 0; i < resp_frame_len; i++) {
					uart_poll_out(ctx->uart_dev, resp_frame[i]);
				}
			}
			k_mutex_unlock(&ctx->tx_mutex);
		}
	}
}

static void dispatch_frame(struct kiss_transport_ctx *ctx)
{
	uint8_t port = KISS_CMD_PORT(ctx->rx_ctx.cmd);
	uint8_t cmd_type = KISS_CMD_TYPE(ctx->rx_ctx.cmd);

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	ctx->stats.rx_frames++;
	if (cmd_type == KISS_CMD_DATA) {
		if (port == KISS_PORT_AX25) {
			ctx->stats.rx_data_port0++;
		} else if (port == KISS_PORT_LICHEN_RAW) {
			ctx->stats.rx_data_port1++;
		} else {
			ctx->stats.unknown_port++;
		}
	} else if (cmd_type == KISS_CMD_TXDELAY || cmd_type == KISS_CMD_PERSISTENCE ||
		   cmd_type == KISS_CMD_SLOTTIME || cmd_type == KISS_CMD_TXTAIL ||
		   cmd_type == KISS_CMD_FULLDUPLEX || cmd_type == KISS_CMD_SETHARDWARE) {
		ctx->stats.rx_commands++;
	}
	k_mutex_unlock(&ctx->stats_mutex);

	LOG_DBG("KISS RX: port=%u cmd=%u len=%zu", port, cmd_type, ctx->rx_ctx.len);

	switch (cmd_type) {
	case KISS_CMD_DATA:
		if (port == KISS_PORT_AX25) {
			if (ctx->config.ax25_rx_cb != NULL) {
				ctx->config.ax25_rx_cb(ctx->rx_ctx.buf, ctx->rx_ctx.len,
						       ctx->config.user_ctx);
			}
		} else if (port == KISS_PORT_LICHEN_RAW) {
			if (ctx->config.raw_rx_cb != NULL) {
				ctx->config.raw_rx_cb(ctx->rx_ctx.buf, ctx->rx_ctx.len,
						      ctx->config.user_ctx);
			}
		} else {
			LOG_WRN("KISS: data on unsupported port %u", port);
		}
		break;

	case KISS_CMD_TXDELAY:
	case KISS_CMD_PERSISTENCE:
	case KISS_CMD_SLOTTIME:
	case KISS_CMD_TXTAIL:
	case KISS_CMD_FULLDUPLEX:
		handle_timing_command(ctx, cmd_type, ctx->rx_ctx.buf, ctx->rx_ctx.len);
		break;

	case KISS_CMD_SETHARDWARE:
		handle_sethardware(ctx, ctx->rx_ctx.buf, ctx->rx_ctx.len);
		break;

	case KISS_CMD_RETURN:
		LOG_DBG("KISS: Return command ignored");
		break;

	default:
		LOG_WRN("KISS: unknown command type %u", cmd_type);
		break;
	}
}

/* ─── UART callbacks and RX thread ────────────────────────────────────────── */

static void uart_rx_callback(const struct device *dev, void *user_data)
{
	struct kiss_transport_ctx *ctx = user_data;
	uint8_t c;

	ARG_UNUSED(dev);

	while (uart_irq_update(ctx->uart_dev) &&
	       uart_irq_rx_ready(ctx->uart_dev)) {
		int n = uart_fifo_read(ctx->uart_dev, &c, 1);

		if (n == 1) {
			uint32_t written = ring_buf_put(&ctx->rx_ring, &c, 1);

			if (written == 0) {
				LOG_WRN("KISS RX: ring buffer overflow");
				ctx->stats.overflow_errors++;
			}
			k_sem_give(&ctx->rx_sem);
		}
	}
}

static void kiss_rx_thread_fn(void *p1, void *p2, void *p3)
{
	struct kiss_transport_ctx *ctx = p1;
	uint8_t buf[32];
	uint32_t n;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("KISS RX thread started");

	while (atomic_get(&ctx->shutdown) == 0) {
		k_sem_take(&ctx->rx_sem, K_FOREVER);

		if (atomic_get(&ctx->shutdown) != 0) {
			break;
		}

		/* Drain the ring buffer */
		while ((n = ring_buf_get(&ctx->rx_ring, buf, sizeof(buf))) > 0) {
			k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
			ctx->stats.rx_bytes += n;
			k_mutex_unlock(&ctx->stats_mutex);

			for (uint32_t i = 0; i < n; i++) {
				int ret = kiss_decode_byte(&ctx->rx_ctx, buf[i]);

				if (ret == 1) {
					/* Complete frame ready */
					dispatch_frame(ctx);
					kiss_decode_init(&ctx->rx_ctx);
				} else if (ret < 0) {
					/* Error - frame already reset */
					k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
					if (ret == -EOVERFLOW) {
						ctx->stats.overflow_errors++;
					} else {
						ctx->stats.frame_errors++;
					}
					k_mutex_unlock(&ctx->stats_mutex);
				}
			}
		}
	}

	LOG_INF("KISS RX thread exiting");
}

/* ─── TX helper ───────────────────────────────────────────────────────────── */

static int kiss_tx_frame(struct kiss_transport_ctx *ctx,
			 uint8_t port, const uint8_t *data, size_t len)
{
	size_t frame_len;
	int ret;

	if (data == NULL && len > 0) {
		return -EINVAL;
	}

	if (len > KISS_MAX_PAYLOAD) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);

	ret = kiss_encode(port, KISS_CMD_DATA, data, len,
			  ctx->tx_frame, sizeof(ctx->tx_frame), &frame_len);
	if (ret < 0) {
		k_mutex_unlock(&ctx->tx_mutex);
		return ret;
	}

#ifdef CONFIG_ZTEST
	memcpy(ctx->last_tx, ctx->tx_frame, frame_len);
	ctx->last_tx_len = frame_len;
#endif

	if (ctx->uart_dev != NULL) {
		for (size_t i = 0; i < frame_len; i++) {
			uart_poll_out(ctx->uart_dev, ctx->tx_frame[i]);
		}

		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_frames++;
		ctx->stats.tx_bytes += (uint32_t)frame_len;
		if (port == KISS_PORT_AX25) {
			ctx->stats.tx_data_port0++;
		} else if (port == KISS_PORT_LICHEN_RAW) {
			ctx->stats.tx_data_port1++;
		}
		k_mutex_unlock(&ctx->stats_mutex);
	} else {
		k_mutex_unlock(&ctx->tx_mutex);
		return -ENODEV;
	}

	k_mutex_unlock(&ctx->tx_mutex);

	LOG_DBG("KISS TX: port=%u len=%zu -> %zu bytes framed", port, len, frame_len);
	return 0;
}

/* ─── Public API ──────────────────────────────────────────────────────────── */

int kiss_transport_init(const struct kiss_transport_config *config)
{
	struct kiss_transport_ctx *ctx = &s_ctx;
	const struct device *uart_dev;

	if (config == NULL) {
		return -EINVAL;
	}

	/* At least one RX callback required */
	if (config->ax25_rx_cb == NULL && config->raw_rx_cb == NULL) {
		LOG_ERR("KISS: at least one RX callback required");
		return -EINVAL;
	}

	if (ctx->initialized) {
		return -EALREADY;
	}

	/* Initialize synchronization primitives */
	k_mutex_init(&ctx->tx_mutex);
	k_mutex_init(&ctx->params_mutex);
	k_mutex_init(&ctx->stats_mutex);
	k_sem_init(&ctx->rx_sem, 0, K_SEM_MAX_LIMIT);
	ring_buf_init(&ctx->rx_ring, sizeof(ctx->rx_ring_buf), ctx->rx_ring_buf);
	atomic_set(&ctx->shutdown, 0);

	/* Initialize RX decoder */
	kiss_decode_init(&ctx->rx_ctx);

	/* Initialize default timing parameters */
	ctx->params.txdelay = KISS_DEFAULT_TXDELAY;
	ctx->params.persistence = KISS_DEFAULT_PERSISTENCE;
	ctx->params.slottime = KISS_DEFAULT_SLOTTIME;
	ctx->params.txtail = 0;
	ctx->params.fullduplex = false;

	/* Reset statistics */
	memset(&ctx->stats, 0, sizeof(ctx->stats));

	/* Store configuration */
	ctx->config = *config;

	/* Get UART device */
#if DT_HAS_CHOSEN(lichen_kiss_uart)
	uart_dev = DEVICE_DT_GET(DT_CHOSEN(lichen_kiss_uart));
#else
	uart_dev = NULL;
#endif

	if (uart_dev != NULL && device_is_ready(uart_dev)) {
		ctx->uart_dev = uart_dev;

		/* Configure UART interrupts for RX */
		uart_irq_callback_user_data_set(uart_dev, uart_rx_callback, ctx);
		uart_irq_rx_enable(uart_dev);

		LOG_INF("KISS transport: UART %s ready", uart_dev->name);
	} else {
		LOG_WRN("KISS transport: no UART device available");
		ctx->uart_dev = NULL;
	}

	/* Start RX processing thread */
	k_thread_create(&s_rx_thread, s_rx_stack, K_THREAD_STACK_SIZEOF(s_rx_stack),
			kiss_rx_thread_fn, ctx, NULL, NULL,
			RX_THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_rx_thread, "kiss_rx");

	ctx->initialized = true;
	LOG_INF("KISS transport initialized");

	return 0;
}

void kiss_transport_deinit(void)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (!ctx->initialized) {
		return;
	}

	if (ctx->uart_dev != NULL) {
		uart_irq_rx_disable(ctx->uart_dev);
	}

	atomic_set(&ctx->shutdown, 1);
	k_sem_give(&ctx->rx_sem);

	/* Wait for the RX thread to exit gracefully */
	int ret = k_thread_join(&s_rx_thread, K_MSEC(1000));
	if (ret != 0) {
		LOG_WRN("KISS RX thread join failed: %d, aborting", ret);
		k_thread_abort(&s_rx_thread);
	}

	ctx->initialized = false;
	LOG_INF("KISS transport deinitialized");
}

bool kiss_transport_is_ready(void)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	return ctx->initialized;
}

int kiss_transport_send_ax25(const uint8_t *data, size_t len)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (!ctx->initialized) {
		return -ENODEV;
	}

	return kiss_tx_frame(ctx, KISS_PORT_AX25, data, len);
}

int kiss_transport_send_raw(const uint8_t *data, size_t len)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (!ctx->initialized) {
		return -ENODEV;
	}

	return kiss_tx_frame(ctx, KISS_PORT_LICHEN_RAW, data, len);
}

int kiss_transport_send(uint8_t port, const uint8_t *data, size_t len)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (!ctx->initialized) {
		return -ENODEV;
	}

	if (port > KISS_PORT_MAX) {
		return -EINVAL;
	}

	return kiss_tx_frame(ctx, port, data, len);
}

int kiss_transport_get_params(struct kiss_params *params)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (params == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->params_mutex, K_FOREVER);
	*params = ctx->params;
	k_mutex_unlock(&ctx->params_mutex);

	return 0;
}

int kiss_transport_set_params(const struct kiss_params *params)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (params == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->params_mutex, K_FOREVER);
	ctx->params = *params;
	k_mutex_unlock(&ctx->params_mutex);

	return 0;
}

int kiss_transport_get_stats(struct kiss_transport_stats *stats)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	if (stats == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	*stats = ctx->stats;
	k_mutex_unlock(&ctx->stats_mutex);

	return 0;
}

void kiss_transport_reset_stats(void)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	memset(&ctx->stats, 0, sizeof(ctx->stats));
	k_mutex_unlock(&ctx->stats_mutex);
}

/* ─── Test helpers ────────────────────────────────────────────────────────── */

#ifdef CONFIG_ZTEST
int kiss_transport_test_inject_rx(const uint8_t *data, size_t len)
{
	struct kiss_transport_ctx *ctx = &s_ctx;
	int frames = 0;

	for (size_t i = 0; i < len; i++) {
		int ret = kiss_decode_byte(&ctx->rx_ctx, data[i]);

		if (ret == 1) {
			dispatch_frame(ctx);
			kiss_decode_init(&ctx->rx_ctx);
			frames++;
		}
	}

	return frames;
}

int kiss_transport_test_get_last_tx(uint8_t *buf, size_t max, size_t *len)
{
	struct kiss_transport_ctx *ctx = &s_ctx;
	size_t copy_len;

	if (buf == NULL || len == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);

	copy_len = MIN(ctx->last_tx_len, max);
	if (copy_len > 0) {
		memcpy(buf, ctx->last_tx, copy_len);
	}
	*len = ctx->last_tx_len;

	k_mutex_unlock(&ctx->tx_mutex);

	return 0;
}

void kiss_transport_test_reset(void)
{
	struct kiss_transport_ctx *ctx = &s_ctx;

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);
	k_mutex_lock(&ctx->params_mutex, K_FOREVER);
	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);

	kiss_decode_init(&ctx->rx_ctx);
	ring_buf_reset(&ctx->rx_ring);
	memset(&ctx->stats, 0, sizeof(ctx->stats));
	ctx->last_tx_len = 0;

	ctx->params.txdelay = KISS_DEFAULT_TXDELAY;
	ctx->params.persistence = KISS_DEFAULT_PERSISTENCE;
	ctx->params.slottime = KISS_DEFAULT_SLOTTIME;
	ctx->params.txtail = 0;
	ctx->params.fullduplex = false;

	k_mutex_unlock(&ctx->stats_mutex);
	k_mutex_unlock(&ctx->params_mutex);
	k_mutex_unlock(&ctx->tx_mutex);
}
#endif /* CONFIG_ZTEST */
