/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/watchdog.h>
#include <zephyr/kernel.h>
#include <zephyr/pm/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/crc.h>
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

#include <lichen/hal.h>

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

/* Stall-marker uses the nRF GPREGRET2 retention register (nRF boards only). */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#include <nrfx_power.h>
#define STALL_MARKER_HAVE 1
#endif

LOG_MODULE_REGISTER(lichen_puck, LOG_LEVEL_INF);

/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5 @ 868 MHz (EU). */
#define LORA_FREQ_HZ       868000000U
#define LORA_MAX_FRAME     255
#define BEACON_INTERVAL_MS CONFIG_LICHEN_PUCK_BEACON_INTERVAL_MS

/*
 * LICHEN announce frame with 32-bit CRC MIC.
 *   [0] length = 9   (total frame size)
 *   [1] llsec  = 0x00  (AddrMode=0, MIC32, no sig, no enc)
 *   [2] epoch  = 0
 *   [3] seqhi  = 0
 *   [4] seqlo  = incremented on each TX
 *   [5-8] MIC  = CRC32 of bytes 1-4 (llsec through seqlo)
 */
#define BEACON_HDR_LEN 5
#define BEACON_MIC_LEN 4
#define BEACON_TOTAL_LEN (BEACON_HDR_LEN + BEACON_MIC_LEN)
static uint8_t s_beacon[BEACON_TOTAL_LEN];
static uint8_t s_seqnum;
static uint8_t s_epoch;

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
/* Placeholder IID — in production derive from nRF52840 FICR. */
static const uint8_t s_iid[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

/* Radio stats forwarded to native protocol */
static struct ln_radio_stats s_radio_stats;

/* Last known GPS fix */
static struct ln_gps_info s_gps;
#endif

/* --------------------------------------------------------------------------
 * GNSS callback (called from GNSS driver context)
 * -------------------------------------------------------------------------- */

#if defined(LICHEN_HAL_GNSS_DEVICE) && IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <zephyr/drivers/gnss.h>

static void on_gnss_data(const struct device *dev, const struct gnss_data *data)
{
	ARG_UNUSED(dev);

	if (data->info.fix_status == GNSS_FIX_STATUS_NO_FIX) {
		s_gps.valid = false;
		return;
	}

	s_gps.lat_udeg  = (int32_t)(data->nav_data.latitude  / 1000); /* nanodeg → microdeg */
	s_gps.lon_udeg  = (int32_t)(data->nav_data.longitude / 1000);
	s_gps.alt_cm    = data->nav_data.altitude / 10;              /* mm → cm */
	s_gps.valid     = true;
}

GNSS_DATA_CALLBACK_DEFINE(LICHEN_HAL_GNSS_DEVICE, on_gnss_data);
#endif

/* --------------------------------------------------------------------------
 * LICHEN Native incoming message handler
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
static void on_native_rx(uint8_t msg_type, const uint8_t *buf, size_t len)
{
	/*
	 * lichen_native_handle_rx handles hello and log_subscribe internally.
	 * send_message (0x20) → transmit on LoRa.
	 */
	if (msg_type == LN_TYPE_SEND_MESSAGE) {
		/* Minimal: ignore routing, blast the payload over LoRa.
		 * Full implementation would parse dest IID and route. */
		LOG_DBG("host send_message — LoRa TX not yet implemented");
	} else {
		lichen_native_handle_rx(msg_type, buf, len);
	}
}
#endif

/* --------------------------------------------------------------------------
 * LoRa helpers
 * -------------------------------------------------------------------------- */

static int lora_set_mode(const struct device *dev, bool tx)
{
	struct lora_modem_config cfg = {
		.frequency     = LORA_FREQ_HZ,
		.bandwidth     = BW_125_KHZ,
		.datarate      = SF_10,
		.coding_rate   = CR_4_5,
		.preamble_len  = 8,
		.tx_power      = 14,
		.tx            = tx,
		.public_network = false,
	};
	return lora_config(dev, &cfg);
}

/* Main-loop phase marker (retained across watchdog reset — see stall_report).
 *
 * Stored in the GPREGRET2 retention register, NOT RAM: MCUboot runs between the
 * watchdog reset and the app and clobbers .noinit RAM, but leaves GPREGRET2
 * alone. GPREGRET (reg 0) is reserved for the DFU-touch magic. High nibble
 * 0xA0 = valid marker, low nibble = phase. */
enum stall_phase {
	PH_BOOT = 0, PH_RECV, PH_RX_FORWARD, PH_CFG_TX,
	PH_TX, PH_CFG_RX, PH_NODE_INFO, PH_NPHASES,
};

#define STALL_GPREG_MAGIC 0xA0u

static inline void set_phase(enum stall_phase ph)
{
#if defined(STALL_MARKER_HAVE)
	NRF_POWER->GPREGRET2 = STALL_GPREG_MAGIC | ((uint32_t)ph & 0x0Fu);
#else
	ARG_UNUSED(ph);
#endif
}

static void send_beacon(const struct device *dev)
{
	/* Build beacon header */
	s_beacon[0] = BEACON_TOTAL_LEN;
	s_beacon[1] = 0x00;  /* LLSec: AddrMode=0, MIC32, no sig, no enc */
	if (++s_seqnum == 0) {
		s_epoch++;  /* Increment epoch on seqnum wrap */
	}
	s_beacon[2] = s_epoch;   /* epoch */
	s_beacon[3] = 0x00;      /* seqhi */
	s_beacon[4] = s_seqnum;  /* seqlo */

	/* Compute CRC32 MIC over header (bytes 1-4, excluding length byte) */
	uint32_t mic = crc32_ieee(&s_beacon[1], BEACON_HDR_LEN - 1);
	s_beacon[5] = (uint8_t)(mic & 0xFF);
	s_beacon[6] = (uint8_t)((mic >> 8) & 0xFF);
	s_beacon[7] = (uint8_t)((mic >> 16) & 0xFF);
	s_beacon[8] = (uint8_t)((mic >> 24) & 0xFF);

	set_phase(PH_CFG_TX);
	if (lora_set_mode(dev, true) < 0) {
		LOG_ERR("TX config failed");
		return;
	}
	set_phase(PH_TX);
	int ret = lora_send(dev, s_beacon, sizeof(s_beacon));
	if (ret < 0) {
		LOG_ERR("beacon TX failed: %d", ret);
	} else {
		LOG_INF("beacon seq=%u mic=0x%08x", s_seqnum, mic);
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
		s_radio_stats.tx_pkts++;
#endif
	}
	set_phase(PH_CFG_RX);
	lora_set_mode(dev, false);
}

/* --------------------------------------------------------------------------
 * Hardware watchdog — resilience against radio-driver lockups
 *
 * A LoRa TX/RX can wedge the main thread (e.g. a radio SPI transaction that
 * never completes when USB-CDC EasyDMA contends with the SPIM). We can't feed
 * the watchdog straight from the main loop: a normal RX wait blocks up to 5 s,
 * so a main-loop-granular watchdog needs a ~20 s timeout — slow recovery that
 * makes host monitoring painful (long USB drop-outs).
 *
 * Instead we track a "progress" heartbeat that the radio driver bumps from
 * inside its poll loops (via the weak lichen_radio_progress() hook it calls),
 * plus the main loop each iteration. A k_timer feeds the SoC watchdog only
 * while the heartbeat is fresh. Normal multi-second RX/TX waits keep bumping
 * the heartbeat so they don't trip it; a genuine stall stops the bumps and the
 * watchdog resets within a few seconds.
 *
 * The feeder runs from a k_timer (system-clock ISR), NOT a thread: under heavy
 * USB-CDC contention the CDC work queue can starve a cooperative feeder thread,
 * which would withhold the feed and reset the SoC even though main is fine. A
 * timer ISR cannot be starved by threads.
 * -------------------------------------------------------------------------- */

/* WDT_STALL_MS must exceed the longest legitimately-blocking main-loop step
 * that does NOT bump the heartbeat — i.e. the SX126x RX k_poll wait (the LR1110
 * RX/TX poll loops bump continuously). We cap the RX window at RX_WINDOW_MS
 * (< WDT_STALL_MS) so a normal RX never looks like a stall. */
#define WDT_TIMEOUT_MS   4000   /* SoC reset if not fed for this long */
#define WDT_STALL_MS     4000   /* feeder withholds the feed after no progress this long */
#define WDT_FEED_MS      500    /* feeder cadence */
#define RX_WINDOW_MS     2000   /* per-iteration RX listen window */

static const struct device *s_wdt;
static int s_wdt_channel = -1;
static atomic_t s_last_progress_ms;

/* Marks forward progress. Strong definition overriding the radio driver's weak
 * stub, so the driver's poll loops bump this heartbeat too. */
void lichen_radio_progress(void)
{
	atomic_set(&s_last_progress_ms, (atomic_val_t)k_uptime_get());
}

/* Runs in system-clock ISR context — feed only while progress is fresh. */
static void wdt_feed_timer_fn(struct k_timer *t)
{
	ARG_UNUSED(t);
	int64_t age = k_uptime_get() - (int64_t)atomic_get(&s_last_progress_ms);

	if (s_wdt && age < WDT_STALL_MS) {
		wdt_feed(s_wdt, s_wdt_channel);
	}
	/* else: no forward progress → withhold feed → SoC resets */
}

static K_TIMER_DEFINE(s_wdt_timer, wdt_feed_timer_fn, NULL);

static void wdt_init(void)
{
	lichen_radio_progress(); /* seed a fresh heartbeat before arming */

	s_wdt = DEVICE_DT_GET(DT_ALIAS(watchdog0));
	if (!device_is_ready(s_wdt)) {
		LOG_WRN("watchdog not ready — running without it");
		s_wdt = NULL;
		return;
	}

	struct wdt_timeout_cfg cfg = {
		.flags   = WDT_FLAG_RESET_SOC,
		.window  = { .min = 0, .max = WDT_TIMEOUT_MS },
		.callback = NULL,
	};

	s_wdt_channel = wdt_install_timeout(s_wdt, &cfg);
	if (s_wdt_channel < 0) {
		LOG_WRN("wdt_install_timeout failed: %d", s_wdt_channel);
		s_wdt = NULL;
		return;
	}

	if (wdt_setup(s_wdt, WDT_OPT_PAUSE_HALTED_BY_DBG) < 0) {
		LOG_WRN("wdt_setup failed");
		s_wdt = NULL;
		return;
	}

	k_timer_start(&s_wdt_timer, K_MSEC(WDT_FEED_MS), K_MSEC(WDT_FEED_MS));
	LOG_INF("watchdog armed (%d ms, stall %d ms, timer-fed)",
		WDT_TIMEOUT_MS, WDT_STALL_MS);
}

static inline void wdt_kick(void)
{
	lichen_radio_progress();
}

/* --------------------------------------------------------------------------
 * Stall marker — retained across a warm (watchdog) reset
 *
 * The heartbeat watchdog resets the SoC when main stalls, but the deferred log
 * that would say *where* is lost in the reset. set_phase() records the current
 * main-loop phase in a .noinit variable (RAM survives a watchdog reset on
 * nRF52); stall_report() prints it on the next boot. (Types/setter are defined
 * earlier, before send_beacon, since it uses them.)
 * -------------------------------------------------------------------------- */

static void stall_report(void)
{
#if defined(STALL_MARKER_HAVE)
	static const char *const names[PH_NPHASES] = {
		"boot", "recv", "rx_forward", "cfg_tx",
		"tx", "cfg_rx", "node_info",
	};
	uint32_t g  = NRF_POWER->GPREGRET2;
	uint32_t rr = NRF_POWER->RESETREAS;

	NRF_POWER->RESETREAS = rr; /* write-1-to-clear so next boot is fresh */

	uint32_t ph = g & 0x0Fu;
	const char *phn = ((g & 0xF0u) == STALL_GPREG_MAGIC) && ph < PH_NPHASES
			  ? names[ph] : "n/a";

	/* RESETREAS: bit1=DOG(watchdog) bit2=SREQ(soft) bit0=pin bit3=lockup */
	LOG_WRN("*** boot: RESETREAS=0x%08x %s GPREGRET2=0x%02x phase=%s ***",
		rr,
		(rr & BIT(1)) ? "WATCHDOG" :
		(rr & BIT(2)) ? "soft" :
		(rr & BIT(3)) ? "LOCKUP" :
		(rr & BIT(0)) ? "pin" : "poweron/other",
		g, phn);
	set_phase(PH_BOOT);
#endif
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(void)
{
	const struct device *lora_dev;
	struct lichen_hal_identity identity;
	int ret;

	LOG_INF("LICHEN puck starting");
	stall_report();

	/* Enable USB early so CDC-ACM enumerates before peripheral drivers
	 * start — guarantees serial log visibility even if LoRa/GNSS fails. */
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
	usb_enable(NULL);
	k_sleep(K_MSEC(200));
#endif

	lichen_hal_identity_get(&identity);

	/* LoRa radio (via the board-capability HAL) */
	ret = lichen_hal_lora_device_get(&lora_dev);
	if (ret < 0) {
		LOG_ERR("LoRa radio unavailable: %d", ret);
		return ret;
	}
	if (lora_set_mode(lora_dev, false) < 0) {
		LOG_ERR("LoRa config failed — spinning for serial debug");
		k_sleep(K_FOREVER);
	}
	LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);

	/* GNSS power-on (PM_DEVICE start) */
#if IS_ENABLED(CONFIG_LICHEN_HAS_GNSS)
	const struct device *gnss_dev;

	if (lichen_hal_gnss_device_get(&gnss_dev) == 0) {
		pm_device_action_run(gnss_dev, PM_DEVICE_ACTION_RESUME);
	}
#endif

	/* LICHEN Native over USB CDC-ACM */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
	if (lichen_native_init(on_native_rx) == 0) {
		LOG_INF("LICHEN Native ready");
		lichen_native_send_hello();
	}
#endif

	/* Arm the watchdog just before entering the loop: everything above runs
	 * quickly and deterministically; the loop is where a radio call can
	 * wedge. */
	wdt_init();

	/* Main loop: RX with 5s timeout, beacon every 60s. */
	uint8_t buf[LORA_MAX_FRAME];
	int16_t rssi;
	int8_t  snr;
	int64_t last_tx_ms  = -(int64_t)BEACON_INTERVAL_MS;
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
	int64_t last_info_ms = 0;
#endif

	while (1) {
		wdt_kick();

		set_phase(PH_RECV);
		int len = lora_recv(lora_dev, buf, sizeof(buf),
				    K_MSEC(RX_WINDOW_MS), &rssi, &snr);

		if (len > 0) {
			LOG_INF("RX %d B rssi=%d snr=%d [%02x %02x]",
				len, rssi, snr,
				buf[0], len > 1 ? buf[1] : 0u);
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
			s_radio_stats.rx_pkts++;
			/* Forward to connected host.
			 * src_iid is unknown at this layer — send zeros. */
			static const uint8_t unknown_iid[8];
			set_phase(PH_RX_FORWARD);
			lichen_native_send_message_received(unknown_iid,
							    buf, len,
							    rssi, snr);
#endif
		}

		int64_t now = k_uptime_get();

		if (now - last_tx_ms >= BEACON_INTERVAL_MS) {
			send_beacon(lora_dev);
			last_tx_ms = now;
		}

		/* Send node_info every 60s */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
		if (now - last_info_ms >= 60000) {
			set_phase(PH_NODE_INFO);
			lichen_native_send_node_info(
				identity.board_name,
				"lichen-fw-0.1.0",
				identity.zephyr_board,
				(uint64_t)now,
				s_iid,
				s_gps.valid ? &s_gps : NULL,
				&s_radio_stats);
			last_info_ms = now;
		}
#endif
	}
}
