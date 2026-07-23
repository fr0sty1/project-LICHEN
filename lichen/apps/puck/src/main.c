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
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

#include <lichen/hal.h>
#include "../../../subsys/lichen/l2/lichen_util.h"
#include "../../../subsys/lichen/l2/crash_info.h"

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

#include "puck_location.h"

#if IS_ENABLED(CONFIG_LICHEN_L2)
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap_service.h>
#include <lichen/coap_client.h>
#include <lichen/coap_server.h>
#include "lichen_l2.h"
#include "ipv6_addr.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_COAP_LOCATION)
static uint16_t s_coap_server_port = 5683;

/* Puck owns this app service; gateway defines its own service with the same
 * resource section, while standalone builds use lichen_coap_server instead. */
COAP_SERVICE_DEFINE(lichen_coap, NULL, &s_coap_server_port,
		    COAP_SERVICE_AUTOSTART);
#endif

/* Stall-marker uses the nRF GPREGRET2 retention register (nRF boards only). */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#include <nrfx_power.h>
#define STALL_MARKER_HAVE 1
#endif

LOG_MODULE_REGISTER(lichen_puck, LOG_LEVEL_INF);

#if IS_ENABLED(CONFIG_LICHEN_L2) && IS_ENABLED(CONFIG_STATS)
#include <zephyr/stats/stats.h>

/*
 * CoAP round-trip counters, exported over SMP as the "coap" STATS group so
 * the round trip can be confirmed on the console-less T1000-E via if02
 * (qpc0 end-to-end validation): sent GETs vs successful 2.05 responses vs
 * errors/timeouts.
 */
STATS_SECT_START(lichen_coap_stats)
STATS_SECT_ENTRY32(sent)
STATS_SECT_ENTRY32(ok)
STATS_SECT_ENTRY32(err)
STATS_SECT_END;

STATS_NAME_START(lichen_coap_stats)
STATS_NAME(lichen_coap_stats, sent)
STATS_NAME(lichen_coap_stats, ok)
STATS_NAME(lichen_coap_stats, err)
STATS_NAME_END(lichen_coap_stats);

STATS_SECT_DECL(lichen_coap_stats) lichen_coap_stats;
#define COAP_STAT_INC(f) STATS_INC(lichen_coap_stats, f)
#else
#define COAP_STAT_INC(f) do { } while (0)
#endif

/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5 @ 915 MHz (US915). */
#define LORA_FREQ_HZ       915000000U
#define LORA_MAX_FRAME     255
#define BEACON_INTERVAL_MS CONFIG_LICHEN_PUCK_BEACON_INTERVAL_MS

/*
 * Unsigned LICHEN neighbor beacon.
 *   [0] length = 4   (body length; total frame size is 5)
 *   [1] llsec  = 0x00  (AddrMode=0, no signature, no encryption)
 *   [2] epoch  = 0
 *   [3] seqhi  = 0
 *   [4] seqlo  = incremented on each TX
 */
#define BEACON_HDR_LEN 5
#define BEACON_TOTAL_LEN BEACON_HDR_LEN

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
/* Placeholder IID — in production derive from nRF52840 FICR. */
static const uint8_t s_iid[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

/* Radio stats forwarded to native protocol */
static struct ln_radio_stats s_radio_stats;

#endif

/* --------------------------------------------------------------------------
 * GNSS callback (called from GNSS driver context)
 * -------------------------------------------------------------------------- */

#if defined(LICHEN_HAL_GNSS_DEVICE)
#include <zephyr/drivers/gnss.h>

static void on_gnss_data(const struct device *dev, const struct gnss_data *data)
{
	lichen_puck_location_gnss_callback_for_test(dev, data);
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
 * LoRa helpers (raw-radio mode only — under CONFIG_LICHEN_L2 the net
 * interface owns the half-duplex radio and these would fight its RX thread)
 * -------------------------------------------------------------------------- */

#if !IS_ENABLED(CONFIG_LICHEN_L2)
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
#endif /* !CONFIG_LICHEN_L2 */

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

#if !IS_ENABLED(CONFIG_LICHEN_L2)
static void send_beacon(const struct device *dev)
{
	/* Build beacon header. Static state persists across calls. */
	static uint8_t beacon[BEACON_TOTAL_LEN];
	static uint8_t seqnum;
	static uint8_t epoch;

	beacon[0] = BEACON_TOTAL_LEN - 1U;
	beacon[1] = 0x00;  /* LLSec: broadcast, unsigned, plaintext */
	if (++seqnum == 0) {
		epoch++;  /* Increment epoch on seqnum wrap */
	}
	beacon[2] = epoch;   /* epoch */
	beacon[3] = 0x00;      /* seqhi */
	beacon[4] = seqnum;  /* seqlo */

	set_phase(PH_CFG_TX);
	if (lora_set_mode(dev, true) < 0) {
		LOG_ERR("TX config failed");
		return;
	}
	set_phase(PH_TX);
	int ret = lora_send(dev, beacon, sizeof(beacon));
	if (ret < 0) {
		LOG_ERR("beacon TX failed: %d", ret);
	} else {
		LOG_INF("beacon seq=%u", seqnum);
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
		s_radio_stats.tx_pkts++;
#endif
	}
	set_phase(PH_CFG_RX);
	lora_set_mode(dev, false);
}
#endif /* !CONFIG_LICHEN_L2 */

#if IS_ENABLED(CONFIG_LICHEN_L2)
static void on_coap_response(void *user_data, int status, uint8_t code,
			     const uint8_t *payload, size_t payload_len)
{
	ARG_UNUSED(user_data);

	if (status != LICHEN_COAP_OK) {
		LOG_WRN("CoAP response error: %d", status);
		COAP_STAT_INC(err);
		return;
	}
	COAP_STAT_INC(ok);
	LOG_INF("CoAP %u.%02u response, %u B payload",
		code >> 5, code & 0x1F, (unsigned int)payload_len);
	if (payload_len > 0) {
		LOG_HEXDUMP_INF(payload, MIN(payload_len, 64), "payload");
	}
}
#endif /* CONFIG_LICHEN_L2 */

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
#define WDT_PROGRESS_FRESH(now, last) \
	((uint32_t)((uint32_t)(now) - (uint32_t)(last)) < WDT_STALL_MS)

BUILD_ASSERT(WDT_PROGRESS_FRESH(0x00000010U, 0xfffffff0U));
BUILD_ASSERT(WDT_PROGRESS_FRESH(0x00000f8fU, 0xfffffff0U));
BUILD_ASSERT(!WDT_PROGRESS_FRESH(0x00000f90U, 0xfffffff0U));

static const struct device *s_wdt;
static int s_wdt_channel = -1;
static atomic_t s_last_progress_ms;

/* Marks forward progress. Strong definition overriding the radio driver's weak
 * stub, so the driver's poll loops bump this heartbeat too. */
void lichen_radio_progress(void)
{
	atomic_set(&s_last_progress_ms, (atomic_val_t)k_uptime_get_32());
}

/* Runs in system-clock ISR context — feed only while progress is fresh. */
static void wdt_feed_timer_fn(struct k_timer *t)
{
	ARG_UNUSED(t);
	uint32_t now = k_uptime_get_32();
	uint32_t last = (uint32_t)atomic_get(&s_last_progress_ms);

	if (s_wdt && WDT_PROGRESS_FRESH(now, last)) {
		wdt_feed(s_wdt, s_wdt_channel);
	}
	/* else: no forward progress → withhold feed → SoC resets */
}

static K_TIMER_DEFINE(s_wdt_timer, wdt_feed_timer_fn, NULL);

static void wdt_init(void)
{
	lichen_radio_progress(); /* seed a fresh heartbeat before arming */

#if !DT_NODE_HAS_STATUS(DT_ALIAS(watchdog0), okay)
	/* No watchdog on this board (e.g. native_sim) */
	LOG_WRN("no watchdog0 alias — running without watchdog");
	return;
#else
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

	int ret = wdt_setup(s_wdt, WDT_OPT_PAUSE_HALTED_BY_DBG);
	if (ret < 0) {
		LOG_ERR("wdt_setup failed: %d", ret);
		crash_info_store(CRASH_WDT_SETUP_FAILURE, __LINE__, (uint32_t)ret);
		if (!IS_ENABLED(CONFIG_IWDG_STM32)) {
			s_wdt = NULL;
			return;
		}
	}

	k_timer_start(&s_wdt_timer, K_MSEC(WDT_FEED_MS), K_MSEC(WDT_FEED_MS));
	LOG_INF("watchdog armed (%d ms, stall %d ms, timer-fed)",
		WDT_TIMEOUT_MS, WDT_STALL_MS);
#endif /* DT_NODE_HAS_STATUS(DT_ALIAS(watchdog0), okay) */
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
	struct lichen_hal_identity identity;
	int ret;

	LOG_INF("LICHEN puck starting");
	stall_report();

#if IS_ENABLED(CONFIG_LICHEN_L2)
	/* Quiesce the radio before USB bring-up. The L2 RX thread polls the
	 * radio over SPI (EasyDMA) continuously from NET_DEVICE_INIT — on
	 * nRF52840 that traffic during USBD enumeration wedges USB into a
	 * permanent -110 descriptor-read loop (both USB stacks, both radios;
	 * bd lora_ipv6_mesh-r002). Brought back up after USB settles below. */
	struct net_if *l2_iface =
		net_if_get_first_by_type(&NET_L2_GET_NAME(lichen_l2));

	if (l2_iface != NULL) {
		net_if_down(l2_iface);
	}
#endif

	/* Enable USB early so CDC-ACM enumerates before peripheral drivers
	 * start — guarantees serial log visibility even if LoRa/GNSS fails. */
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
	usb_enable(NULL);
	k_sleep(K_MSEC(200));
#endif

	lichen_hal_identity_get(&identity);

#if !IS_ENABLED(CONFIG_LICHEN_L2)
	const struct device *lora_dev;

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
#endif

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

#if IS_ENABLED(CONFIG_LICHEN_L2)
	/* L2/CoAP mode: the LICHEN net interface owns the radio and delivers
	 * IPv6 both ways; the app talks CoAP to the dev-provisioned peer.
	 * The ~230 B /status payload arrives via CoAP Block2 (RFC 7959) —
	 * the gateway slices it into 64-byte blocks that each fit the L2
	 * MTU, and the CoAP client reassembles. */
	static const char *const req_path[] = { "status", NULL };
	uint8_t peer_eui64[LICHEN_L2_ADDR_LEN];
	uint8_t peer_iid[LICHEN_L2_ADDR_LEN];
	struct sockaddr_in6 peer_addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(5683),
	};
	LOG_INF("L2/CoAP mode on %s", identity.board_name);

	if (l2_iface == NULL) {
		LOG_ERR("no LICHEN L2 iface — idling for debug");
		while (1) {
			wdt_kick();
			k_sleep(K_SECONDS(1));
		}
	}

	/* USB settle: the iface (and its radio-polling RX thread) stays down
	 * until enumeration is safely over — see the net_if_down() above. */
	for (int i = 0; i < 10; i++) {
		wdt_kick();
		k_sleep(K_SECONDS(1));
	}
	net_if_up(l2_iface);
	k_sleep(K_MSEC(500));

	/* Provision AFTER net_if_up: the enable path re-initializes the link
	 * context, which would wipe an earlier-loaded key. */
#if IS_ENABLED(CONFIG_LICHEN_L2_DEV_PROVISIONING)
	ret = -EAGAIN;
	for (int i = 0; i < 50 && ret == -EAGAIN; i++) {
		ret = lichen_l2_dev_provision(peer_eui64);
		if (ret == -EAGAIN) {
			wdt_kick();
			k_sleep(K_MSEC(100));
		}
	}
#else
	/* No provisioning path yet besides the dev one: without a signing key
	 * and a peer, nothing can authenticate. Stay up (USB/native alive)
	 * but radio-idle. */
	ret = -ENOTSUP;
#endif
	if (ret != 0) {
		LOG_ERR("L2 provisioning unavailable (%d) — idling", ret);
		while (1) {
			wdt_kick();
			k_sleep(K_SECONDS(1));
		}
	}

	/* Publish self identity (the "identity canary") so /config/identity,
	 * MeshCore, and logs confirm successful L2 key + app identity setup.
	 * Fixes missing canary in nRF/ESP puck L2 startup. */
	ret = lichen_l2_publish_app_identity("puck", identity.board_name);
	if (ret < 0) {
		LOG_WRN("app identity publish failed (%d)", ret);
	} else {
		LOG_INF("OK: local node identity at startup");
	}

	lichen_eui64_to_iid(peer_eui64, peer_iid);
	lichen_make_link_local(peer_iid,
			       (struct in6_addr *)&peer_addr.sin6_addr);
	peer_addr.sin6_scope_id = net_if_get_by_iface(l2_iface);

	ret = lichen_coap_client_init();
	if (ret != 0) {
		LOG_ERR("CoAP client init failed: %d", ret);
	}

	ret = lichen_coap_server_init(NULL);
	if (ret != 0) {
		LOG_ERR("CoAP server init failed: %d", ret);
	}

#if IS_ENABLED(CONFIG_STATS)
	(void)STATS_INIT_AND_REG(lichen_coap_stats, STATS_SIZE_32, "coap");
#endif

	while (1) {
		set_phase(PH_TX);
		ret = lichen_coap_get(&peer_addr, req_path,
				      on_coap_response, NULL);
		if (ret != 0) {
			LOG_WRN("CoAP GET send failed: %d", ret);
		} else {
			COAP_STAT_INC(sent);
			LOG_INF("CoAP GET /status sent");
		}
		set_phase(PH_RECV);
		for (int i = 0; i < 15; i++) {
			wdt_kick();
			k_sleep(K_SECONDS(1));
		}
	}
#else /* !CONFIG_LICHEN_L2 — raw-radio beacon mode */
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
			static uint32_t rx_count = 0;
			rx_count++;
			LOG_INF("RX %d B rssi=%d snr=%d pkt#%u [%02x %02x]",
				len, rssi, snr, rx_count,
				buf[0], len > 1 ? buf[1] : 0u);
			LOG_HEXDUMP_DBG(buf, MIN(len, 32), "RX payload");
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
			struct lichen_hal_location_time_snapshot location_time;
			struct ln_gps_info gps;
			const struct ln_gps_info *gps_ptr = NULL;

			set_phase(PH_NODE_INFO);
			if (lichen_hal_location_time_snapshot_get(&location_time) == 0 &&
			    lichen_puck_location_snapshot_to_native_gps(&location_time,
								       &gps)) {
				gps_ptr = &gps;
			}
			lichen_native_send_node_info(
				identity.board_name,
				"lichen-fw-0.1.0",
				identity.zephyr_board,
				(uint64_t)now,
				s_iid,
				gps_ptr,
				&s_radio_stats);
			last_info_ms = now;
		}
#endif
	}
#endif /* CONFIG_LICHEN_L2 */
}
