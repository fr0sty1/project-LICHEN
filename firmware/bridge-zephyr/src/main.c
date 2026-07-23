/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * LICHEN LoRa Bridge - Zephyr version
 * IPv6 mesh networking over LoRa.
 *
 * LED diagnostic patterns (led0 alias, if present):
 * - Solid on during init: normal startup in progress
 * - 3 rapid blinks (100ms on/off): USB CDC initialization failed
 * - Continuous 200ms blink (forever): network/L2 init failed
 * - Off after init: ready, normal operation
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

#if defined(CONFIG_LICHEN_IPV6)
#include "ipv6_addr.h"
#endif

#include "crash_info.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* LED (optional - not all boards have one) */
#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAS_LED 1
static bool led_configured;

/**
 * @brief Set LED state with error logging
 *
 * Wrapper around gpio_pin_set_dt that logs errors. Since LED is non-critical,
 * we log but don't propagate errors.
 */
static inline void led_set(int value)
{
    /* No-op if led_configured is false (GPIO init failed) */
    if (led_configured) {
        int ret = gpio_pin_set_dt(&led, value);
        if (ret < 0) {
            LOG_ERR("main: LED gpio_pin_set_dt failed (%d)", ret);
        }
    }
}
#endif

#if defined(CONFIG_LICHEN_LORA_L2) && !defined(CONFIG_LICHEN_L2)
#error "CONFIG_LICHEN_LORA_L2 without CONFIG_LICHEN_L2 is disabled: enable full LICHEN_L2 networking so LoRa RX is framed, decompressed, and injected into IPv6"
#endif

int main(void)
{
#if defined(HAS_LED) || defined(CONFIG_USB_DEVICE_STACK)
    int ret = 0;
#endif

    LOG_INF("main: starting");
    crash_info_check_and_clear();

#if defined(HAS_LED)
    /* LED pattern: solid on during init = startup in progress */
    if (gpio_is_ready_dt(&led)) {
        ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
        if (ret < 0) {
            LOG_ERR("main: LED GPIO configure failed (%d)", ret);
        } else {
            led_configured = true;
            led_set(1);
        }
    }
#endif

#if defined(CONFIG_USB_DEVICE_STACK)
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("main: USB enable failed (%d)", ret);
        /*
         * USB CDC failure means console output may not be visible.
         * Provide visual feedback via LED if available.
         *
         * Note: We continue startup despite USB failure. Console output may
         * go to UART instead (if available), and LoRa functionality can still
         * operate. The LED pattern provides visual indication of the failure.
         *
         * LED pattern: 3 rapid blinks (100ms) then off = non-fatal USB failure.
         * Distinct from fatal LoRa failure which is continuous 200ms blink.
         */
#if defined(HAS_LED)
        for (int i = 0; i < 3; i++) {
            led_set(1);
            k_sleep(K_MSEC(100));
            led_set(0);
            k_sleep(K_MSEC(100));
        }
#endif
        /* Turn LED off after error indication */
#if defined(HAS_LED)
        led_set(0);
#endif
    } else {
        k_sleep(K_MSEC(1000));
        LOG_INF("main: USB CDC ready");
    }
#else
    LOG_INF("main: UART console ready");
#endif

    /*
     * LICHEN_L2 initializes through NET_DEVICE_INIT. The old standalone
     * LICHEN_LORA_L2 path was removed because it accepted RX callbacks but
     * never parsed frames or injected IPv6 packets.
     */

#if defined(HAS_LED)
    /* LED pattern: off after init = ready, normal operation */
    led_set(0);
#endif

    LOG_INF("main: ready");

    while (1) {
        k_sleep(K_SECONDS(60));
        LOG_DBG("main: tick");
    }
}
