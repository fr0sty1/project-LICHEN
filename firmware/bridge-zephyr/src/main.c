/*
 * LICHEN LoRa Bridge - Zephyr version
 * IPv6 mesh networking over LoRa.
 *
 * LED diagnostic patterns (led0 alias, if present):
 * - Solid on during init: normal startup in progress
 * - 3 rapid blinks (100ms on/off): USB CDC initialization failed
 * - Continuous 200ms blink (forever): standalone LoRa init failed
 * - Off after init: ready, normal operation
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

#if defined(CONFIG_LICHEN_LORA_L2)
#include "lora_l2.h"
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

/*
 * Standalone LoRa mode: CONFIG_LICHEN_LORA_L2 without CONFIG_LICHEN_L2.
 *
 * When CONFIG_LICHEN_L2 is enabled, the Zephyr L2 integration handles all
 * initialization via NET_DEVICE_INIT's callback (lichen_l2_iface_init).
 * That path sets up the LoRa driver, RX callback, and link context.
 *
 * When CONFIG_LICHEN_L2 is NOT enabled (standalone mode), main() handles
 * initialization directly. This is for testing/debugging without the full
 * IPv6 stack, or on boards that don't support Zephyr networking.
 */
#if defined(CONFIG_LICHEN_LORA_L2) && !defined(CONFIG_LICHEN_L2)
/**
 * @brief Handle received LoRa packets (standalone mode only)
 */
static void lora_rx_handler(const uint8_t *data, size_t len,
                            int16_t rssi, int8_t snr, void *user_data)
{
    ARG_UNUSED(user_data);
    ARG_UNUSED(data);

    // ponytail: RX processing not implemented - add when needed
    LOG_INF("main: RX %zu bytes standalone (RSSI %d dBm, SNR %d dB)", len, rssi, snr);
}

/**
 * @brief Initialize standalone LoRa L2 (no Zephyr net_if)
 *
 * @return 0 on success, negative errno on failure
 */
static int init_standalone_lora(void)
{
    int ret;
    const uint8_t *eui64;

    ret = lichen_lora_l2_init();
    if (ret < 0) {
        LOG_ERR("main: LoRa L2 init failed (%d)", ret);
        return ret;
    }

    lichen_lora_l2_set_rx_callback(lora_rx_handler, NULL);

    ret = lichen_lora_l2_start();
    if (ret < 0) {
        LOG_ERR("main: LoRa L2 start failed (%d)", ret);
        return ret;
    }

    eui64 = lichen_lora_l2_get_eui64();
    if (eui64 == NULL) {
        LOG_ERR("main: failed to get EUI-64");
        goto cleanup;
    }

    LOG_INF("main: EUI-64 %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

#if defined(CONFIG_LICHEN_IPV6)
    ret = lichen_log_link_local_from_eui64(eui64, NULL);
    if (ret < 0) {
        goto cleanup;
    }
#endif

    LOG_INF("main: LoRa L2 active (SF10 BW125 915 MHz)");
    return 0;

cleanup:
    lichen_lora_l2_stop();
    lichen_lora_l2_deinit();
    return (ret < 0) ? ret : -ENODATA;
}
#endif

int main(void)
{
    int ret = 0;

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
 * Standalone LoRa initialization (no Zephyr net_if).
 * When CONFIG_LICHEN_L2 is enabled, NET_DEVICE_INIT handles init via
 * lichen_l2_iface_init() - we skip this block to avoid double-init.
 */
#if defined(CONFIG_LICHEN_LORA_L2) && !defined(CONFIG_LICHEN_L2)
    ret = init_standalone_lora();
    if (ret < 0) {
        LOG_ERR("main: standalone LoRa init failed (%d)", ret);
        LOG_ERR("main: fatal, entering error state");
#if defined(HAS_LED)
        /*
         * LED pattern: continuous 200ms blink forever = fatal LoRa failure.
         * Distinct from USB failure which is 3 rapid 100ms blinks then stops.
         */
        while (1) {
            led_set(1);
            k_sleep(K_MSEC(200));
            led_set(0);
            k_sleep(K_MSEC(200));
        }
#else
        /* No LED: sleep forever to avoid spinning */
        while (1) {
            k_sleep(K_SECONDS(60));
        }
#endif
    }
#endif

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
