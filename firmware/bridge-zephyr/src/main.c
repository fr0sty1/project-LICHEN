/*
 * LICHEN LoRa Bridge - Zephyr version
 * IPv6 mesh networking over LoRa.
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

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* LED (optional - not all boards have one) */
#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAS_LED 1
static bool led_configured;
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

    LOG_INF("RX: %zu bytes, RSSI=%d dBm, SNR=%d dB", len, rssi, snr);

    /*
     * Future: Parse LICHEN frame, verify signature, check replay,
     * decompress SCHC, inject into IPv6 stack.
     */
}
#endif

int main(void)
{
    int ret = 0;

    LOG_INF("LICHEN bridge (Zephyr) starting...");

#if defined(HAS_LED)
    if (gpio_is_ready_dt(&led)) {
        ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
        if (ret < 0) {
            LOG_ERR("Failed to configure LED GPIO: %d", ret);
        } else {
            led_configured = true;
            gpio_pin_set_dt(&led, 1);
        }
    }
#endif

#if defined(CONFIG_USB_DEVICE_STACK)
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable failed: %d", ret);
    } else {
        k_sleep(K_MSEC(1000));
        LOG_INF("USB CDC ready");
    }
#else
    LOG_INF("UART console ready");
#endif

/*
 * Standalone LoRa initialization (no Zephyr net_if).
 * When CONFIG_LICHEN_L2 is enabled, NET_DEVICE_INIT handles init via
 * lichen_l2_iface_init() - we skip this block to avoid double-init.
 */
#if defined(CONFIG_LICHEN_LORA_L2) && !defined(CONFIG_LICHEN_L2)
    {
        bool init_ok = false;

        ret = lichen_lora_l2_init();
        if (ret < 0) {
            LOG_ERR("LoRa L2 init failed: %d", ret);
        } else {
            /* Set up RX callback */
            lichen_lora_l2_set_rx_callback(lora_rx_handler, NULL);

            /* Start LoRa L2 */
            ret = lichen_lora_l2_start();
            if (ret < 0) {
                LOG_ERR("LoRa L2 start failed: %d", ret);
            } else {
                /* Log our link-layer address */
                const uint8_t *eui64 = lichen_lora_l2_get_eui64();
                if (eui64 == NULL) {
                    LOG_ERR("Failed to get EUI-64 address");
                } else {
                    LOG_INF("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                            eui64[0], eui64[1], eui64[2], eui64[3],
                            eui64[4], eui64[5], eui64[6], eui64[7]);

#if defined(CONFIG_LICHEN_IPV6)
                    /* Derive and log link-local address */
                    ret = lichen_log_link_local_from_eui64(eui64, NULL);
                    if (ret == 0) {
                        init_ok = true;
                    }
#else
                    init_ok = true;
#endif
                }
            }
        }

        /* Turn off busy LED */
#if defined(HAS_LED)
        if (led_configured) {
            gpio_pin_set_dt(&led, 0);
        }
#endif

        if (init_ok) {
            LOG_INF("LoRa L2 active: SF10, BW125, 915MHz");
        }
    }
#else
    /* Non-LoRa build: turn off LED */
#if defined(HAS_LED)
    if (led_configured) {
        gpio_pin_set_dt(&led, 0);
    }
#endif
#endif /* CONFIG_LICHEN_LORA_L2 && !CONFIG_LICHEN_L2 */

    LOG_INF("Ready - LICHEN IPv6/LoRa mesh");

    while (1) {
        k_sleep(K_SECONDS(60));
        LOG_DBG("tick");
    }
}
