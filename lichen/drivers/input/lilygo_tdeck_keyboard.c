/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/input/input.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#define DT_DRV_COMPAT lilygo_tdeck_keyboard

struct lilygo_tdeck_keyboard_config {
	struct i2c_dt_spec i2c;
};

struct lilygo_tdeck_keyboard_data {
	struct k_thread thread;
};

K_KERNEL_STACK_DEFINE(lilygo_tdeck_keyboard_stack, 1024);

static void lilygo_tdeck_keyboard_poll(const struct device *dev) {
	const struct lilygo_tdeck_keyboard_config *config = dev->config;
	uint8_t buf[8] = {0};
	if (i2c_burst_read_dt(&config->i2c, 0x03, buf, 8) == 0) {
		uint8_t keys = buf[0];
		input_report_key(dev, INPUT_KEY_UP, !!(keys & BIT(0)));
		input_report_key(dev, INPUT_KEY_DOWN, !!(keys & BIT(1)));
		input_report_key(dev, INPUT_KEY_LEFT, !!(keys & BIT(2)));
		input_report_key(dev, INPUT_KEY_RIGHT, !!(keys & BIT(3)));
		input_report_key(dev, INPUT_KEY_ENTER, !!(keys & BIT(4)));
		input_report_key(dev, INPUT_KEY_BACK, !!(keys & BIT(5)));
		input_report_key(dev, INPUT_KEY_0, !!(keys & BIT(6)));
		input_report_key(dev, INPUT_KEY_1, !!(keys & BIT(7)));
		int8_t dx = buf[1];
		int8_t dy = buf[2];
		if (dx) input_report_rel(dev, INPUT_REL_X, dx);
		if (dy) input_report_rel(dev, INPUT_REL_Y, dy);
		if (buf[3] & 0x1) {
			input_report_key(dev, INPUT_BTN_MOUSE, 1);
			input_report_key(dev, INPUT_BTN_MOUSE, 0);
		}
		input_sync(dev);
	}
}

static void lilygo_tdeck_keyboard_thread(void *p1, void *p2, void *p3) {
	const struct device *dev = p1;
	while (true) {
		lilygo_tdeck_keyboard_poll(dev);
		k_msleep(20);
	}
}

static int lilygo_tdeck_keyboard_init(const struct device *dev) {
	const struct lilygo_tdeck_keyboard_config *config = dev->config;
	if (!device_is_ready(config->i2c.bus)) {
		return -ENODEV;
	}
	i2c_reg_write_byte_dt(&config->i2c, 0x01, 0xFF);
	k_thread_create(&((struct lilygo_tdeck_keyboard_data *)dev->data)->thread, lilygo_tdeck_keyboard_stack, K_KERNEL_STACK_SIZEOF(lilygo_tdeck_keyboard_stack), lilygo_tdeck_keyboard_thread, (void *)dev, NULL, NULL, 6, 0, K_NO_WAIT);
	return 0;
}

static const struct lilygo_tdeck_keyboard_config lilygo_tdeck_keyboard_config = {
	.i2c = I2C_DT_SPEC_INST_GET(0),
};

static struct lilygo_tdeck_keyboard_data lilygo_tdeck_keyboard_data;

DEVICE_DT_INST_DEFINE(0, lilygo_tdeck_keyboard_init, NULL, &lilygo_tdeck_keyboard_data, &lilygo_tdeck_keyboard_config, POST_KERNEL, CONFIG_INPUT_INIT_PRIORITY, NULL);
