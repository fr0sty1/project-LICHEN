<<<<<<< HEAD
#define DT_DRV_COMPAT lilygo_tdeck_keyboard

=======
>>>>>>> origin/integration/worker3-20260722
#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/input/input.h>
#include <zephyr/kernel.h>
<<<<<<< HEAD
#include <zephyr/sys/util.h>

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
	k_thread_create(&((struct lilygo_tdeck_keyboard_data *)dev->data)->thread, lilygo_tdeck_keyboard_stack, K_KERNEL_STACK_SIZEOF(lilygo_tdeck_keyboard_stack), lilygo_tdeck_keyboard_thread, (void *)dev, NULL, NULL, 6, 0, K_NO_WAIT);
	return 0;
}

static const struct lilygo_tdeck_keyboard_config lilygo_tdeck_keyboard_config = {
	.i2c = I2C_DT_SPEC_INST_GET(0),
};

static struct lilygo_tdeck_keyboard_data lilygo_tdeck_keyboard_data;

=======
#define DT_DRV_COMPAT lilygo_tdeck_keyboard
struct lilygo_tdeck_keyboard_config { struct i2c_dt_spec bus; };
struct lilygo_tdeck_keyboard_data { const struct device *dev; struct k_thread thread; uint8_t stack[512]; };
static const uint16_t tdeck_keymap[] = {0, INPUT_KEY_ENTER, INPUT_KEY_UP, INPUT_KEY_DOWN, INPUT_KEY_LEFT, INPUT_KEY_RIGHT, INPUT_KEY_0, INPUT_KEY_1, INPUT_KEY_2, INPUT_KEY_3, INPUT_KEY_4, INPUT_KEY_5, INPUT_KEY_6, INPUT_KEY_7, INPUT_KEY_8, INPUT_KEY_9};
static void lilygo_tdeck_poll(void *a, void *b, void *c) { const struct device *dev = a; const struct lilygo_tdeck_keyboard_config *cfg = dev->config; uint8_t buf; while (1) { k_msleep(50); if (i2c_reg_read_byte_dt(&cfg->bus, 0x03, &buf) == 0 && buf < sizeof(tdeck_keymap)/sizeof(*tdeck_keymap)) { uint16_t k = tdeck_keymap[buf]; if (k) { input_report_key(dev, k, 1); input_sync(dev); input_report_key(dev, k, 0); input_sync(dev); } } } }
static int lilygo_tdeck_keyboard_init(const struct device *dev) { const struct lilygo_tdeck_keyboard_config *cfg = dev->config; struct lilygo_tdeck_keyboard_data *data = dev->data; if (!device_is_ready(cfg->bus.bus)) return -ENODEV; i2c_reg_write_byte_dt(&cfg->bus, 0x01, 0xFF); data->dev = dev; k_thread_create(&data->thread, data->stack, sizeof(data->stack), lilygo_tdeck_poll, (void *)dev, NULL, NULL, 5, 0, K_NO_WAIT); return 0; }
static const struct lilygo_tdeck_keyboard_config lilygo_tdeck_keyboard_config = { .bus = I2C_DT_SPEC_GET(DT_NODELABEL(keyboard0)) };
static struct lilygo_tdeck_keyboard_data lilygo_tdeck_keyboard_data;
>>>>>>> origin/integration/worker3-20260722
DEVICE_DT_INST_DEFINE(0, lilygo_tdeck_keyboard_init, NULL, &lilygo_tdeck_keyboard_data, &lilygo_tdeck_keyboard_config, POST_KERNEL, CONFIG_INPUT_INIT_PRIORITY, NULL);
