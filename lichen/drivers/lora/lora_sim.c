/*
 * LICHEN simulator LoRa driver for Zephyr native_sim.
 *
 * Connects to the Python/Rust lichen-sim server over TCP and implements the
 * Zephyr LoRa API on top of the simulator wire protocol.
 *
 * Wire protocol (all integers little-endian, 4-byte length-prefixed frames):
 *   REGISTER 0x01: [1B sim_id_len][sim_id][1B node_id_len][node_id][24B xyz]
 *   OK       0x00
 *   TX       0x10: [2B payload_len][payload]
 *   TX_DONE  0x11: [4B airtime_us]
 *   TX_FAIL  0x12
 *   RX       0x20: [4B timeout_ms]
 *   RX_OK    0x21: [2B payload_len][payload][2B rssi_s16][2B snr_s16]
 *   RX_TIMEOUT 0x22
 *   ERR      0xFF: [1B code][1B msg_len][msg]
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lora_sim, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_sim

/* Message type bytes */
#define MSG_OK         0x00
#define MSG_REGISTER   0x01
#define MSG_TX         0x10
#define MSG_TX_DONE    0x11
#define MSG_TX_FAIL    0x12
#define MSG_RX         0x20
#define MSG_RX_OK      0x21
#define MSG_RX_TIMEOUT 0x22
#define MSG_ERR        0xFF

/* Maximum receive buffer for a single frame (256-byte LoRa payload + headers) */
#define RX_BUF_MAX 320

/* Socket timeout in milliseconds - prevents indefinite blocking on disconnected simulator */
#define SOCKET_TIMEOUT_MS 5000

struct lora_sim_data {
	int fd;
};

/* --- framing ------------------------------------------------------------ */

static int send_exact(int fd, const uint8_t *buf, int len)
{
	while (len > 0) {
		int n = zsock_send(fd, buf, len, 0);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				LOG_ERR("send timeout - simulator may be disconnected");
				return -ETIMEDOUT;
			}
			LOG_ERR("send error: %d", errno);
			return -EIO;
		}
		if (n == 0) {
			LOG_ERR("send: connection closed by simulator");
			return -ECONNRESET;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

static int recv_exact(int fd, uint8_t *buf, int len)
{
	while (len > 0) {
		int n = zsock_recv(fd, buf, len, MSG_WAITALL);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				LOG_ERR("recv timeout - simulator may be disconnected");
				return -ETIMEDOUT;
			}
			LOG_ERR("recv error: %d", errno);
			return -EIO;
		}
		if (n == 0) {
			LOG_ERR("recv: connection closed by simulator");
			return -ECONNRESET;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

static int drain_exact(int fd, uint32_t len)
{
	uint8_t discard[64];

	while (len > 0) {
		int chunk = len > sizeof(discard) ? sizeof(discard) : (int)len;

		if (recv_exact(fd, discard, chunk) < 0) {
			return -EIO;
		}
		len -= chunk;
	}
	return 0;
}

static int write_frame(int fd, const uint8_t *payload, uint32_t len)
{
	uint8_t hdr[4];

	sys_put_le32(len, hdr);
	if (send_exact(fd, hdr, 4) < 0) {
		return -EIO;
	}
	return send_exact(fd, payload, len);
}

/* Read length-prefix, return number of bytes placed into buf. */
static int read_frame(int fd, uint8_t *buf, uint32_t buf_size)
{
	uint8_t hdr[4];

	if (recv_exact(fd, hdr, 4) < 0) {
		return -EIO;
	}
	uint32_t len = sys_get_le32(hdr);

	if (len > buf_size) {
		LOG_ERR("frame too large: %u > %u", len, buf_size);
		if (drain_exact(fd, len) < 0) {
			LOG_ERR("failed to drain oversized frame");
			return -EIO;
		}
		return -ENOMEM;
	}
	if (recv_exact(fd, buf, len) < 0) {
		return -EIO;
	}
	return (int)len;
}

/* --- init: connect + REGISTER ------------------------------------------ */

static int lora_sim_connect(struct lora_sim_data *data)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port   = htons(CONFIG_LORA_LICHEN_SIM_PORT),
	};
	struct zsock_timeval tv = {
		.tv_sec  = SOCKET_TIMEOUT_MS / 1000,
		.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000,
	};

	zsock_inet_pton(AF_INET, CONFIG_LORA_LICHEN_SIM_HOST, &addr.sin_addr);

	data->fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (data->fd < 0) {
		LOG_ERR("socket() failed: %d", errno);
		return -errno;
	}

	/* Set socket timeouts to prevent indefinite blocking on disconnected simulator.
	 * This is critical for Zephyr cooperative threads where blocking forever
	 * freezes the entire system.
	 */
	if (zsock_setsockopt(data->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		LOG_WRN("setsockopt(SO_RCVTIMEO) failed: %d", errno);
	}
	if (zsock_setsockopt(data->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		LOG_WRN("setsockopt(SO_SNDTIMEO) failed: %d", errno);
	}

	if (zsock_connect(data->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_ERR("connect() to %s:%d failed: %d",
			CONFIG_LORA_LICHEN_SIM_HOST,
			CONFIG_LORA_LICHEN_SIM_PORT, errno);
		zsock_close(data->fd);
		data->fd = -1;
		return -errno;
	}
	LOG_INF("connected to simulator at %s:%d",
		CONFIG_LORA_LICHEN_SIM_HOST, CONFIG_LORA_LICHEN_SIM_PORT);
	return 0;
}

static int lora_sim_register(struct lora_sim_data *data)
{
	static const char sim_id[]  = CONFIG_LORA_LICHEN_SIM_SIM_ID;
	static const char node_id[] = CONFIG_LORA_LICHEN_SIM_NODE_ID;
	uint8_t buf[256];
	int off = 0;
	size_t sim_id_len = strlen(sim_id);
	size_t node_id_len = strlen(node_id);

	/* Validate string lengths fit in uint8_t and total message fits in buffer.
	 * Message format: 1B type + 1B sim_id_len + sim_id + 1B node_id_len + node_id + 24B xyz
	 * Maximum usable space for strings: 256 - 1 - 1 - 1 - 24 = 229 bytes
	 */
	if (sim_id_len > 255 || node_id_len > 255) {
		LOG_ERR("sim_id or node_id exceeds 255 bytes");
		return -EINVAL;
	}
	if (1 + 1 + sim_id_len + 1 + node_id_len + 24 > sizeof(buf)) {
		LOG_ERR("REGISTER message too large: sim_id=%zu + node_id=%zu exceeds buffer",
			sim_id_len, node_id_len);
		return -EMSGSIZE;
	}

	buf[off++] = MSG_REGISTER;
	buf[off++] = (uint8_t)sim_id_len;
	memcpy(buf + off, sim_id, sim_id_len);
	off += sim_id_len;
	buf[off++] = (uint8_t)node_id_len;
	memcpy(buf + off, node_id, node_id_len);
	off += node_id_len;
	/* Position: (0.0, 0.0, 0.0) as three IEEE 754 doubles, little-endian */
	memset(buf + off, 0, 24);
	off += 24;

	if (write_frame(data->fd, buf, off) < 0) {
		return -EIO;
	}

	uint8_t resp[64];
	int n = read_frame(data->fd, resp, sizeof(resp));

	if (n < 1) {
		return -EIO;
	}
	if (resp[0] != MSG_OK) {
		LOG_ERR("REGISTER rejected (type=0x%02x)", resp[0]);
		return -EPROTO;
	}
	LOG_INF("registered as node_id=\"%s\"", node_id);
	return 0;
}

/* --- LoRa API callbacks ------------------------------------------------- */

static int lora_sim_config(const struct device *dev,
			   struct lora_modem_config *config)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(config);
	/* Simulator ignores RF config; the medium model controls propagation. */
	return 0;
}

static int lora_sim_send(const struct device *dev,
			 uint8_t *data, uint32_t data_len)
{
	if (dev == NULL || data == NULL) {
		return -EINVAL;
	}
	struct lora_sim_data *drv = dev->data;

	if (drv->fd <= 0) {
		LOG_ERR("send: not connected to simulator");
		return -ENOTCONN;
	}
	uint8_t buf[256 + 3];
	int off = 0;

	if (data_len > 255) {
		return -EMSGSIZE;
	}
	buf[off++] = MSG_TX;
	sys_put_le16((uint16_t)data_len, buf + off);
	off += 2;
	memcpy(buf + off, data, data_len);
	off += data_len;

	if (write_frame(drv->fd, buf, off) < 0) {
		return -EIO;
	}

	uint8_t resp[8];
	int n = read_frame(drv->fd, resp, sizeof(resp));

	if (n < 1) {
		return -EIO;
	}
	if (resp[0] == MSG_TX_DONE) {
		return 0;
	}
	if (resp[0] == MSG_TX_FAIL) {
		return -EIO;
	}
	LOG_ERR("unexpected TX response: 0x%02x", resp[0]);
	return -EPROTO;
}

static int lora_sim_recv(const struct device *dev,
			 uint8_t *data, uint8_t size,
			 k_timeout_t timeout,
			 int16_t *rssi, int8_t *snr)
{
	struct lora_sim_data *drv = dev->data;

	if (drv->fd <= 0) {
		LOG_ERR("recv: not connected to simulator");
		return -ENOTCONN;
	}

	/* K_FOREVER sends 0xFFFFFFFF as the explicit "wait forever" marker.
	 * The server interprets this as infinite timeout.
	 */
	bool forever = K_TIMEOUT_EQ(timeout, K_FOREVER);
	uint32_t timeout_ms = forever ? UINT32_MAX : k_ticks_to_ms_floor32(timeout.ticks);
	uint8_t req[5];

	req[0] = MSG_RX;
	sys_put_le32(timeout_ms, req + 1);

	if (write_frame(drv->fd, req, sizeof(req)) < 0) {
		return -EIO;
	}

	uint8_t buf[RX_BUF_MAX];
	int n = read_frame(drv->fd, buf, sizeof(buf));

	if (n < 1) {
		return -EIO;
	}
	if (buf[0] == MSG_RX_TIMEOUT) {
		return -EAGAIN;
	}
	if (buf[0] != MSG_RX_OK) {
		LOG_ERR("unexpected RX response: 0x%02x", buf[0]);
		return -EPROTO;
	}
	if (n < 5) {
		return -EPROTO;
	}
	uint16_t payload_len = sys_get_le16(buf + 1);

	if (n < (int)(3 + payload_len + 4)) {
		return -EPROTO;
	}
	if (payload_len > size) {
		LOG_ERR("recv: packet too large for buffer: %u > %u", payload_len, size);
		return -EMSGSIZE;
	}

	memcpy(data, buf + 3, payload_len);

	if (rssi) {
		*rssi = (int16_t)sys_get_le16(buf + 3 + payload_len);
	}
	if (snr) {
		*snr = (int8_t)((int16_t)sys_get_le16(buf + 3 + payload_len + 2) / 10);
	}
	return payload_len;
}

/* --- device init -------------------------------------------------------- */

static int lora_sim_init(const struct device *dev)
{
	struct lora_sim_data *data = dev->data;
	int rc;

	data->fd = -1;

	rc = lora_sim_connect(data);
	if (rc < 0) {
		return rc;
	}
	rc = lora_sim_register(data);
	if (rc < 0) {
		zsock_close(data->fd);
		data->fd = -1;
		return rc;
	}
	return 0;
}

static const struct lora_driver_api lora_sim_api = {
	.config = lora_sim_config,
	.send   = lora_sim_send,
	.recv   = lora_sim_recv,
};

#define LORA_SIM_DEFINE(inst)						\
	static struct lora_sim_data lora_sim_data_##inst;		\
	DEVICE_DT_INST_DEFINE(inst, lora_sim_init, NULL,		\
			      &lora_sim_data_##inst, NULL,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_sim_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_SIM_DEFINE)
