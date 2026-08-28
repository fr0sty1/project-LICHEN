/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_client.h>
#include <lichen/coap_location.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/hal.h>
#include <lichen/lora_l2.h>
#include <lichen/senml.h>

LOG_MODULE_REGISTER(lichen_coap_location,
                    CONFIG_LICHEN_COAP_LOCATION_LOG_LEVEL);

#define LOCATION_SENML_MAX LICHEN_POSITION_BEACON_PAYLOAD_MAX
#define BASE_NAME_MAX 32

#define POSITION_BEACON_DEFAULT_MOVEMENT_CM 1000U
#define POSITION_BEACON_DEFAULT_STATIONARY_CM 300U
#define POSITION_BEACON_DEFAULT_HYSTERESIS 2U
#define POSITION_BEACON_DEFAULT_MAX_RETRIES 3U
#define POSITION_BEACON_COAP_PORT 5683U

struct position_beacon_state {
  struct lichen_position_beacon_config config;
  struct lichen_position_beacon_stats stats;
  enum lichen_position_privacy_mode privacy;
  bool configured;
  bool running;
  bool transmit_in_progress;
  bool have_previous_position;
  bool have_last_motion_sample;
  int32_t previous_latitude_e7;
  int32_t previous_longitude_e7;
  int64_t last_motion_sample_ms;
  int64_t last_poll_ms;
  uint8_t stationary_samples;
};

static struct position_beacon_state beacon;
static void position_beacon_work_handler(struct k_work *work);
K_MUTEX_DEFINE(position_beacon_mutex);
K_WORK_DELAYABLE_DEFINE(position_beacon_work, position_beacon_work_handler);

struct position_cache_entry {
  bool used;
  uint8_t node[16];
  int32_t latitude_e7;
  int32_t longitude_e7;
  int32_t altitude_cm;
  uint64_t timestamp_unix;
  int64_t observed_ms;
  enum lichen_position_privacy_mode privacy;
  bool altitude_valid;
};

struct position_cache_state {
  struct position_cache_entry entries[LICHEN_POSITION_CACHE_MAX_ENTRIES];
  enum lichen_position_privacy_mode privacy;
  int64_t last_now_ms;
  bool have_last_now;
};

struct cbor_writer {
  uint8_t *buf;
  size_t len;
  size_t cap;
  bool overflow;
};

static struct position_cache_state position_cache;
K_MUTEX_DEFINE(position_cache_mutex);

struct position_observer_delivery {
  struct coap_observer *observer;
  int64_t retry_at_ms;
  uint8_t retries;
  bool pending;
  bool drop;
};

struct position_observe_state {
  struct position_observer_delivery delivery[LICHEN_POSITION_OBSERVER_MAX];
  struct lichen_position_observe_stats stats;
  struct lichen_hal_location_time_snapshot last_snapshot;
  uint8_t payload[LOCATION_SENML_MAX];
  size_t payload_len;
  int64_t last_notify_ms;
  int64_t last_poll_ms;
  int64_t current_now_ms;
  enum lichen_position_privacy_mode privacy;
  bool have_last_snapshot;
  bool have_last_poll;
};

static struct position_observe_state position_observe;
K_MUTEX_DEFINE(position_observe_mutex);

extern struct coap_resource lichen_sensors_location;
static void remove_all_location_observers_locked(void);

static void build_base_name(char *out, size_t out_len) {
  uint8_t eui[8];

  if (out_len == 0 || lichen_lora_l2_copy_eui64(eui) != 0) {
    if (out_len > 0) {
      out[0] = '\0';
    }
    return;
  }
  int ret = snprintf(out, out_len,
                     "urn:dev:mac:%02x%02x%02x%02x%02x%02x%02x%02x:", eui[0],
                     eui[1], eui[2], eui[3], eui[4], eui[5], eui[6], eui[7]);
  if (ret < 0 || (size_t)ret >= out_len) {
    out[0] = '\0';
    return;
  }
}

static int64_t deadline_after(int64_t now_ms, uint32_t delay_ms) {
  if (now_ms > INT64_MAX - (int64_t)delay_ms) {
    return INT64_MAX;
  }
  return now_ms + (int64_t)delay_ms;
}

static double position_distance_cm(int32_t lat1_e7, int32_t lon1_e7,
                                   int32_t lat2_e7, int32_t lon2_e7) {
  const double degrees_to_radians = 0.017453292519943295;
  const double e7_degree_to_cm = 1.1131949079327357;
  double middle_latitude =
      ((double)lat1_e7 + (double)lat2_e7) * 0.5e-7 * degrees_to_radians;
  double north_cm = ((double)lat2_e7 - (double)lat1_e7) * e7_degree_to_cm;
  double east_cm = ((double)lon2_e7 - (double)lon1_e7) * cos(middle_latitude) *
                   e7_degree_to_cm;

  return hypot(north_cm, east_cm);
}

static void
update_motion_locked(const struct lichen_hal_location_time_snapshot *snap) {
  double distance_cm;

  if (!snap->latitude_e7_valid || !snap->longitude_e7_valid) {
    return;
  }
  if (!beacon.have_previous_position) {
    beacon.previous_latitude_e7 = snap->latitude_e7;
    beacon.previous_longitude_e7 = snap->longitude_e7;
    beacon.have_previous_position = true;
    return;
  }

  distance_cm = position_distance_cm(beacon.previous_latitude_e7,
                                     beacon.previous_longitude_e7,
                                     snap->latitude_e7, snap->longitude_e7);
  beacon.previous_latitude_e7 = snap->latitude_e7;
  beacon.previous_longitude_e7 = snap->longitude_e7;

  if (!beacon.stats.moving) {
    if (distance_cm >= (double)beacon.config.moving_threshold_cm) {
      beacon.stats.moving = true;
      beacon.stationary_samples = 0U;
    }
    return;
  }

  if (distance_cm <= (double)beacon.config.stationary_threshold_cm) {
    if (beacon.stationary_samples < UINT8_MAX) {
      beacon.stationary_samples++;
    }
    if (beacon.stationary_samples >=
        beacon.config.stationary_hysteresis_samples) {
      beacon.stats.moving = false;
      beacon.stationary_samples = 0U;
    }
  } else {
    beacon.stationary_samples = 0U;
  }
}

static int default_beacon_tx(const uint8_t *payload, size_t payload_len,
                             void *user_data) {
  static const char *const path[] = {"pos", NULL};
  struct lichen_coap_request request = {
      .path = path,
      .method = COAP_METHOD_PUT,
      .payload = payload,
      .payload_len = payload_len,
      .content_format = SENML_CBOR_CONTENT_FORMAT,
      .confirmable = false,
      .timeout_ms = LICHEN_COAP_TIMEOUT_MS,
  };
  uint32_t interface_index = (uint32_t)(uintptr_t)user_data;
  struct net_if *iface;
  int ret;

  request.addr.sin6_family = AF_INET6;
  request.addr.sin6_port = htons(POSITION_BEACON_COAP_PORT);
  if (interface_index == 0U) {
    iface = net_if_get_default();
    if (iface != NULL) {
      interface_index = net_if_get_by_iface(iface);
    }
  }
  request.addr.sin6_scope_id = interface_index;
  request.addr.sin6_addr.s6_addr[0] = 0xffU;
  request.addr.sin6_addr.s6_addr[1] = 0x02U;
  request.addr.sin6_addr.s6_addr[15] = 0x01U;

  ret = lichen_coap_request(&request);
  if (ret == LICHEN_COAP_OK) {
    return 0;
  }
  if (ret == LICHEN_COAP_ERR_NO_MEMORY) {
    return -ENOBUFS;
  }
  if (ret == LICHEN_COAP_ERR_SEND_FAILED || ret == LICHEN_COAP_ERR_TRANSPORT) {
    return -EAGAIN;
  }
  return -EIO;
}

static bool transient_tx_error(int ret) {
  return ret == -EAGAIN || ret == -ENOBUFS || ret == -ENOMEM || ret == -EBUSY;
}

static bool location_snapshot_fresh(
    const struct lichen_hal_location_time_snapshot *snap) {
  if (!snap->location_provider_available || !snap->latitude_e7_valid ||
      !snap->longitude_e7_valid) {
    return false;
  }
  if (snap->fix_state_valid &&
      (snap->fix_state == LICHEN_HAL_LOCATION_FIX_NONE ||
       snap->fix_state == LICHEN_HAL_LOCATION_FIX_NO_FIX ||
       snap->fix_state == LICHEN_HAL_LOCATION_FIX_STALE ||
       snap->fix_state == LICHEN_HAL_LOCATION_FIX_ERROR)) {
    return false;
  }
  return true;
}

static int encode_location_snapshot(
    const struct lichen_hal_location_time_snapshot *snap, uint8_t *payload,
    size_t payload_len) {
  char base_name[BASE_NAME_MAX];
  float alt = snap->altitude_m_valid ? (float)snap->altitude_m : NAN;
  float hacc = snap->horizontal_accuracy_mm_valid
                   ? (float)snap->horizontal_accuracy_mm / 1000.0f
                   : NAN;
  float vacc = snap->vertical_accuracy_mm_valid
                   ? (float)snap->vertical_accuracy_mm / 1000.0f
                   : NAN;
  uint64_t base_time = snap->fix_time_unix_valid ? snap->fix_time_unix : 0U;

  build_base_name(base_name, sizeof(base_name));
  return senml_encode_location_full(
      base_name[0] != '\0' ? base_name : NULL, base_time,
      (float)snap->latitude_e7 / 1e7f, (float)snap->longitude_e7 / 1e7f, alt,
      NAN, NAN, hacc, vacc, payload, payload_len);
}

__weak int lichen_position_observe_send(
    const struct coap_resource *resource, const struct sockaddr *addr,
    socklen_t addr_len, const uint8_t *token, uint8_t token_len,
    uint32_t sequence, const uint8_t *payload, size_t payload_len, bool initial,
    uint8_t request_type, uint16_t request_id) {
  uint8_t buffer[CONFIG_COAP_SERVER_MESSAGE_SIZE];
  struct coap_packet packet;
  uint8_t type = initial && request_type == COAP_TYPE_CON ? COAP_TYPE_ACK
                                                          : COAP_TYPE_NON_CON;
  uint16_t id = initial ? request_id : coap_next_id();
  int ret;

  ret = coap_packet_init(&packet, buffer, sizeof(buffer), COAP_VERSION_1, type,
                         token_len, token, COAP_RESPONSE_CODE_CONTENT, id);
  if (ret < 0) {
    return ret;
  }
  ret = coap_append_option_int(&packet, COAP_OPTION_OBSERVE, sequence);
  if (ret < 0) {
    return ret;
  }
  ret = coap_append_option_int(&packet, COAP_OPTION_CONTENT_FORMAT,
                               SENML_CBOR_CONTENT_FORMAT);
  if (ret < 0) {
    return ret;
  }
  ret = coap_packet_append_payload_marker(&packet);
  if (ret < 0) {
    return ret;
  }
  ret = coap_packet_append_payload(&packet, payload, payload_len);
  if (ret < 0) {
    return ret;
  }
  return coap_resource_send(resource, &packet, addr, addr_len, NULL);
}

static struct position_observer_delivery *observer_delivery_locked(
    struct coap_observer *observer) {
  struct position_observer_delivery *free_slot = NULL;

  for (size_t i = 0; i < ARRAY_SIZE(position_observe.delivery); i++) {
    struct position_observer_delivery *delivery =
        &position_observe.delivery[i];

    if (delivery->observer == observer) {
      return delivery;
    }
    if (delivery->observer == NULL && free_slot == NULL) {
      free_slot = delivery;
    }
  }
  if (free_slot != NULL) {
    free_slot->observer = observer;
  }
  return free_slot;
}

static uint8_t observer_count(void) {
  uint8_t count = 0U;
  struct coap_observer *observer;

  SYS_SLIST_FOR_EACH_CONTAINER(&lichen_sensors_location.observers, observer,
                               list) {
    count++;
  }
  return count;
}

static bool observer_addr_equal(const struct sockaddr *a,
                                const struct sockaddr *b) {
  if (a->sa_family != b->sa_family) {
    return false;
  }
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

    return a6->sin6_port == b6->sin6_port &&
           a6->sin6_scope_id == b6->sin6_scope_id &&
           net_ipv6_addr_cmp(&a6->sin6_addr, &b6->sin6_addr);
  }
#if defined(CONFIG_NET_IPV4)
  if (a->sa_family == AF_INET) {
    const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
    const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

    return a4->sin_port == b4->sin_port &&
           net_ipv4_addr_cmp(&a4->sin_addr, &b4->sin_addr);
  }
#endif
  return false;
}

static struct coap_observer *find_location_observer(
    const struct sockaddr *addr, const uint8_t *token, uint8_t token_len) {
  struct coap_observer *observer;

  SYS_SLIST_FOR_EACH_CONTAINER(&lichen_sensors_location.observers, observer,
                               list) {
    if (observer->tkl == token_len &&
        memcmp(observer->token, token, token_len) == 0 &&
        observer_addr_equal(&observer->addr, addr)) {
      return observer;
    }
  }
  return NULL;
}

static void position_observe_notify_cb(struct coap_resource *resource,
                                       struct coap_observer *observer) {
  struct position_observer_delivery *delivery;
  int ret;

  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  if (position_observe.privacy != LICHEN_POSITION_PRIVACY_PUBLIC ||
      position_observe.payload_len == 0U) {
    k_mutex_unlock(&position_observe_mutex);
    return;
  }
  delivery = observer_delivery_locked(observer);
  if (delivery == NULL) {
    position_observe.stats.failures++;
    position_observe.stats.last_error = -ENOSPC;
    k_mutex_unlock(&position_observe_mutex);
    return;
  }
  ret = lichen_position_observe_send(
      resource, &observer->addr, sizeof(observer->addr), observer->token,
      observer->tkl, (uint32_t)resource->age, position_observe.payload,
      position_observe.payload_len, false, COAP_TYPE_NON_CON, 0U);
  if (ret == 0) {
    delivery->pending = false;
    delivery->retries = 0U;
    position_observe.stats.notifications++;
    position_observe.stats.last_error = 0;
  } else if (transient_tx_error(ret)) {
    delivery->pending = true;
    delivery->retry_at_ms = deadline_after(position_observe.current_now_ms,
                                            LICHEN_POSITION_OBSERVE_RETRY_MS);
    position_observe.stats.backpressure++;
    position_observe.stats.last_error = ret;
  } else {
    delivery->drop = true;
    position_observe.stats.failures++;
    position_observe.stats.last_error = ret;
  }
  k_mutex_unlock(&position_observe_mutex);
}

static uint32_t current_interval_locked(void) {
  return beacon.stats.moving ? beacon.config.moving_interval_ms
                             : beacon.config.stationary_interval_ms;
}

static uint32_t next_work_delay_locked(int64_t now_ms) {
  int64_t sample_due = deadline_after(now_ms, beacon.config.moving_interval_ms);
  int64_t next = beacon.stats.next_due_ms < sample_due
                     ? beacon.stats.next_due_ms
                     : sample_due;
  int64_t delay = next > now_ms ? next - now_ms : 0;

  return delay > UINT32_MAX ? UINT32_MAX : (uint32_t)delay;
}

static void position_beacon_work_handler(struct k_work *work) {
  int64_t now_ms = k_uptime_get();
  uint32_t delay_ms;
  bool running;

  ARG_UNUSED(work);
  (void)lichen_position_beacon_poll(now_ms);

  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  running = beacon.running;
  delay_ms = next_work_delay_locked(now_ms);
  if (running) {
    (void)k_work_reschedule(&position_beacon_work, K_MSEC(delay_ms));
  }
  k_mutex_unlock(&position_beacon_mutex);
}

int lichen_position_beacon_configure(
    const struct lichen_position_beacon_config *config, int64_t now_ms) {
  struct lichen_position_beacon_config effective = {0};

  if (now_ms < 0) {
    return -EINVAL;
  }
  if (config != NULL) {
    effective = *config;
  }
  effective.moving_interval_ms =
      effective.moving_interval_ms != 0U
          ? effective.moving_interval_ms
          : LICHEN_POSITION_BEACON_MOVING_INTERVAL_MS;
  effective.stationary_interval_ms =
      effective.stationary_interval_ms != 0U
          ? effective.stationary_interval_ms
          : LICHEN_POSITION_BEACON_STATIONARY_INTERVAL_MS;
  effective.retry_interval_ms = effective.retry_interval_ms != 0U
                                    ? effective.retry_interval_ms
                                    : LICHEN_POSITION_BEACON_RETRY_INTERVAL_MS;
  effective.moving_threshold_cm = effective.moving_threshold_cm != 0U
                                      ? effective.moving_threshold_cm
                                      : POSITION_BEACON_DEFAULT_MOVEMENT_CM;
  effective.stationary_threshold_cm =
      effective.stationary_threshold_cm != 0U
          ? effective.stationary_threshold_cm
          : POSITION_BEACON_DEFAULT_STATIONARY_CM;
  effective.stationary_hysteresis_samples =
      effective.stationary_hysteresis_samples != 0U
          ? effective.stationary_hysteresis_samples
          : POSITION_BEACON_DEFAULT_HYSTERESIS;
  effective.max_retries = effective.max_retries != 0U
                              ? effective.max_retries
                              : POSITION_BEACON_DEFAULT_MAX_RETRIES;

  if (effective.stationary_interval_ms < effective.moving_interval_ms ||
      effective.stationary_threshold_cm >= effective.moving_threshold_cm) {
    return -EINVAL;
  }

  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  if (beacon.running) {
    k_mutex_unlock(&position_beacon_mutex);
    return -EBUSY;
  }
  beacon.config = effective;
  beacon.stats = (struct lichen_position_beacon_stats){
      .next_due_ms = now_ms,
  };
  beacon.privacy = LICHEN_POSITION_PRIVACY_PUBLIC;
  beacon.have_previous_position = false;
  beacon.have_last_motion_sample = false;
  beacon.transmit_in_progress = false;
  beacon.last_poll_ms = now_ms;
  beacon.stationary_samples = 0U;
  beacon.configured = true;
  k_mutex_unlock(&position_beacon_mutex);
  return 0;
}

int lichen_position_beacon_poll(int64_t now_ms) {
  struct lichen_hal_location_time_snapshot snap;
  lichen_position_beacon_tx_fn tx_fn;
  void *tx_user_data;
  char base_name[BASE_NAME_MAX];
  uint8_t payload[LOCATION_SENML_MAX];
  uint32_t interval_ms;
  uint64_t base_time;
  float alt;
  float hacc;
  float vacc;
  bool was_moving;
  int len;
  int ret;

  if (now_ms < 0) {
    return -EINVAL;
  }
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  if (!beacon.configured) {
    k_mutex_unlock(&position_beacon_mutex);
    return -EAGAIN;
  }
  if (now_ms < beacon.last_poll_ms) {
    k_mutex_unlock(&position_beacon_mutex);
    return -ERANGE;
  }
  if (beacon.transmit_in_progress) {
    k_mutex_unlock(&position_beacon_mutex);
    return -EBUSY;
  }
  beacon.last_poll_ms = now_ms;
  if (lichen_hal_location_time_snapshot_get(&snap) < 0 ||
      !snap.latitude_e7_valid || !snap.longitude_e7_valid) {
    beacon.stats.no_fix++;
    beacon.stats.next_due_ms =
        deadline_after(now_ms, beacon.config.moving_interval_ms);
    k_mutex_unlock(&position_beacon_mutex);
    return LICHEN_POSITION_BEACON_NO_FIX;
  }

  was_moving = beacon.stats.moving;
  if (!beacon.have_last_motion_sample ||
      now_ms - beacon.last_motion_sample_ms >=
          (int64_t)beacon.config.moving_interval_ms) {
    update_motion_locked(&snap);
    beacon.last_motion_sample_ms = now_ms;
    beacon.have_last_motion_sample = true;
  }
  if (!was_moving && beacon.stats.moving && beacon.stats.next_due_ms > now_ms) {
    beacon.stats.next_due_ms = now_ms;
  }
  (void)lichen_position_observe_poll(now_ms);
  if (now_ms < beacon.stats.next_due_ms) {
    k_mutex_unlock(&position_beacon_mutex);
    return LICHEN_POSITION_BEACON_IDLE;
  }
  if (beacon.privacy != LICHEN_POSITION_PRIVACY_PUBLIC) {
    beacon.stats.privacy_suppressed++;
    beacon.stats.retry_count = 0U;
    beacon.stats.next_due_ms =
        deadline_after(now_ms, current_interval_locked());
    k_mutex_unlock(&position_beacon_mutex);
    return LICHEN_POSITION_BEACON_SUPPRESSED;
  }
  tx_fn = beacon.config.tx_fn != NULL ? beacon.config.tx_fn : default_beacon_tx;
  tx_user_data = beacon.config.tx_fn != NULL
                     ? beacon.config.tx_user_data
                     : (void *)(uintptr_t)beacon.config.interface_index;
  beacon.transmit_in_progress = true;
  k_mutex_unlock(&position_beacon_mutex);

  build_base_name(base_name, sizeof(base_name));
  alt = snap.altitude_m_valid ? (float)snap.altitude_m : NAN;
  hacc = snap.horizontal_accuracy_mm_valid
             ? (float)snap.horizontal_accuracy_mm / 1000.0f
             : NAN;
  vacc = snap.vertical_accuracy_mm_valid
             ? (float)snap.vertical_accuracy_mm / 1000.0f
             : NAN;
  base_time = snap.fix_time_unix_valid ? snap.fix_time_unix : 0U;
  len = senml_encode_location_full(base_name[0] != '\0' ? base_name : NULL,
                                   base_time, (float)snap.latitude_e7 / 1e7f,
                                   (float)snap.longitude_e7 / 1e7f, alt, NAN,
                                   NAN, hacc, vacc, payload, sizeof(payload));
  if (len < 0) {
    k_mutex_lock(&position_beacon_mutex, K_FOREVER);
    beacon.transmit_in_progress = false;
    beacon.stats.failures++;
    beacon.stats.last_error = len;
    beacon.stats.retry_count = 0U;
    beacon.stats.next_due_ms =
        deadline_after(now_ms, current_interval_locked());
    k_mutex_unlock(&position_beacon_mutex);
    return len;
  }

  ret = tx_fn(payload, (size_t)len, tx_user_data);
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  beacon.transmit_in_progress = false;
  interval_ms = current_interval_locked();
  if (ret == 0) {
    beacon.stats.sent++;
    beacon.stats.last_error = 0;
    beacon.stats.retry_count = 0U;
    beacon.stats.next_due_ms = deadline_after(now_ms, interval_ms);
    k_mutex_unlock(&position_beacon_mutex);
    return LICHEN_POSITION_BEACON_SENT;
  }

  beacon.stats.last_error = ret;
  if (transient_tx_error(ret)) {
    beacon.stats.backpressure++;
    if (beacon.stats.retry_count < beacon.config.max_retries) {
      beacon.stats.retry_count++;
      beacon.stats.next_due_ms =
          deadline_after(now_ms, beacon.config.retry_interval_ms);
    } else {
      beacon.stats.failures++;
      beacon.stats.retry_count = 0U;
      beacon.stats.next_due_ms = deadline_after(now_ms, interval_ms);
    }
  } else {
    beacon.stats.failures++;
    beacon.stats.retry_count = 0U;
    beacon.stats.next_due_ms = deadline_after(now_ms, interval_ms);
  }
  k_mutex_unlock(&position_beacon_mutex);
  return ret;
}

int lichen_position_beacon_start(
    const struct lichen_position_beacon_config *config) {
  int ret = lichen_position_beacon_configure(config, k_uptime_get());

  if (ret < 0) {
    return ret;
  }
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  beacon.running = true;
  k_mutex_unlock(&position_beacon_mutex);
  (void)k_work_reschedule(&position_beacon_work, K_NO_WAIT);
  return 0;
}

void lichen_position_beacon_stop(void) {
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  beacon.running = false;
  k_mutex_unlock(&position_beacon_mutex);
  (void)k_work_cancel_delayable(&position_beacon_work);
}

int lichen_position_beacon_set_privacy(enum lichen_position_privacy_mode mode) {
  bool running;

  if (mode < LICHEN_POSITION_PRIVACY_PUBLIC ||
      mode > LICHEN_POSITION_PRIVACY_OFF) {
    return -EINVAL;
  }
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  if (!beacon.configured) {
    k_mutex_unlock(&position_beacon_mutex);
    return -EAGAIN;
  }
  beacon.privacy = mode;
  if (mode == LICHEN_POSITION_PRIVACY_PUBLIC) {
    beacon.stats.next_due_ms = 0;
  }
  running = beacon.running;
  k_mutex_unlock(&position_beacon_mutex);
  if (running && mode == LICHEN_POSITION_PRIVACY_PUBLIC) {
    (void)k_work_reschedule(&position_beacon_work, K_NO_WAIT);
  }
  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  position_observe.privacy = mode;
  if (mode != LICHEN_POSITION_PRIVACY_PUBLIC) {
    remove_all_location_observers_locked();
  }
  k_mutex_unlock(&position_observe_mutex);
  (void)lichen_position_cache_set_privacy(mode);
  return 0;
}

int lichen_position_beacon_get_stats(
    struct lichen_position_beacon_stats *stats) {
  if (stats == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&position_beacon_mutex, K_FOREVER);
  if (!beacon.configured) {
    k_mutex_unlock(&position_beacon_mutex);
    return -EAGAIN;
  }
  *stats = beacon.stats;
  k_mutex_unlock(&position_beacon_mutex);
  return 0;
}

static void remove_all_location_observers_locked(void) {
  struct coap_observer *observer;

  while ((observer = SYS_SLIST_PEEK_HEAD_CONTAINER(
              &lichen_sensors_location.observers, observer, list)) != NULL) {
    (void)coap_remove_observer(&lichen_sensors_location, observer);
    memset(observer, 0, sizeof(*observer));
  }
  memset(position_observe.delivery, 0, sizeof(position_observe.delivery));
  position_observe.stats.observers = 0U;
}

void lichen_position_observe_reset(void) {
  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  remove_all_location_observers_locked();
  position_observe = (struct position_observe_state){
      .privacy = LICHEN_POSITION_PRIVACY_PUBLIC,
  };
  lichen_sensors_location.age = 0;
  k_mutex_unlock(&position_observe_mutex);
}

static bool location_source_changed(
    const struct lichen_hal_location_time_snapshot *a,
    const struct lichen_hal_location_time_snapshot *b) {
  return a->source_class_valid != b->source_class_valid ||
         (a->source_class_valid && a->source_class != b->source_class) ||
         strncmp(a->source_name, b->source_name, sizeof(a->source_name)) != 0;
}

static bool location_freshness_changed(
    const struct lichen_hal_location_time_snapshot *a,
    const struct lichen_hal_location_time_snapshot *b) {
  return a->fix_state_valid != b->fix_state_valid ||
         (a->fix_state_valid && a->fix_state != b->fix_state) ||
         a->age_seconds_valid != b->age_seconds_valid;
}

static void remove_dropped_observers_locked(void) {
  for (size_t i = 0; i < ARRAY_SIZE(position_observe.delivery); i++) {
    struct position_observer_delivery *delivery =
        &position_observe.delivery[i];

    if (delivery->drop && delivery->observer != NULL) {
      (void)coap_remove_observer(&lichen_sensors_location,
                                 delivery->observer);
      memset(delivery->observer, 0, sizeof(*delivery->observer));
      *delivery = (struct position_observer_delivery){0};
    }
  }
  position_observe.stats.observers = observer_count();
}

static void retry_location_observers_locked(int64_t now_ms) {
  for (size_t i = 0; i < ARRAY_SIZE(position_observe.delivery); i++) {
    struct position_observer_delivery *delivery =
        &position_observe.delivery[i];
    int ret;

    if (delivery->observer != NULL &&
        delivery->observer->addr.sa_family == AF_UNSPEC) {
      *delivery = (struct position_observer_delivery){0};
      continue;
    }
    if (!delivery->pending || delivery->observer == NULL ||
        now_ms < delivery->retry_at_ms) {
      continue;
    }
    ret = lichen_position_observe_send(
        &lichen_sensors_location, &delivery->observer->addr,
        sizeof(delivery->observer->addr), delivery->observer->token,
        delivery->observer->tkl, (uint32_t)lichen_sensors_location.age,
        position_observe.payload, position_observe.payload_len, false,
        COAP_TYPE_NON_CON, 0U);
    if (ret == 0) {
      delivery->pending = false;
      delivery->retries = 0U;
      position_observe.stats.notifications++;
      position_observe.stats.last_error = 0;
    } else if (transient_tx_error(ret)) {
      delivery->retries++;
      position_observe.stats.backpressure++;
      position_observe.stats.last_error = ret;
      if (delivery->retries >= 3U) {
        delivery->drop = true;
        delivery->pending = false;
        position_observe.stats.failures++;
      } else {
        delivery->retry_at_ms =
            deadline_after(now_ms, LICHEN_POSITION_OBSERVE_RETRY_MS);
      }
    } else {
      delivery->drop = true;
      delivery->pending = false;
      position_observe.stats.failures++;
      position_observe.stats.last_error = ret;
    }
  }
  remove_dropped_observers_locked();
}

int lichen_position_observe_poll(int64_t now_ms) {
  struct lichen_hal_location_time_snapshot snap;
  bool trigger;
  int len;
  int ret;

  if (now_ms < 0) {
    return -EINVAL;
  }
  if (lichen_hal_location_time_snapshot_get(&snap) < 0) {
    return LICHEN_POSITION_OBSERVE_NO_FIX;
  }

  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  if (position_observe.have_last_poll &&
      now_ms < position_observe.last_poll_ms) {
    k_mutex_unlock(&position_observe_mutex);
    return -ERANGE;
  }
  position_observe.have_last_poll = true;
  position_observe.last_poll_ms = now_ms;
  position_observe.current_now_ms = now_ms;
  retry_location_observers_locked(now_ms);
  if (position_observe.privacy != LICHEN_POSITION_PRIVACY_PUBLIC) {
    k_mutex_unlock(&position_observe_mutex);
    return LICHEN_POSITION_OBSERVE_SUPPRESSED;
  }
  if (!location_snapshot_fresh(&snap)) {
    k_mutex_unlock(&position_observe_mutex);
    return LICHEN_POSITION_OBSERVE_NO_FIX;
  }
  trigger = !position_observe.have_last_snapshot;
  if (position_observe.have_last_snapshot) {
    trigger = location_source_changed(&snap, &position_observe.last_snapshot) ||
              location_freshness_changed(&snap,
                                         &position_observe.last_snapshot) ||
              position_distance_cm(
                  position_observe.last_snapshot.latitude_e7,
                  position_observe.last_snapshot.longitude_e7,
                  snap.latitude_e7, snap.longitude_e7) >=
                  LICHEN_POSITION_OBSERVE_DISTANCE_CM ||
              now_ms - position_observe.last_notify_ms >=
                  LICHEN_POSITION_OBSERVE_INTERVAL_MS;
  }
  if (!trigger) {
    k_mutex_unlock(&position_observe_mutex);
    return LICHEN_POSITION_OBSERVE_IDLE;
  }
  len = encode_location_snapshot(&snap, position_observe.payload,
                                 sizeof(position_observe.payload));
  if (len < 0) {
    position_observe.stats.failures++;
    position_observe.stats.last_error = len;
    k_mutex_unlock(&position_observe_mutex);
    return len;
  }
  position_observe.payload_len = (size_t)len;
  position_observe.last_snapshot = snap;
  position_observe.have_last_snapshot = true;
  position_observe.last_notify_ms = now_ms;
  k_mutex_unlock(&position_observe_mutex);

  ret = coap_resource_notify(&lichen_sensors_location);
  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  remove_dropped_observers_locked();
  position_observe.stats.sequence =
      (uint32_t)lichen_sensors_location.age;
  position_observe.stats.observers = observer_count();
  k_mutex_unlock(&position_observe_mutex);
  return ret < 0 ? ret : LICHEN_POSITION_OBSERVE_NOTIFIED;
}

int lichen_position_observe_get_stats(
    struct lichen_position_observe_stats *stats) {
  if (stats == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&position_observe_mutex, K_FOREVER);
  *stats = position_observe.stats;
  stats->observers = observer_count();
  stats->sequence = (uint32_t)lichen_sensors_location.age;
  k_mutex_unlock(&position_observe_mutex);
  return 0;
}

static void cbor_put_byte(struct cbor_writer *w, uint8_t value) {
  if (w->len >= w->cap) {
    w->overflow = true;
  } else {
    w->buf[w->len++] = value;
  }
}

static void cbor_put_bytes(struct cbor_writer *w, const uint8_t *data,
                           size_t len) {
  if (len > w->cap - w->len) {
    w->overflow = true;
    return;
  }
  memcpy(&w->buf[w->len], data, len);
  w->len += len;
}

static void cbor_put_value(struct cbor_writer *w, uint8_t major,
                           uint64_t value) {
  if (value < 24U) {
    cbor_put_byte(w, (uint8_t)(major | value));
  } else if (value <= UINT8_MAX) {
    cbor_put_byte(w, (uint8_t)(major | 24U));
    cbor_put_byte(w, (uint8_t)value);
  } else if (value <= UINT16_MAX) {
    cbor_put_byte(w, (uint8_t)(major | 25U));
    cbor_put_byte(w, (uint8_t)(value >> 8));
    cbor_put_byte(w, (uint8_t)value);
  } else if (value <= UINT32_MAX) {
    cbor_put_byte(w, (uint8_t)(major | 26U));
    for (int shift = 24; shift >= 0; shift -= 8) {
      cbor_put_byte(w, (uint8_t)(value >> shift));
    }
  } else {
    cbor_put_byte(w, (uint8_t)(major | 27U));
    for (int shift = 56; shift >= 0; shift -= 8) {
      cbor_put_byte(w, (uint8_t)(value >> shift));
    }
  }
}

static void cbor_put_text(struct cbor_writer *w, const char *text) {
  size_t len = strlen(text);

  cbor_put_value(w, 0x60U, len);
  cbor_put_bytes(w, (const uint8_t *)text, len);
}

static void cbor_put_double(struct cbor_writer *w, double value) {
  uint64_t bits;

  memcpy(&bits, &value, sizeof(bits));
  cbor_put_byte(w, 0xfbU);
  for (int shift = 56; shift >= 0; shift -= 8) {
    cbor_put_byte(w, (uint8_t)(bits >> shift));
  }
}

static bool cache_node_valid(const uint8_t node[16]) {
  struct in6_addr addr;

  memcpy(addr.s6_addr, node, sizeof(addr.s6_addr));
  return !net_ipv6_is_addr_unspecified(&addr) &&
         !net_ipv6_is_addr_mcast(&addr);
}

static bool cache_provenance_valid(
    const struct lichen_position_cache_update *update) {
  if (!update->authenticated ||
      memcmp(update->node, update->authenticated_node,
             sizeof(update->node)) != 0) {
    return false;
  }
  if (update->privacy == LICHEN_POSITION_PRIVACY_PUBLIC) {
    return update->provenance == LICHEN_POSITION_PROVENANCE_LINK_SIGNED;
  }
  if (update->privacy == LICHEN_POSITION_PRIVACY_GROUP) {
    return update->provenance == LICHEN_POSITION_PROVENANCE_GROUP_OSCORE;
  }
  return false;
}

void lichen_position_cache_reset(void) {
  k_mutex_lock(&position_cache_mutex, K_FOREVER);
  position_cache = (struct position_cache_state){
      .privacy = LICHEN_POSITION_PRIVACY_PUBLIC,
  };
  k_mutex_unlock(&position_cache_mutex);
}

int lichen_position_cache_update(
    const struct lichen_position_cache_update *update) {
  struct position_cache_entry *slot = NULL;
  struct position_cache_entry *oldest = NULL;

  if (update == NULL || update->observed_monotonic_ms < 0 ||
      update->latitude_e7 < -900000000 ||
      update->latitude_e7 > 900000000 ||
      update->longitude_e7 < -1800000000 ||
      update->longitude_e7 > 1800000000 || !cache_node_valid(update->node) ||
      !cache_provenance_valid(update)) {
    return -EINVAL;
  }

  k_mutex_lock(&position_cache_mutex, K_FOREVER);
  if (position_cache.have_last_now &&
      update->observed_monotonic_ms < position_cache.last_now_ms) {
    k_mutex_unlock(&position_cache_mutex);
    return -ERANGE;
  }
  for (size_t i = 0; i < ARRAY_SIZE(position_cache.entries); i++) {
    struct position_cache_entry *entry = &position_cache.entries[i];

    if (entry->used &&
        memcmp(entry->node, update->node, sizeof(entry->node)) == 0) {
      slot = entry;
      if (update->timestamp_unix != 0U && entry->timestamp_unix != 0U &&
          update->timestamp_unix <= entry->timestamp_unix) {
        k_mutex_unlock(&position_cache_mutex);
        return -EALREADY;
      }
      break;
    }
    if (!entry->used && slot == NULL) {
      slot = entry;
    }
    if (entry->used &&
        (oldest == NULL || entry->observed_ms < oldest->observed_ms)) {
      oldest = entry;
    }
  }
  if (slot == NULL) {
    slot = oldest;
  }
  *slot = (struct position_cache_entry){
      .used = true,
      .latitude_e7 = update->latitude_e7,
      .longitude_e7 = update->longitude_e7,
      .altitude_cm = update->altitude_cm,
      .timestamp_unix = update->timestamp_unix,
      .observed_ms = update->observed_monotonic_ms,
      .privacy = update->privacy,
      .altitude_valid = update->altitude_valid,
  };
  memcpy(slot->node, update->node, sizeof(slot->node));
  position_cache.last_now_ms = update->observed_monotonic_ms;
  position_cache.have_last_now = true;
  k_mutex_unlock(&position_cache_mutex);
  return 0;
}

size_t lichen_position_cache_purge(int64_t now_ms, uint32_t max_age_ms) {
  size_t removed = 0U;

  if (now_ms < 0) {
    return 0U;
  }
  if (max_age_ms == 0U) {
    max_age_ms = LICHEN_POSITION_CACHE_EXPIRY_MS;
  }
  k_mutex_lock(&position_cache_mutex, K_FOREVER);
  if (position_cache.have_last_now && now_ms < position_cache.last_now_ms) {
    k_mutex_unlock(&position_cache_mutex);
    return 0U;
  }
  for (size_t i = 0; i < ARRAY_SIZE(position_cache.entries); i++) {
    struct position_cache_entry *entry = &position_cache.entries[i];

    if (entry->used && now_ms - entry->observed_ms > max_age_ms) {
      *entry = (struct position_cache_entry){0};
      removed++;
    }
  }
  position_cache.last_now_ms = now_ms;
  position_cache.have_last_now = true;
  k_mutex_unlock(&position_cache_mutex);
  return removed;
}

int lichen_position_cache_set_privacy(enum lichen_position_privacy_mode mode) {
  if (mode < LICHEN_POSITION_PRIVACY_PUBLIC ||
      mode > LICHEN_POSITION_PRIVACY_OFF) {
    return -EINVAL;
  }
  k_mutex_lock(&position_cache_mutex, K_FOREVER);
  position_cache.privacy = mode;
  k_mutex_unlock(&position_cache_mutex);
  return 0;
}

int lichen_position_cache_encode(int64_t now_ms, uint8_t *out,
                                 size_t out_len) {
  uint8_t scratch[LICHEN_POSITION_CACHE_PAYLOAD_MAX];
  struct cbor_writer writer = {
      .buf = scratch,
      .cap = sizeof(scratch),
  };
  size_t count = 0U;

  if (out == NULL || now_ms < 0) {
    return -EINVAL;
  }
  k_mutex_lock(&position_cache_mutex, K_FOREVER);
  if (position_cache.privacy != LICHEN_POSITION_PRIVACY_PUBLIC) {
    k_mutex_unlock(&position_cache_mutex);
    return -EACCES;
  }
  if (position_cache.have_last_now && now_ms < position_cache.last_now_ms) {
    k_mutex_unlock(&position_cache_mutex);
    return -ERANGE;
  }
  for (size_t i = 0; i < ARRAY_SIZE(position_cache.entries); i++) {
    struct position_cache_entry *entry = &position_cache.entries[i];

    if (entry->used &&
        now_ms - entry->observed_ms > LICHEN_POSITION_CACHE_EXPIRY_MS) {
      *entry = (struct position_cache_entry){0};
    }
    if (entry->used &&
        entry->privacy == LICHEN_POSITION_PRIVACY_PUBLIC) {
      count++;
    }
  }
  position_cache.last_now_ms = now_ms;
  position_cache.have_last_now = true;

  cbor_put_byte(&writer, 0xa1U);
  cbor_put_text(&writer, "positions");
  cbor_put_value(&writer, 0x80U, count);
  for (size_t i = 0; i < ARRAY_SIZE(position_cache.entries); i++) {
    const struct position_cache_entry *entry = &position_cache.entries[i];
    struct in6_addr addr;
    char node[NET_IPV6_ADDR_LEN];
    uint64_t age_s;

    if (!entry->used ||
        entry->privacy != LICHEN_POSITION_PRIVACY_PUBLIC) {
      continue;
    }
    memcpy(addr.s6_addr, entry->node, sizeof(addr.s6_addr));
    if (net_addr_ntop(AF_INET6, &addr, node, sizeof(node)) == NULL) {
      k_mutex_unlock(&position_cache_mutex);
      return -EIO;
    }
    age_s = (uint64_t)(now_ms - entry->observed_ms) / 1000U;
    cbor_put_value(&writer, 0xa0U, entry->altitude_valid ? 6U : 5U);
    cbor_put_text(&writer, "node");
    cbor_put_text(&writer, node);
    cbor_put_text(&writer, "lat");
    cbor_put_double(&writer, (double)entry->latitude_e7 / 1e7);
    cbor_put_text(&writer, "lon");
    cbor_put_double(&writer, (double)entry->longitude_e7 / 1e7);
    if (entry->altitude_valid) {
      cbor_put_text(&writer, "alt");
      cbor_put_double(&writer, (double)entry->altitude_cm / 100.0);
    }
    cbor_put_text(&writer, "ts");
    cbor_put_value(&writer, 0x00U, entry->timestamp_unix);
    cbor_put_text(&writer, "age_s");
    cbor_put_value(&writer, 0x00U, age_s);
  }
  if (writer.overflow || writer.len > out_len) {
    k_mutex_unlock(&position_cache_mutex);
    return -ENOBUFS;
  }
  memcpy(out, scratch, writer.len);
  k_mutex_unlock(&position_cache_mutex);
  return (int)writer.len;
}

static int sensors_location_get(struct coap_resource *resource,
                                struct coap_packet *request,
                                struct sockaddr *addr, socklen_t addr_len) {
  struct lichen_hal_location_time_snapshot snap;
  char base_name[BASE_NAME_MAX];
  uint8_t senml[LOCATION_SENML_MAX];
  float lat;
  float lon;
  float alt;
  float speed;
  float heading;
  float hacc;
  float vacc;
  uint64_t base_time;
  uint8_t token[COAP_TOKEN_MAX_LEN];
  uint8_t token_len;
  int observe = -ENOENT;
  int len;
  int ret;

  if (lichen_hal_location_time_snapshot_get(&snap) < 0 ||
      !location_snapshot_fresh(&snap)) {
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
  }

  lat = (float)snap.latitude_e7 / 1e7f;
  lon = (float)snap.longitude_e7 / 1e7f;
  alt = snap.altitude_m_valid ? (float)snap.altitude_m : NAN;
  /* speed, heading: not yet in HAL snapshot; always NAN */
  speed = NAN;
  heading = NAN;
  hacc = snap.horizontal_accuracy_mm_valid
             ? (float)snap.horizontal_accuracy_mm / 1000.0f
             : NAN;
  vacc = snap.vertical_accuracy_mm_valid
             ? (float)snap.vertical_accuracy_mm / 1000.0f
             : NAN;
  base_time = snap.fix_time_unix_valid ? snap.fix_time_unix : 0U;

  build_base_name(base_name, sizeof(base_name));

  len = senml_encode_location_full(base_name[0] != '\0' ? base_name : NULL,
                                   base_time, lat, lon, alt, speed, heading,
                                   hacc, vacc, senml, sizeof(senml));
  if (len < 0) {
    LOG_ERR("senml_encode_location_full failed: %d", len);
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
  }

  if (request != NULL && addr != NULL) {
    observe = coap_get_option_int(request, COAP_OPTION_OBSERVE);
  }
  if (observe >= 0) {
    bool public;

    if (observe > 1) {
      return lichen_coap_respond(resource, request, addr, addr_len,
                                 COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
    }
    k_mutex_lock(&position_observe_mutex, K_FOREVER);
    public = position_observe.privacy == LICHEN_POSITION_PRIVACY_PUBLIC;
    k_mutex_unlock(&position_observe_mutex);
    if (!public) {
      return lichen_coap_respond(resource, request, addr, addr_len,
                                 COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
    }
    token_len = coap_header_get_token(request, token);
    if (observe == 0 && token_len > 0U &&
        observer_count() >= LICHEN_POSITION_OBSERVER_MAX &&
        find_location_observer(addr, token, token_len) == NULL) {
      return lichen_coap_respond(
          resource, request, addr, addr_len,
          COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
    }
    ret = coap_resource_parse_observe(resource, request, addr);
    if (ret < 0) {
      uint8_t code = ret == -ENOMEM ? COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE
                                    : COAP_RESPONSE_CODE_BAD_REQUEST;

      return lichen_coap_respond(resource, request, addr, addr_len, code, 0,
                                 NULL, 0);
    }
    if (observe == 0) {
      ret = lichen_position_observe_send(
          resource, addr, addr_len, token, token_len, (uint32_t)resource->age,
          senml, (size_t)len, true, coap_header_get_type(request),
          coap_header_get_id(request));
      if (ret < 0) {
        struct coap_observer *observer =
            find_location_observer(addr, token, token_len);

        if (observer != NULL) {
          (void)coap_remove_observer(resource, observer);
          memset(observer, 0, sizeof(*observer));
        }
      }
      k_mutex_lock(&position_observe_mutex, K_FOREVER);
      position_observe.stats.observers = observer_count();
      k_mutex_unlock(&position_observe_mutex);
      return ret;
    }
    k_mutex_lock(&position_observe_mutex, K_FOREVER);
    position_observe.stats.observers = observer_count();
    k_mutex_unlock(&position_observe_mutex);
  }

  return lichen_coap_respond(resource, request, addr, addr_len,
                             COAP_RESPONSE_CODE_CONTENT,
                             SENML_CBOR_CONTENT_FORMAT, senml, (size_t)len);
}

static int sensors_location_post(struct coap_resource *resource,
                                 struct coap_packet *request,
                                 struct sockaddr *addr, socklen_t addr_len) {
  struct coap_oscore_unprotect_result oscore;
  int ret;

  ret = coap_oscore_unprotect_resource_request(
      resource, request, addr, addr_len, COAP_METHOD_POST, &oscore);
  if (ret != 0) {
    return ret;
  }
  if (!oscore.is_protected && !lichen_coap_is_local_admin(addr, addr_len)) {
    return coap_oscore_respond_resource(
        resource, request, addr, addr_len, &oscore,
        COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
  }
  if (oscore.payload == NULL || oscore.payload_len == 0) {
    return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                        &oscore, COAP_RESPONSE_CODE_BAD_REQUEST,
                                        0, NULL, 0);
  }
  LOG_INF("crowd map /sensors/location POST (%u bytes)", oscore.payload_len);
  return coap_oscore_respond_resource(resource, request, addr, addr_len,
                                      &oscore, COAP_RESPONSE_CODE_CREATED, 0,
                                      NULL, 0);
}

static const char *const sensors_location_path[] = {"sensors", "location",
                                                    NULL};
static const char *const position_cache_path[] = {"pos", "cache", NULL};

static int position_cache_get(struct coap_resource *resource,
                              struct coap_packet *request,
                              struct sockaddr *addr, socklen_t addr_len) {
  uint8_t payload[LICHEN_POSITION_CACHE_PAYLOAD_MAX];
  int len = lichen_position_cache_encode(k_uptime_get(), payload,
                                         sizeof(payload));

  if (len == -EACCES) {
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
  }
  if (len < 0) {
    return lichen_coap_respond(resource, request, addr, addr_len,
                               COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
  }
  return lichen_coap_respond(resource, request, addr, addr_len,
                             COAP_RESPONSE_CODE_CONTENT, 60U, payload,
                             (size_t)len);
}

COAP_RESOURCE_DEFINE(lichen_sensors_location, lichen_coap_server,
                     {
                         .get = sensors_location_get,
                         .post = sensors_location_post,
                         .notify = position_observe_notify_cb,
                         .path = sensors_location_path,
                     });

COAP_RESOURCE_DEFINE(lichen_position_cache, lichen_coap_server,
                     {
                         .get = position_cache_get,
                         .path = position_cache_path,
                     });
