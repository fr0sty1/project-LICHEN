/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/app_interface.h>
#if IS_ENABLED(CONFIG_LICHEN_HAL)
#include <lichen/app_interface/hal_bridge.h>
#endif

#define SINK_MAX CONFIG_LICHEN_APP_INTERFACE_MAX_SUBSCRIBERS
BUILD_ASSERT(SINK_MAX <= 8, "SINK_MAX too large for stack snapshots");

struct sink_slot {
	struct lichen_app_interface_sink sink;
	bool used;
};

static struct sink_slot s_sinks[SINK_MAX];
static struct lichen_app_interface_stats s_stats;
static K_MUTEX_DEFINE(s_mutex);
#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
static int s_test_next_location_submit_ret;
static int s_test_next_clear_network_ret;
#endif

static bool same_sink(const struct lichen_app_interface_sink *a,
		      const struct lichen_app_interface_sink *b)
{
	return a->emit_text == b->emit_text &&
	       a->emit_status == b->emit_status &&
	       a->submit_text == b->submit_text &&
	       a->get_status == b->get_status &&
	       a->get_config == b->get_config &&
	       a->set_config == b->set_config &&
	       a->user_data == b->user_data;
}

static bool valid_sink(const struct lichen_app_interface_sink *sink)
{
	return sink != NULL &&
	       (sink->emit_text != NULL || sink->emit_status != NULL ||
		sink->submit_text != NULL ||
		sink->get_status != NULL || sink->get_config != NULL ||
		sink->set_config != NULL);
}

static bool valid_text(const struct lichen_app_text_event *event)
{
	return event != NULL &&
	       (event->payload != NULL || event->payload_len == 0U) &&
	       event->payload_len <= CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD;
}

static bool provider_conflict(const struct lichen_app_interface_sink *existing,
			      const struct lichen_app_interface_sink *candidate)
{
	bool candidate_config = candidate->get_config != NULL ||
				candidate->set_config != NULL;
	bool existing_config = existing->get_config != NULL ||
			       existing->set_config != NULL;

	return (candidate->get_status != NULL && existing->get_status != NULL) ||
	       (candidate_config && existing_config) ||
	       (candidate->submit_text != NULL && existing->submit_text != NULL);
}

int lichen_app_interface_register_sink(
	const struct lichen_app_interface_sink *sink, uint8_t *out_id)
{
	int free_idx = -1;

	if (!valid_sink(sink)) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (size_t i = 0U; i < ARRAY_SIZE(s_sinks); i++) {
		if (s_sinks[i].used && same_sink(&s_sinks[i].sink, sink)) {
			*out_id = (uint8_t)i;
			k_mutex_unlock(&s_mutex);
			return 0;
		}
		if (s_sinks[i].used && provider_conflict(&s_sinks[i].sink, sink)) {
			k_mutex_unlock(&s_mutex);
			return -EALREADY;
		}
		if (!s_sinks[i].used && free_idx < 0) {
			free_idx = (int)i;
		}
	}
	if (free_idx < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOMEM;
	}

	s_sinks[free_idx].sink = *sink;
	s_sinks[free_idx].used = true;
	*out_id = (uint8_t)free_idx;
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_app_interface_unregister_sink(uint8_t sink_id)
{
	if (sink_id >= ARRAY_SIZE(s_sinks)) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (!s_sinks[sink_id].used) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	memset(&s_sinks[sink_id], 0, sizeof(s_sinks[sink_id]));
	k_mutex_unlock(&s_mutex);
	return 0;
}

static size_t snapshot_text_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.emit_text != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static size_t snapshot_status_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.emit_status != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static size_t snapshot_submit_text_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.submit_text != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static size_t snapshot_get_status_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.get_status != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static size_t snapshot_get_config_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.get_config != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static size_t snapshot_set_config_sinks(
	struct lichen_app_interface_sink *snapshot, size_t snapshot_len)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_sinks) && count < snapshot_len; i++) {
		if (s_sinks[i].used && s_sinks[i].sink.set_config != NULL) {
			snapshot[count++] = s_sinks[i].sink;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

static void count_emit(bool status)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	if (status) {
		s_stats.status_emit_count++;
	} else {
		s_stats.text_emit_count++;
	}
	k_mutex_unlock(&s_mutex);
}

static void count_submit_text(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	s_stats.text_submit_count++;
	k_mutex_unlock(&s_mutex);
}

static void count_delivery(bool status)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	if (status) {
		s_stats.status_delivery_count++;
	} else {
		s_stats.text_delivery_count++;
	}
	k_mutex_unlock(&s_mutex);
}

static void count_submit_text_delivery(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	s_stats.text_submit_delivery_count++;
	k_mutex_unlock(&s_mutex);
}

static int finish_emit(bool status, size_t sinks, size_t delivered,
		       int first_error)
{
	if (sinks == 0U) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.no_subscriber_count++;
		k_mutex_unlock(&s_mutex);
		return -ENOTSUP;
	}
	k_mutex_lock(&s_mutex, K_FOREVER);
	if (first_error < 0) {
		if (first_error == -ENOMEM) {
			s_stats.backpressure_count++;
		} else {
			s_stats.subscriber_error_count++;
		}
	}
	k_mutex_unlock(&s_mutex);
	ARG_UNUSED(status);
	return delivered > 0U ? 0 : (first_error < 0 ? first_error : -EIO);
}

int lichen_app_interface_emit_text(
	const struct lichen_app_text_event *event)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	size_t delivered = 0U;
	int first_error = 0;

	if (!valid_text(event)) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
		return event != NULL &&
		       event->payload_len > CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD ?
		       -EMSGSIZE : -EINVAL;
	}

	count_emit(false);
	sink_count = snapshot_text_sinks(snapshot, ARRAY_SIZE(snapshot));
	for (size_t i = 0U; i < sink_count; i++) {
		int ret = snapshot[i].emit_text(event, snapshot[i].user_data);

		if (ret == 0) {
			delivered++;
			count_delivery(false);
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	return finish_emit(false, sink_count, delivered, first_error);
}

int lichen_app_interface_submit_text(
	const struct lichen_app_text_event *event)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	size_t delivered = 0U;
	int first_error = 0;

	if (!valid_text(event)) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
		return event != NULL &&
		       event->payload_len > CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD ?
		       -EMSGSIZE : -EINVAL;
	}

	count_submit_text();
	sink_count = snapshot_submit_text_sinks(snapshot, ARRAY_SIZE(snapshot));
	for (size_t i = 0U; i < sink_count; i++) {
		int ret = snapshot[i].submit_text(event, snapshot[i].user_data);

		if (ret == 0) {
			delivered++;
			count_submit_text_delivery();
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	return finish_emit(false, sink_count, delivered, first_error);
}

int lichen_app_interface_emit_status(
	const struct lichen_app_status_event *event)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	size_t delivered = 0U;
	int first_error = 0;

	if (event == NULL) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
		return -EINVAL;
	}

	count_emit(true);
	sink_count = snapshot_status_sinks(snapshot, ARRAY_SIZE(snapshot));
	for (size_t i = 0U; i < sink_count; i++) {
		int ret = snapshot[i].emit_status(event, snapshot[i].user_data);

		if (ret == 0) {
			delivered++;
			count_delivery(true);
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	return finish_emit(true, sink_count, delivered, first_error);
}

int lichen_app_interface_get_status(
	struct lichen_app_status_snapshot *status)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	int first_error = 0;

	if (status == NULL) {
		return -EINVAL;
	}

	sink_count = snapshot_get_status_sinks(snapshot, ARRAY_SIZE(snapshot));
	if (sink_count == 0U) {
		return -ENOTSUP;
	}
	for (size_t i = 0U; i < sink_count; i++) {
		int ret;

		memset(status, 0, sizeof(*status));
		ret = snapshot[i].get_status(status, snapshot[i].user_data);

		if (ret == 0) {
			return 0;
		}
		if (first_error == 0) {
			first_error = ret;
		}
	}
	return first_error;
}

int lichen_app_interface_get_config(
	struct lichen_app_config_snapshot *config)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	int first_error = 0;

	if (config == NULL) {
		return -EINVAL;
	}

	sink_count = snapshot_get_config_sinks(snapshot, ARRAY_SIZE(snapshot));
	if (sink_count == 0U) {
		return -ENOTSUP;
	}
	for (size_t i = 0U; i < sink_count; i++) {
		int ret = snapshot[i].get_config(config, snapshot[i].user_data);

		if (ret == 0) {
			return 0;
		}
		if (first_error == 0) {
			first_error = ret;
		}
	}
	return first_error;
}

int lichen_app_interface_set_config(
	const struct lichen_app_config_snapshot *config)
{
	struct lichen_app_interface_sink snapshot[SINK_MAX];
	size_t sink_count;
	size_t accepted = 0U;
	int first_error = 0;

	if (config == NULL) {
		return -EINVAL;
	}

	sink_count = snapshot_set_config_sinks(snapshot, ARRAY_SIZE(snapshot));
	if (sink_count == 0U) {
		return -ENOTSUP;
	}
	for (size_t i = 0U; i < sink_count; i++) {
		int ret = snapshot[i].set_config(config, snapshot[i].user_data);

		if (ret == 0) {
			accepted++;
		} else if (first_error == 0) {
			first_error = ret;
		}
	}
	return accepted > 0U ? 0 : first_error;
}

static int submit_location_with_bridge(
	const struct lichen_app_location_time_snapshot *location,
	int (*submit)(const struct lichen_app_location_time_snapshot *location))
{
	int ret;

	if (location == NULL) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
		return -EINVAL;
	}

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
	k_mutex_lock(&s_mutex, K_FOREVER);
	ret = s_test_next_location_submit_ret;
	s_test_next_location_submit_ret = 0;
	k_mutex_unlock(&s_mutex);
	if (ret != 0) {
		return ret;
	}
#endif

#if IS_ENABLED(CONFIG_LICHEN_HAL)
	ret = submit(location);
	if (ret == -EINVAL) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
	}
	return ret;
#else
	ARG_UNUSED(ret);
	ARG_UNUSED(submit);
	return -ENOTSUP;
#endif
}

int lichen_app_interface_submit_location(
	const struct lichen_app_location_time_snapshot *location)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_location_with_bridge(location,
					   lichen_app_location_submit_to_hal);
#else
	return submit_location_with_bridge(location, NULL);
#endif
}

int lichen_app_interface_submit_network_location(
	const struct lichen_app_location_time_snapshot *location)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_location_with_bridge(
		location, lichen_app_network_location_submit_to_hal);
#else
	return submit_location_with_bridge(location, NULL);
#endif
}

int lichen_app_interface_clear_network_location(void)
{
#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
	int ret;

	k_mutex_lock(&s_mutex, K_FOREVER);
	ret = s_test_next_clear_network_ret;
	s_test_next_clear_network_ret = 0;
	k_mutex_unlock(&s_mutex);
	if (ret != 0) {
		return ret;
	}
#endif

#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return lichen_app_network_location_clear_from_hal();
#else
	return -ENOTSUP;
#endif
}

int lichen_app_interface_submit_manual_location(
	const struct lichen_app_location_time_snapshot *location)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_location_with_bridge(
		location, lichen_app_manual_location_submit_to_hal);
#else
	return submit_location_with_bridge(location, NULL);
#endif
}

static int submit_time_with_bridge(
	const struct lichen_app_time_snapshot *time,
	int (*submit)(const struct lichen_app_time_snapshot *time))
{
	int ret;

	if (time == NULL) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_LICHEN_HAL)
	ret = submit(time);
	if (ret == -EINVAL) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_stats.invalid_count++;
		k_mutex_unlock(&s_mutex);
	}
	return ret;
#else
	ARG_UNUSED(ret);
	ARG_UNUSED(submit);
	return -ENOTSUP;
#endif
}

int lichen_app_interface_submit_time(const struct lichen_app_time_snapshot *time)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_time_with_bridge(time, lichen_app_time_submit_to_hal);
#else
	return submit_time_with_bridge(time, NULL);
#endif
}

int lichen_app_interface_submit_network_time(
	const struct lichen_app_time_snapshot *time)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_time_with_bridge(time, lichen_app_network_time_submit_to_hal);
#else
	return submit_time_with_bridge(time, NULL);
#endif
}

int lichen_app_interface_submit_manual_time(
	const struct lichen_app_time_snapshot *time)
{
#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return submit_time_with_bridge(time, lichen_app_manual_time_submit_to_hal);
#else
	return submit_time_with_bridge(time, NULL);
#endif
}

int lichen_app_interface_copy_stats(
	struct lichen_app_interface_stats *stats)
{
	if (stats == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	*stats = s_stats;
	k_mutex_unlock(&s_mutex);
	return 0;
}

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
void lichen_app_interface_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	memset(s_sinks, 0, sizeof(s_sinks));
	memset(&s_stats, 0, sizeof(s_stats));
	s_test_next_location_submit_ret = 0;
	s_test_next_clear_network_ret = 0;
	k_mutex_unlock(&s_mutex);
}

void lichen_app_interface_test_fail_next_location_submit(int ret)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
<<<<<<< HEAD
	s_test_next_location_submit_ret = ret;
=======
	s_test_next_location_submit_ret = ret != 0 ? ret : 0;
>>>>>>> 5daf4c1e1 (project-LICHEN-jr2k: fix)
	k_mutex_unlock(&s_mutex);
}


void lichen_app_interface_test_fail_next_clear_network(int ret)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
<<<<<<< HEAD
	s_test_next_clear_network_ret = ret;
=======
	s_test_next_clear_network_ret = ret != 0 ? ret : 0;
>>>>>>> 5daf4c1e1 (project-LICHEN-jr2k: fix)
	k_mutex_unlock(&s_mutex);
}

#endif
