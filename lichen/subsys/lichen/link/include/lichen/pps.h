/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file pps.h
 * @brief Bounded PPS edge capture and trusted GNSS-second association
 */

#ifndef LICHEN_PPS_H_
#define LICHEN_PPS_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#define LICHEN_PPS_NSEC_PER_SECOND UINT64_C(1000000000)
#define LICHEN_PPS_USEC_PER_SECOND UINT64_C(1000000)

enum lichen_pps_time_scale {
	LICHEN_PPS_TIME_SCALE_INVALID = 0,
	LICHEN_PPS_TIME_SCALE_UNIX_UTC = 1,
};

struct lichen_pps_capture_result {
	bool replaced_unassociated;
	uint64_t previous_edge_ns;
	uint64_t elapsed_intervals;
	uint64_t missed_pulses;
};

struct lichen_pps_gnss_sample {
	uint64_t unix_second;
	uint64_t message_monotonic_ns;
	uint32_t source_generation;
	enum lichen_pps_time_scale scale;
	bool time_valid;
	bool source_authenticated;
};

struct lichen_pps_association {
	uint64_t edge_monotonic_ns;
	uint64_t message_monotonic_ns;
	uint64_t unix_second;
	uint64_t unix_time_us;
	uint64_t message_delay_ns;
	uint64_t elapsed_intervals;
};

struct lichen_pps_snapshot {
	bool pending;
	uint64_t pending_edge_ns;
	bool associated;
	struct lichen_pps_association last_association;
	uint64_t replaced_edges;
	uint64_t missed_pulses;
	uint64_t rejected_edges;
	uint64_t rejected_associations;
	uint32_t source_generation;
};

/**
 * @brief PPS state stored by the caller; no dynamic allocation is performed.
 *
 * The atomic flag is a non-spinning try-lock.  Capture from an ISR is bounded
 * and returns -EBUSY if a thread is committing another transition.
 */
struct lichen_pps_associator {
	atomic_flag lock;
	bool initialized;
	uint64_t firmware_epoch_floor_s;
	uint64_t maximum_message_delay_ns;
	uint64_t maximum_edge_jitter_ns;
	uint32_t source_generation;
	bool has_last_edge;
	uint64_t last_edge_ns;
	bool has_pending_edge;
	uint64_t pending_edge_ns;
	uint64_t pending_intervals;
	bool has_last_message;
	uint64_t last_message_ns;
	bool has_last_gnss_second;
	uint64_t last_gnss_second;
	bool has_last_association;
	struct lichen_pps_association last_association;
	uint64_t replaced_edges;
	uint64_t missed_pulses;
	uint64_t rejected_edges;
	uint64_t rejected_associations;
};

int lichen_pps_associator_init(struct lichen_pps_associator *state,
			       uint64_t firmware_epoch_floor_s,
			       uint64_t maximum_message_delay_ns,
			       uint64_t maximum_edge_jitter_ns,
			       uint32_t source_generation);

/**
 * @brief Capture one rising edge without blocking or allocating.
 *
 * Edges must advance monotonically and lie within the configured jitter of an
 * integer number of seconds after the prior edge.  Multiple elapsed seconds
 * are accepted and reported as missed pulses.  A newer valid edge replaces an
 * unassociated edge, making the missed association observable.
 */
int lichen_pps_capture_edge_isr(struct lichen_pps_associator *state,
				uint64_t edge_monotonic_ns,
				struct lichen_pps_capture_result *result);

/**
 * @brief Associate the pending edge with an authenticated Unix-UTC second.
 *
 * The maximum message delay is inclusive.  Rejections retain the pending edge
 * and leave @p result unchanged.  Source changes require an explicit reset.
 */
int lichen_pps_associate(struct lichen_pps_associator *state,
			 const struct lichen_pps_gnss_sample *sample,
			 struct lichen_pps_association *result);

int lichen_pps_discard_pending(struct lichen_pps_associator *state,
			       uint64_t *discarded_edge_ns);

/**
 * @brief Clear runtime history after reboot/source change, preserving policy.
 */
int lichen_pps_associator_reset(struct lichen_pps_associator *state,
				uint32_t source_generation);

int lichen_pps_snapshot_get(struct lichen_pps_associator *state,
			    struct lichen_pps_snapshot *snapshot);

#endif /* LICHEN_PPS_H_ */
