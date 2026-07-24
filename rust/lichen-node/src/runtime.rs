// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Executor-neutral single-owner RPL runtime deadlines.

use lichen_rpl::trickle::TrickleEvent;

use crate::{RplMaintenanceOutcome, RplNode};
use crate::routing::TrickleSafeLivenessPolicy;

pub const DEFAULT_MAINTENANCE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_NEIGHBOR_TIMEOUT_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplRuntimeConfigError {
    ZeroMaintenanceInterval,
    ZeroNeighborTimeout,
    MaintenanceExceedsNeighborTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RplRuntimeConfig {
    maintenance_interval_ms: u64,
    neighbor_timeout_ms: u64,
}

impl RplRuntimeConfig {
    pub const fn new(
        maintenance_interval_ms: u64,
        neighbor_timeout_ms: u64,
    ) -> Result<Self, RplRuntimeConfigError> {
        if maintenance_interval_ms == 0 {
            return Err(RplRuntimeConfigError::ZeroMaintenanceInterval);
        }
        if neighbor_timeout_ms == 0 {
            return Err(RplRuntimeConfigError::ZeroNeighborTimeout);
        }
        if maintenance_interval_ms > neighbor_timeout_ms {
            return Err(RplRuntimeConfigError::MaintenanceExceedsNeighborTimeout);
        }
        Ok(Self {
            maintenance_interval_ms,
            neighbor_timeout_ms,
        })
    }
}

impl Default for RplRuntimeConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MAINTENANCE_INTERVAL_MS, DEFAULT_NEIGHBOR_TIMEOUT_MS)
            .expect("default RPL runtime config is valid")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RplRuntimeAction {
    Receive { timeout_ms: u32 },
    TrickleTransmit,
    TrickleExpire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RplRuntimeActionError {
    ExpectedReceive,
    ExpectedTrickleTransmit,
    ExpectedTrickleExpire,
    ActionNotPending,
    PollWithPending,
    TrickleEventChanged,
    StaleGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RplRuntimePoll {
    pub now_ms: u64,
    pub maintenance: Option<RplMaintenanceOutcome>,
    pub action: RplRuntimeAction,
    pub generation: u64,
}

/// Deadline state for a loop that keeps exclusive ownership of one RPL stack.
#[derive(Debug)]
pub struct RplRuntime {
    config: RplRuntimeConfig,
    last_now_ms: u64,
    next_maintenance_ms: Option<u64>,
    pending_action: Option<RplRuntimeAction>,
    bound_generation: u64,
}

impl RplRuntime {
    pub fn new(config: RplRuntimeConfig, now_ms: u64) -> Self {
        Self {
            config,
            last_now_ms: now_ms,
            next_maintenance_ms: now_ms.checked_add(config.maintenance_interval_ms),
            pending_action: None,
            bound_generation: 0,
        }
    }

    /// Observe the clock once, run due maintenance, and return the next loop action.
    ///
    /// Returns `PollWithPending` if a prior poll's action has not yet been completed,
    /// or `StaleGeneration` if the provided stack generation does not match the bound one.
    /// This enforces single-owner by tying RplRuntime validity to current RplStack generation.
    pub fn poll(
        &mut self,
        node: &mut RplNode,
        observed_now_ms: u64,
        stack_generation: u64,
    ) -> Result<RplRuntimePoll, RplRuntimeActionError> {
        if self.pending_action.is_some() {
            return Err(RplRuntimeActionError::PollWithPending);
        }
        if self.bound_generation != 0 && self.bound_generation != stack_generation {
            return Err(RplRuntimeActionError::StaleGeneration);
        }
        self.bound_generation = stack_generation;
        let (now_ms, maintenance) = self.observe(node, observed_now_ms);
        let action = self.next_action(node, now_ms);
        self.pending_action = Some(action);

        Ok(RplRuntimePoll {
            now_ms,
            maintenance,
            action,
            generation: stack_generation,
        })
    }

    pub(crate) fn complete_receive(
        &mut self,
        node: &mut RplNode,
        action: RplRuntimeAction,
        observed_now_ms: u64,
        stack_generation: u64,
    ) -> Result<(u64, Option<RplMaintenanceOutcome>), RplRuntimeActionError> {
        if self.bound_generation != 0 && self.bound_generation != stack_generation {
            return Err(RplRuntimeActionError::StaleGeneration);
        }
        if !matches!(action, RplRuntimeAction::Receive { .. }) {
            return Err(RplRuntimeActionError::ExpectedReceive);
        }
        self.take_pending(action)?;
        Ok(self.observe(node, observed_now_ms))
    }

    pub(crate) fn receive_timeout(
        &self,
        action: RplRuntimeAction,
        stack_generation: u64,
    ) -> Result<u32, RplRuntimeActionError> {
        if self.bound_generation != 0 && self.bound_generation != stack_generation {
            return Err(RplRuntimeActionError::StaleGeneration);
        }
        let RplRuntimeAction::Receive { timeout_ms } = action else {
            return Err(RplRuntimeActionError::ExpectedReceive);
        };
        if self.pending_action != Some(action) {
            return Err(RplRuntimeActionError::ActionNotPending);
        }
        Ok(timeout_ms)
    }

    pub(crate) fn complete_trickle_transmit(
        &mut self,
        node: &mut RplNode,
        action: RplRuntimeAction,
        observed_now_ms: u64,
        stack_generation: u64,
    ) -> Result<(Option<RplMaintenanceOutcome>, bool), RplRuntimeActionError> {
        if self.bound_generation != 0 && self.bound_generation != stack_generation {
            return Err(RplRuntimeActionError::StaleGeneration);
        }
        if action != RplRuntimeAction::TrickleTransmit {
            return Err(RplRuntimeActionError::ExpectedTrickleTransmit);
        }
        self.take_pending(action)?;
        let (now_ms, maintenance) = self.observe(node, observed_now_ms);
        if !matches!(node.poll_trickle(), TrickleEvent::Transmit { at_ms } if at_ms <= now_ms) {
            return Err(RplRuntimeActionError::TrickleEventChanged);
        }
        Ok((maintenance, node.trickle_transmit()))
    }

    pub(crate) fn complete_trickle_expire(
        &mut self,
        node: &mut RplNode,
        action: RplRuntimeAction,
        observed_now_ms: u64,
        rand_offset: u32,
        stack_generation: u64,
    ) -> Result<Option<RplMaintenanceOutcome>, RplRuntimeActionError> {
        if self.bound_generation != 0 && self.bound_generation != stack_generation {
            return Err(RplRuntimeActionError::StaleGeneration);
        }
        if action != RplRuntimeAction::TrickleExpire {
            return Err(RplRuntimeActionError::ExpectedTrickleExpire);
        }
        self.take_pending(action)?;
        let (now_ms, maintenance) = self.observe(node, observed_now_ms);
        if !matches!(node.poll_trickle(), TrickleEvent::Expire { at_ms } if at_ms <= now_ms) {
            return Err(RplRuntimeActionError::TrickleEventChanged);
        }
        node.trickle_expire(now_ms, rand_offset);
        Ok(maintenance)
    }

    fn observe(
        &mut self,
        node: &mut RplNode,
        observed_now_ms: u64,
    ) -> (u64, Option<RplMaintenanceOutcome>) {
        let now_ms = self.last_now_ms.max(observed_now_ms);
        self.last_now_ms = now_ms;

        let maintenance = if self
            .next_maintenance_ms
            .is_some_and(|deadline| now_ms >= deadline)
        {
            let outcome = node.maintain(now_ms, self.config.neighbor_timeout_ms, &());
            self.next_maintenance_ms = self.next_maintenance_after(now_ms);
            Some(outcome)
        } else {
            None
        };
        (now_ms, maintenance)
    }

    fn next_action(&self, node: &RplNode, now_ms: u64) -> RplRuntimeAction {
        let trickle = node.poll_trickle();
        match trickle {
            TrickleEvent::Transmit { at_ms } if at_ms <= now_ms => {
                RplRuntimeAction::TrickleTransmit
            }
            TrickleEvent::Expire { at_ms } if at_ms <= now_ms => RplRuntimeAction::TrickleExpire,
            TrickleEvent::Stopped if self.next_maintenance_ms.is_none() => {
                RplRuntimeAction::Receive {
                    timeout_ms: u32::MAX,
                }
            }
            _ => {
                let trickle_deadline = match trickle {
                    TrickleEvent::Transmit { at_ms } | TrickleEvent::Expire { at_ms } => at_ms,
                    TrickleEvent::Stopped => u64::MAX,
                };
                let deadline_ms = self
                    .next_maintenance_ms
                    .map_or(trickle_deadline, |maintenance| {
                        maintenance.min(trickle_deadline)
                    });
                let timeout_ms = deadline_ms.saturating_sub(now_ms).min(u64::from(u32::MAX));
                RplRuntimeAction::Receive {
                    timeout_ms: timeout_ms as u32,
                }
            }
        }
    }

    fn next_maintenance_after(&self, now_ms: u64) -> Option<u64> {
        let deadline = self.next_maintenance_ms?;
        let elapsed = now_ms.saturating_sub(deadline);
        let intervals = elapsed / self.config.maintenance_interval_ms + 1;
        self.config
            .maintenance_interval_ms
            .checked_mul(intervals)
            .and_then(|advance| deadline.checked_add(advance))
    }

    fn take_pending(&mut self, action: RplRuntimeAction) -> Result<(), RplRuntimeActionError> {
        if self.pending_action != Some(action) {
            return Err(RplRuntimeActionError::ActionNotPending);
        }
        self.pending_action = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::addr::NodeId;
    use lichen_core::constants::RPL_INSTANCE_ID;
    use lichen_link::{identity::Identity, keys::Seed};
    use lichen_rpl::message::Dio;
    use lichen_rpl::routing::DaoManager;

    use crate::{Node, Router};

    fn node() -> RplNode {
        let node_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 2]);
        RplNode::new(
            node_id,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        )
    }

    fn root() -> RplNode {
        let node_id = NodeId([0x02, 0, 0, 0, 0, 0, 0, 1]);
        let address = node_id.link_local_addr().0;
        RplNode {
            node: Node::new(node_id),
            router: Router::new_root(address),
        }
    }

    #[test]
    fn config_rejects_zero_and_maintenance_above_timeout() {
        assert_eq!(
            RplRuntimeConfig::new(0, 10_000),
            Err(RplRuntimeConfigError::ZeroMaintenanceInterval)
        );
        assert_eq!(
            RplRuntimeConfig::new(1_000, 0),
            Err(RplRuntimeConfigError::ZeroNeighborTimeout)
        );
        assert_eq!(
            RplRuntimeConfig::new(10_001, 10_000),
            Err(RplRuntimeConfigError::MaintenanceExceedsNeighborTimeout)
        );
    }

    #[test]
    fn receive_poll_is_bounded_by_literal_trickle_deadline() {
        let mut node = node();
        node.trickle_start(100, 0);
        let mut runtime = RplRuntime::new(RplRuntimeConfig::default(), 100);

        let p1 = runtime.poll(&mut node, 100, 1).unwrap();
        assert_eq!(
            p1.action,
            RplRuntimeAction::Receive { timeout_ms: 4 }
        );
        let _ = runtime.complete_receive(&mut node, p1.action, 104, 1).unwrap();
        let p2 = runtime.poll(&mut node, 104, 1).unwrap();
        assert_eq!(p2.action, RplRuntimeAction::TrickleTransmit);
    }

    #[test]
    fn backward_clock_is_clamped_for_maintenance_and_poll_deadline() {
        let mut node = node();
        let config = RplRuntimeConfig::new(1_000, 10_000).unwrap();
        let mut runtime = RplRuntime::new(config, 5_000);

        let poll = runtime.poll(&mut node, 4_000, 1).unwrap();
        assert_eq!(poll.now_ms, 5_000);
        assert_eq!(poll.maintenance, None);
        assert_eq!(poll.action, RplRuntimeAction::Receive { timeout_ms: 1_000 });
    }

    #[test]
    fn maintenance_runs_at_exact_boundary_and_keeps_original_cadence() {
        let mut node = node();
        let config = RplRuntimeConfig::new(1_000, 10_000).unwrap();
        let mut runtime = RplRuntime::new(config, 0);

        let p1 = runtime.poll(&mut node, 999, 1).unwrap();
        assert_eq!(p1.maintenance, None);
        let _ = runtime.complete_receive(&mut node, p1.action, 999, 1).unwrap();

        let p2 = runtime.poll(&mut node, 1_000, 1).unwrap();
        assert_eq!(
            p2.maintenance,
            Some(RplMaintenanceOutcome::default())
        );
        let _ = runtime.complete_receive(&mut node, p2.action, 1_000, 1).unwrap();

        let delayed = runtime.poll(&mut node, 2_500, 1).unwrap();
        assert_eq!(delayed.maintenance, Some(RplMaintenanceOutcome::default()));
        assert_eq!(
            delayed.action,
            RplRuntimeAction::Receive { timeout_ms: 500 }
        );
    }

    #[test]
    fn terminal_deadline_runs_once_then_uses_nonzero_saturated_poll() {
        let mut node = node();
        let config = RplRuntimeConfig::new(10, 10).unwrap();
        let mut runtime = RplRuntime::new(config, u64::MAX - 20);

        let p1 = runtime.poll(&mut node, u64::MAX - 11, 1).unwrap();
        assert_eq!(
            p1.action,
            RplRuntimeAction::Receive { timeout_ms: 1 }
        );
        let _ = runtime.complete_receive(&mut node, p1.action, u64::MAX - 11, 1).unwrap();

        let p2 = runtime.poll(&mut node, u64::MAX - 10, 1).unwrap();
        assert!(p2.maintenance.is_some());
        let _ = runtime.complete_receive(&mut node, p2.action, u64::MAX - 10, 1).unwrap();

        let terminal = runtime.poll(&mut node, u64::MAX, 1).unwrap();
        assert!(terminal.maintenance.is_some());
        assert_eq!(
            terminal.action,
            RplRuntimeAction::Receive {
                timeout_ms: u32::MAX
            }
        );
        let _ = runtime.complete_receive(&mut node, terminal.action, u64::MAX, 1).unwrap();
        let repeated = runtime.poll(&mut node, u64::MAX, 1).unwrap();
        assert_eq!(repeated.maintenance, None);
        assert_eq!(repeated.action, terminal.action);
    }

    #[test]
    fn runtime_expires_idle_dao_at_exact_literal_boundary() {
        let mut node = root();
        let root_addr = node.node().node_id.link_local_addr().0;
        let identity = Identity::from_seed(Seed::new([2; 32]));
        let mut target = [0u8; 16];
        target[..2].copy_from_slice(&[0xfe, 0x80]);
        target[8..].copy_from_slice(&identity.iid);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        assert!(node.router.set_dao_lifetime_unit(1));
        assert!(node.router.process_dao_at_ms(&dao, target, target, 1_000));
        let mut runtime = RplRuntime::new(RplRuntimeConfig::new(1_000, 10_000).unwrap(), 1_000);

        let p1 = runtime.poll(&mut node, 1_999, 1).unwrap();
        assert_eq!(p1.maintenance, None);
        let _ = runtime.complete_receive(&mut node, p1.action, 1_999, 1).unwrap();
        assert!(node.router.lookup_route(&target).is_some());

        let p2 = runtime.poll(&mut node, 2_000, 1).unwrap();
        assert!(p2.maintenance.unwrap().routes_expired);
        let _ = runtime.complete_receive(&mut node, p2.action, 2_000, 1).unwrap();
        assert!(node.router.lookup_route(&target).is_none());
    }

    #[test]
    fn runtime_prunes_neighbor_only_after_literal_timeout() {
        let mut node = node();
        let root_addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: crate::routing::ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let mut wire = [0u8; Dio::BASE_LEN];
        dio.write_to(&mut wire).unwrap();
        assert!(node.router.process_dio(&dio, &wire, root_addr, -40, 0));
        let mut runtime = RplRuntime::new(RplRuntimeConfig::new(1, 10_000).unwrap(), 0);

        let p1 = runtime.poll(&mut node, 10_000, 1).unwrap();
        assert!(!p1.maintenance.unwrap().neighbors_pruned);
        let _ = runtime.complete_receive(&mut node, p1.action, 10_000, 1).unwrap();
        assert_eq!(node.router.neighbors().count(), 1);
        let p2 = runtime.poll(&mut node, 10_001, 1).unwrap();
        assert!(p2.maintenance.unwrap().neighbors_pruned);
        let _ = runtime.complete_receive(&mut node, p2.action, 10_001, 1).unwrap();
        assert_eq!(node.router.neighbors().count(), 0);
    }
}
