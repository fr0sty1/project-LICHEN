// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! RplRuntime integration for executor-neutral control loops.

use lichen_hal::{NonVolatile, Radio};

use crate::routing::TrickleSafeLivenessPolicy;
use crate::runtime::{RplRuntime, RplRuntimeAction, RplRuntimeActionError, RplRuntimePoll};
use crate::stack::{RxError, MAX_FRAME_SIZE};
use crate::routing::RplMaintenanceOutcome;

use super::error::{RplReceiveError, RplRuntimeReceiveError, RplRuntimeTrickleError};
use super::RplTrickleTransmitOutcome;
use super::util::RPL_ALL_NODES;
use super::{RplRuntimeReceiveOutcome, RplStack};

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    /// Run DAO-route and neighbor maintenance from one monotonic observation.
    ///
    /// This is an advanced caller-clock API. Production single-owner loops should
    /// use [`Self::runtime_poll`] so clock clamping and cadence remain centralized.
    pub fn maintain<P: TrickleSafeLivenessPolicy>(
        &mut self,
        now_ms: u64,
        neighbor_timeout_ms: u64,
        policy: &P,
    ) -> RplMaintenanceOutcome {
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        self.rpl.maintain(now_ms, neighbor_timeout_ms, policy)
    }

    /// Advance an executor-neutral runtime using this stack as the single owner.
    ///
    /// Binds the runtime to this stack's current generation (incremented on
    /// construction/reset/provision). Returns `PollWithPending` or `StaleGeneration`.
    pub fn runtime_poll(
        &mut self,
        runtime: &mut RplRuntime,
        observed_now_ms: u64,
    ) -> Result<RplRuntimePoll, RplRuntimeActionError> {
        self.routing_now_ms = self.routing_now_ms.max(observed_now_ms);
        runtime.poll(&mut self.rpl, observed_now_ms, self.generation)
    }

    /// Complete a planned receive using a clock sampled after the radio await.
    pub async fn runtime_receive<F>(
        &mut self,
        runtime: &mut RplRuntime,
        action: RplRuntimeAction,
        observe_now_ms: F,
    ) -> Result<RplRuntimeReceiveOutcome, RplRuntimeReceiveError>
    where
        F: FnOnce() -> u64,
    {
        let timeout_ms = runtime
            .receive_timeout(action, self.generation)
            .map_err(RplRuntimeReceiveError::Action)?;
        let mut wire = [0u8; MAX_FRAME_SIZE];
        let channel = self.stack.channel();
        let rx = self.stack.radio().receive(channel, &mut wire, timeout_ms).await;
        let post_await_ms = observe_now_ms();
        let received = match rx {
            Ok(Some(packet)) => {
                if packet.len > wire.len() {
                    let (now_ms, _maintenance) = runtime
                        .complete_receive(&mut self.rpl, action, post_await_ms, self.generation)
                        .map_err(RplRuntimeReceiveError::Action)?;
                    self.routing_now_ms = self.routing_now_ms.max(now_ms);
                    return Err(RplRuntimeReceiveError::Receive(RplReceiveError::Receive(
                        RxError::RadioPacketTooLarge,
                    )));
                }
                let process_result = self
                    .process_received(&wire[..packet.len], packet, post_await_ms)
                    .await
                    .map_err(RplRuntimeReceiveError::Receive);
                match process_result {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        let _ = runtime.complete_receive(
                            &mut self.rpl,
                            action,
                            post_await_ms,
                            self.generation,
                        );
                        return Err(e);
                    }
                }
            }
            Ok(None) => None,
            Err(_) => {
                let (now_ms, _maintenance) = runtime
                    .complete_receive(&mut self.rpl, action, post_await_ms, self.generation)
                    .map_err(RplRuntimeReceiveError::Action)?;
                self.routing_now_ms = self.routing_now_ms.max(now_ms);
                return Err(RplRuntimeReceiveError::Receive(RplReceiveError::Receive(
                    RxError::RadioRx,
                )));
            }
        };
        let (now_ms, maintenance) = runtime
            .complete_receive(&mut self.rpl, action, post_await_ms, self.generation)
            .map_err(RplRuntimeReceiveError::Action)?;
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        Ok(RplRuntimeReceiveOutcome {
            now_ms,
            maintenance,
            received,
            generation: self.generation,
        })
    }

    /// Complete a due Trickle transmit, including suppression and multicast policy.
    pub async fn runtime_complete_trickle_transmit(
        &mut self,
        runtime: &mut RplRuntime,
        action: RplRuntimeAction,
        observed_now_ms: u64,
    ) -> Result<RplTrickleTransmitOutcome, RplRuntimeTrickleError> {
        self.routing_now_ms = self.routing_now_ms.max(observed_now_ms);
        let (_, should_transmit) = runtime
            .complete_trickle_transmit(&mut self.rpl, action, observed_now_ms, self.generation)
            .map_err(RplRuntimeTrickleError::Action)?;
        if !should_transmit {
            return Ok(RplTrickleTransmitOutcome::Suppressed);
        }
        self.send_dio(RPL_ALL_NODES)
            .await
            .map_err(RplRuntimeTrickleError::Transmit)?;
        Ok(RplTrickleTransmitOutcome::Sent)
    }

    /// Complete a due Trickle interval expiry with caller-supplied random offset.
    pub fn runtime_complete_trickle_expire(
        &mut self,
        runtime: &mut RplRuntime,
        action: RplRuntimeAction,
        observed_now_ms: u64,
        rand_offset: u32,
    ) -> Result<Option<RplMaintenanceOutcome>, RplRuntimeTrickleError> {
        self.routing_now_ms = self.routing_now_ms.max(observed_now_ms);
        runtime
            .complete_trickle_expire(
                &mut self.rpl,
                action,
                observed_now_ms,
                rand_offset,
                self.generation,
            )
            .map_err(RplRuntimeTrickleError::Action)
    }

    /// Low-level Trickle initialization for callers that own timer state.
    pub fn trickle_start(&mut self, now_ms: u64, rand_offset: u32) {
        self.bump_generation();
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        self.rpl.trickle_start(now_ms, rand_offset);
    }

    /// Low-level Trickle reset for callers that own timer state.
    pub fn trickle_reset(&mut self, now_ms: u64, rand_offset: u32) {
        self.bump_generation();
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        self.rpl.trickle_reset(now_ms, rand_offset);
    }

    /// Prefer [`Self::runtime_complete_trickle_expire`] in production loops.
    pub fn trickle_expire(&mut self, now_ms: u64, rand_offset: u32) {
        self.bump_generation();
        self.routing_now_ms = self.routing_now_ms.max(now_ms);
        self.rpl.trickle_expire(now_ms, rand_offset);
    }

    /// Prefer [`Self::runtime_complete_trickle_transmit`] in production loops.
    pub fn trickle_transmit(&mut self) -> bool {
        self.rpl.trickle_transmit()
    }
}
