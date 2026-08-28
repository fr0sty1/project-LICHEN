//! Bounded CoAP Observe state machines (RFC 7641).
//!
//! The transport owns sockets and timers. This module owns only protocol state:
//! registrations, 24-bit sequence ordering, cached confirmable notifications,
//! cancellation, retry scheduling, and expiry. All storage is fixed-capacity so
//! the same implementation can be used by `no_std` nodes and gateway clients.

use crate::codec::{CoapBuilder, CoapError, CoapOption, MAX_TOKEN_LEN};
use crate::message::MessageType;
use crate::option::OptionNumber;

/// Largest Observe value (RFC 7641 section 3.4: 24-bit unsigned integer).
pub const OBSERVE_MAX_VALUE: u32 = 0x00ff_ffff;
/// Half of the 24-bit serial space. A difference exactly this large is ambiguous.
pub const OBSERVE_HALF_RANGE: u32 = 0x0080_0000;
/// RFC 7641 section 4.4 freshness fallback.
pub const OBSERVE_FRESHNESS_TIMEOUT_MS: u64 = 128_000;

/// Observe processing error. Operations returning an error leave state unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveError {
    /// Observe option is non-minimal, longer than three bytes, or out of range.
    InvalidObserveValue,
    /// A request Observe value is neither registration (0) nor deregistration (1).
    InvalidRequestValue,
    /// Token exceeds the RFC 7252 eight-byte limit.
    TokenTooLong,
    /// Fixed observer/subscription capacity is exhausted.
    RegistryFull,
    /// Relationship was not found.
    NotFound,
    /// A confirmable notification is already in flight for this observer.
    Backpressure,
    /// Cached wire message exceeds the configured fixed buffer.
    PacketTooLarge,
    /// Notification sequence is stale or equal to the previous publication.
    StaleSequence,
    /// Sequence difference is exactly half the serial space.
    AmbiguousSequence,
    /// Resource does not match the registered relationship.
    WrongResource,
    /// A non-initial Block2 response attempted to carry Observe state, or arrived
    /// before the Observe relationship was established.
    InvalidBlockwise,
    /// Timeout must be non-zero.
    InvalidTimeout,
}

impl core::fmt::Display for ObserveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::InvalidObserveValue => "invalid Observe option value",
            Self::InvalidRequestValue => "invalid Observe request value",
            Self::TokenTooLong => "Observe token exceeds eight bytes",
            Self::RegistryFull => "Observe registry is full",
            Self::NotFound => "Observe relationship not found",
            Self::Backpressure => "Observe notification already in flight",
            Self::PacketTooLarge => "Observe notification exceeds fixed buffer",
            Self::StaleSequence => "Observe sequence is not newer",
            Self::AmbiguousSequence => "Observe sequence is half-range ambiguous",
            Self::WrongResource => "Observe resource does not match registration",
            Self::InvalidBlockwise => "invalid Observe/Block2 boundary",
            Self::InvalidTimeout => "Observe timeout must be non-zero",
        };
        f.write_str(text)
    }
}

impl core::error::Error for ObserveError {}

/// Registration meaning of an Observe request option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveRequest {
    /// GET with Observe=0 establishes or refreshes a relationship.
    Register,
    /// GET with Observe=1 removes the matching relationship.
    Deregister,
}

impl ObserveRequest {
    /// Decode the request option. `None` means this is not an Observe request.
    pub fn decode(option: Option<&[u8]>) -> Result<Option<Self>, ObserveError> {
        let Some(option) = option else {
            return Ok(None);
        };
        match decode_observe_value(option)? {
            0 => Ok(Some(Self::Register)),
            1 => Ok(Some(Self::Deregister)),
            _ => Err(ObserveError::InvalidRequestValue),
        }
    }
}

/// Decode a minimally encoded 0..=0xffffff Observe value.
pub fn decode_observe_value(value: &[u8]) -> Result<u32, ObserveError> {
    if value.len() > 3 || value.first() == Some(&0) {
        return Err(ObserveError::InvalidObserveValue);
    }
    let mut decoded = 0u32;
    for byte in value {
        decoded = (decoded << 8) | u32::from(*byte);
    }
    Ok(decoded)
}

fn encode_observe_value(value: u32) -> Result<([u8; 3], usize), ObserveError> {
    if value > OBSERVE_MAX_VALUE {
        return Err(ObserveError::InvalidObserveValue);
    }
    let bytes = value.to_be_bytes();
    let length = if value == 0 {
        0
    } else if value <= 0xff {
        1
    } else if value <= 0xffff {
        2
    } else {
        3
    };
    let mut encoded = [0u8; 3];
    if length > 0 {
        encoded[..length].copy_from_slice(&bytes[4 - length..]);
    }
    Ok((encoded, length))
}

impl CoapOption<'_> {
    /// True for option number 6.
    pub fn is_observe(&self) -> bool {
        self.number == OptionNumber::Observe as u16
    }

    /// Decode this option as a canonical Observe value.
    pub fn as_observe(&self) -> Result<u32, ObserveError> {
        if !self.is_observe() {
            return Err(ObserveError::InvalidObserveValue);
        }
        decode_observe_value(self.value)
    }
}

impl CoapBuilder<'_> {
    /// Append a canonical Observe option. Options must still be supplied in
    /// numeric order as required by [`CoapBuilder::option`].
    pub fn observe(&mut self, value: u32) -> Result<&mut Self, CoapError> {
        let (encoded, length) =
            encode_observe_value(value).map_err(|_| CoapError::UintOptionTooLong)?;
        self.option(OptionNumber::Observe as u16, &encoded[..length])
    }
}

/// A validated 24-bit Observe sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserveSequence(u32);

impl ObserveSequence {
    /// Validate a sequence value.
    pub fn new(value: u32) -> Result<Self, ObserveError> {
        if value > OBSERVE_MAX_VALUE {
            return Err(ObserveError::InvalidObserveValue);
        }
        Ok(Self(value))
    }

    /// Numeric value.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Advance modulo 2^24.
    pub const fn next(self) -> Self {
        Self((self.0 + 1) & OBSERVE_MAX_VALUE)
    }

    /// Compare with a previously accepted sequence using 24-bit serial arithmetic.
    pub const fn relation_to(self, previous: Self) -> SequenceRelation {
        let difference = self.0.wrapping_sub(previous.0) & OBSERVE_MAX_VALUE;
        if difference == 0 {
            SequenceRelation::Equal
        } else if difference < OBSERVE_HALF_RANGE {
            SequenceRelation::Newer
        } else if difference == OBSERVE_HALF_RANGE {
            SequenceRelation::Ambiguous
        } else {
            SequenceRelation::Older
        }
    }
}

/// RFC 7641 24-bit sequence relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceRelation {
    Equal,
    Newer,
    Older,
    Ambiguous,
}

/// Endpoint and token that uniquely identify one Observe relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserveKey<Peer> {
    peer: Peer,
    token: [u8; MAX_TOKEN_LEN],
    token_len: u8,
}

impl<Peer: Copy> ObserveKey<Peer> {
    pub fn new(peer: Peer, token: &[u8]) -> Result<Self, ObserveError> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(ObserveError::TokenTooLong);
        }
        let mut stored = [0u8; MAX_TOKEN_LEN];
        stored[..token.len()].copy_from_slice(token);
        Ok(Self {
            peer,
            token: stored,
            token_len: token.len() as u8,
        })
    }

    pub const fn peer(&self) -> Peer {
        self.peer
    }

    pub fn token(&self) -> &[u8] {
        &self.token[..usize::from(self.token_len)]
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingNotification<const MAX_WIRE: usize> {
    sequence: ObserveSequence,
    message_id: u16,
    wire: [u8; MAX_WIRE],
    wire_len: usize,
    confirmable: bool,
    attempts: u8,
    due_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct ServerObserver<Peer, const MAX_WIRE: usize> {
    key: ObserveKey<Peer>,
    resource: u16,
    expires_at_ms: u64,
    last_sequence: Option<ObserveSequence>,
    pending: Option<PendingNotification<MAX_WIRE>>,
}

/// Immutable observer description returned during resource dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverInfo<Peer> {
    pub key: ObserveKey<Peer>,
    pub resource: u16,
}

/// One exact cached datagram selected for initial send or retransmission.
#[derive(Clone, Copy, Debug)]
pub struct ObserveDelivery<Peer, const MAX_WIRE: usize> {
    pub key: ObserveKey<Peer>,
    pub sequence: ObserveSequence,
    pub message_id: u16,
    wire: [u8; MAX_WIRE],
    wire_len: usize,
    /// Confirmable notifications remain cached until ACK/RST or retry exhaustion.
    pub confirmable: bool,
    /// False on the initial transmission; true on every retry.
    pub retransmission: bool,
}

impl<Peer, const MAX_WIRE: usize> ObserveDelivery<Peer, MAX_WIRE> {
    pub fn wire(&self) -> &[u8] {
        &self.wire[..self.wire_len]
    }
}

/// Complete input for atomically caching one server notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerNotification<'a> {
    pub resource: u16,
    pub sequence: ObserveSequence,
    pub message_id: u16,
    pub confirmable: bool,
    pub wire: &'a [u8],
    pub now_ms: u64,
}

/// Fixed-capacity server-side observer registry.
pub struct ObserveServer<Peer, const OBSERVERS: usize, const MAX_WIRE: usize> {
    entries: [Option<ServerObserver<Peer, MAX_WIRE>>; OBSERVERS],
    idle_timeout_ms: u64,
    ack_timeout_ms: u64,
    max_retransmit: u8,
}

impl<Peer: Copy + Eq, const OBSERVERS: usize, const MAX_WIRE: usize>
    ObserveServer<Peer, OBSERVERS, MAX_WIRE>
{
    pub fn new(
        idle_timeout_ms: u64,
        ack_timeout_ms: u64,
        max_retransmit: u8,
    ) -> Result<Self, ObserveError> {
        if idle_timeout_ms == 0 || ack_timeout_ms == 0 {
            return Err(ObserveError::InvalidTimeout);
        }
        Ok(Self {
            entries: [None; OBSERVERS],
            idle_timeout_ms,
            ack_timeout_ms,
            max_retransmit,
        })
    }

    /// Register or atomically replace a relationship with the same endpoint/token.
    pub fn register(
        &mut self,
        key: ObserveKey<Peer>,
        resource: u16,
        now_ms: u64,
    ) -> Result<(), ObserveError> {
        let replacement = ServerObserver {
            key,
            resource,
            expires_at_ms: deadline(now_ms, self.idle_timeout_ms),
            last_sequence: None,
            pending: None,
        };
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|item| item.key == key))
        {
            *entry = Some(replacement);
            return Ok(());
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(ObserveError::RegistryFull)?;
        *slot = Some(replacement);
        Ok(())
    }

    /// Remove a relationship because of Observe=1 or local cancellation.
    pub fn deregister(&mut self, key: &ObserveKey<Peer>) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|item| item.key == *key))
        {
            *entry = None;
            true
        } else {
            false
        }
    }

    pub fn contains(&self, key: &ObserveKey<Peer>) -> bool {
        self.entries.iter().flatten().any(|entry| entry.key == *key)
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot iterator used by a resource to dispatch one notification to each
    /// matching observer without exposing mutable registry storage.
    pub fn observers(&self, resource: u16) -> impl Iterator<Item = ObserverInfo<Peer>> + '_ {
        self.entries.iter().filter_map(move |entry| {
            let entry = entry.as_ref()?;
            (entry.resource == resource).then_some(ObserverInfo {
                key: entry.key,
                resource,
            })
        })
    }

    /// Cache an exact encoded message before its first send. Confirmable retries
    /// are returned byte-for-byte from this cache and never rebuilt.
    pub fn queue_notification(
        &mut self,
        key: &ObserveKey<Peer>,
        notification: ServerNotification<'_>,
    ) -> Result<(), ObserveError> {
        if notification.wire.len() > MAX_WIRE {
            return Err(ObserveError::PacketTooLarge);
        }
        let entry = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.key == *key)
            .ok_or(ObserveError::NotFound)?;
        if entry.resource != notification.resource {
            return Err(ObserveError::WrongResource);
        }
        if entry.pending.is_some() {
            return Err(ObserveError::Backpressure);
        }
        if let Some(previous) = entry.last_sequence {
            match notification.sequence.relation_to(previous) {
                SequenceRelation::Newer => {}
                SequenceRelation::Ambiguous => return Err(ObserveError::AmbiguousSequence),
                SequenceRelation::Equal | SequenceRelation::Older => {
                    return Err(ObserveError::StaleSequence)
                }
            }
        }
        let mut cached = [0u8; MAX_WIRE];
        cached[..notification.wire.len()].copy_from_slice(notification.wire);
        entry.pending = Some(PendingNotification {
            sequence: notification.sequence,
            message_id: notification.message_id,
            wire: cached,
            wire_len: notification.wire.len(),
            confirmable: notification.confirmable,
            attempts: 0,
            due_at_ms: notification.now_ms,
        });
        entry.last_sequence = Some(notification.sequence);
        entry.expires_at_ms = deadline(notification.now_ms, self.idle_timeout_ms);
        Ok(())
    }

    /// Return and schedule the next due exact datagram. When retry capacity is
    /// exhausted the relationship is removed and scanning continues.
    pub fn next_due(&mut self, now_ms: u64) -> Option<ObserveDelivery<Peer, MAX_WIRE>> {
        for slot in &mut self.entries {
            let Some(entry) = slot.as_mut() else {
                continue;
            };
            let Some(pending) = entry.pending.as_mut() else {
                continue;
            };
            if now_ms < pending.due_at_ms {
                continue;
            }
            let permitted_attempts = self.max_retransmit.saturating_add(1);
            if pending.attempts >= permitted_attempts {
                *slot = None;
                continue;
            }
            let delivery = ObserveDelivery {
                key: entry.key,
                sequence: pending.sequence,
                message_id: pending.message_id,
                wire: pending.wire,
                wire_len: pending.wire_len,
                confirmable: pending.confirmable,
                retransmission: pending.attempts > 0,
            };
            if !pending.confirmable {
                entry.pending = None;
                return Some(delivery);
            }
            pending.attempts = pending.attempts.saturating_add(1);
            pending.due_at_ms = deadline(now_ms, self.ack_timeout_ms);
            return Some(delivery);
        }
        None
    }

    /// ACK clears only the cached notification; the Observe relationship remains.
    pub fn acknowledge(&mut self, peer: Peer, message_id: u16, now_ms: u64) -> bool {
        if let Some(entry) = self.entries.iter_mut().flatten().find(|entry| {
            entry.key.peer == peer
                && entry
                    .pending
                    .is_some_and(|pending| pending.message_id == message_id)
        }) {
            entry.pending = None;
            entry.expires_at_ms = deadline(now_ms, self.idle_timeout_ms);
            true
        } else {
            false
        }
    }

    /// RST rejects the notification and removes the complete relationship.
    pub fn reset(&mut self, peer: Peer, message_id: u16) -> bool {
        if let Some(slot) = self.entries.iter_mut().find(|entry| {
            entry.as_ref().is_some_and(|item| {
                item.key.peer == peer
                    && item
                        .pending
                        .is_some_and(|pending| pending.message_id == message_id)
            })
        }) {
            *slot = None;
            true
        } else {
            false
        }
    }

    /// Remove idle relationships. Returns the number removed.
    pub fn cleanup(&mut self, now_ms: u64) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|item| now_ms >= item.expires_at_ms)
            {
                *entry = None;
                removed += 1;
            }
        }
        removed
    }
}

#[derive(Clone, Copy, Debug)]
enum ClientState {
    Registering,
    Established {
        sequence: ObserveSequence,
        received_at_ms: u64,
    },
}

#[derive(Clone, Copy, Debug)]
struct ClientSubscription<Peer> {
    key: ObserveKey<Peer>,
    resource: u16,
    expires_at_ms: u64,
    last_message_id: Option<u16>,
    state: ClientState,
}

/// Metadata needed to classify one response or notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientNotification {
    pub message_type: MessageType,
    pub message_id: u16,
    /// Observe value. It is absent on non-initial Block2 continuation blocks.
    pub observe: Option<u32>,
    /// Block2 number, if present.
    pub block2_num: Option<u32>,
    /// Relationship inactivity timeout selected by the caller/resource policy.
    pub max_age_ms: u64,
}

/// Result of processing a client-side notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    Registered(ObserveSequence),
    Notification {
        sequence: ObserveSequence,
        /// RFC 7641's 128-second fallback, rather than serial ordering, made it fresh.
        fresh_by_time: bool,
    },
    Duplicate,
    Stale,
    Ambiguous,
    BlockContinuation,
    Terminated,
}

/// Fixed-capacity client-side subscription registry.
pub struct ObserveClient<Peer, const SUBSCRIPTIONS: usize> {
    entries: [Option<ClientSubscription<Peer>>; SUBSCRIPTIONS],
}

impl<Peer: Copy + Eq, const SUBSCRIPTIONS: usize> ObserveClient<Peer, SUBSCRIPTIONS> {
    pub const fn new() -> Self {
        Self {
            entries: [None; SUBSCRIPTIONS],
        }
    }

    /// Begin or replace a registration before sending GET Observe=0.
    pub fn subscribe(
        &mut self,
        key: ObserveKey<Peer>,
        resource: u16,
        now_ms: u64,
        registration_timeout_ms: u64,
    ) -> Result<(), ObserveError> {
        if registration_timeout_ms == 0 {
            return Err(ObserveError::InvalidTimeout);
        }
        let subscription = ClientSubscription {
            key,
            resource,
            expires_at_ms: deadline(now_ms, registration_timeout_ms),
            last_message_id: None,
            state: ClientState::Registering,
        };
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|item| item.key == key))
        {
            *slot = Some(subscription);
            return Ok(());
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(ObserveError::RegistryFull)?;
        *slot = Some(subscription);
        Ok(())
    }

    pub fn cancel(&mut self, key: &ObserveKey<Peer>) -> bool {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|item| item.key == *key))
        {
            *slot = None;
            true
        } else {
            false
        }
    }

    pub fn contains(&self, key: &ObserveKey<Peer>) -> bool {
        self.entries.iter().flatten().any(|entry| entry.key == *key)
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Process an initial response, notification, terminal response, or a
    /// non-initial Block2 continuation. Stale/ambiguous inputs never advance state.
    pub fn process(
        &mut self,
        key: &ObserveKey<Peer>,
        resource: u16,
        notification: ClientNotification,
        now_ms: u64,
    ) -> Result<ClientEvent, ObserveError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|item| item.key == *key))
            .ok_or(ObserveError::NotFound)?;
        let current = self.entries[index].ok_or(ObserveError::NotFound)?;
        if current.resource != resource {
            return Err(ObserveError::WrongResource);
        }
        if notification.message_type == MessageType::Reset {
            self.entries[index] = None;
            return Ok(ClientEvent::Terminated);
        }
        if notification.max_age_ms == 0 {
            return Err(ObserveError::InvalidTimeout);
        }
        if notification.block2_num.is_some_and(|number| number > 0) {
            if notification.observe.is_some()
                || !matches!(current.state, ClientState::Established { .. })
            {
                return Err(ObserveError::InvalidBlockwise);
            }
            let entry = self.entries[index].as_mut().ok_or(ObserveError::NotFound)?;
            entry.expires_at_ms = deadline(now_ms, notification.max_age_ms);
            entry.last_message_id = Some(notification.message_id);
            return Ok(ClientEvent::BlockContinuation);
        }
        let Some(raw_sequence) = notification.observe else {
            self.entries[index] = None;
            return Ok(ClientEvent::Terminated);
        };
        let sequence = ObserveSequence::new(raw_sequence)?;
        let event = match current.state {
            ClientState::Registering => ClientEvent::Registered(sequence),
            ClientState::Established {
                sequence: previous,
                received_at_ms,
            } => {
                let elapsed = now_ms.saturating_sub(received_at_ms);
                match sequence.relation_to(previous) {
                    SequenceRelation::Newer => ClientEvent::Notification {
                        sequence,
                        fresh_by_time: false,
                    },
                    _ if elapsed > OBSERVE_FRESHNESS_TIMEOUT_MS => ClientEvent::Notification {
                        sequence,
                        fresh_by_time: true,
                    },
                    SequenceRelation::Equal => return Ok(ClientEvent::Duplicate),
                    SequenceRelation::Older => return Ok(ClientEvent::Stale),
                    SequenceRelation::Ambiguous => return Ok(ClientEvent::Ambiguous),
                }
            }
        };
        let entry = self.entries[index].as_mut().ok_or(ObserveError::NotFound)?;
        entry.state = ClientState::Established {
            sequence,
            received_at_ms: now_ms,
        };
        entry.expires_at_ms = deadline(now_ms, notification.max_age_ms);
        entry.last_message_id = Some(notification.message_id);
        Ok(event)
    }

    /// Handle a tokenless RST by endpoint and message ID.
    pub fn reset(&mut self, peer: Peer, message_id: u16) -> bool {
        if let Some(slot) = self.entries.iter_mut().find(|entry| {
            entry.as_ref().is_some_and(|item| {
                item.key.peer == peer && item.last_message_id == Some(message_id)
            })
        }) {
            *slot = None;
            true
        } else {
            false
        }
    }

    pub fn cleanup(&mut self, now_ms: u64) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|item| now_ms >= item.expires_at_ms)
            {
                *entry = None;
                removed += 1;
            }
        }
        removed
    }
}

impl<Peer: Copy + Eq, const SUBSCRIPTIONS: usize> Default for ObserveClient<Peer, SUBSCRIPTIONS> {
    fn default() -> Self {
        Self::new()
    }
}

const fn deadline(now_ms: u64, timeout_ms: u64) -> u64 {
    now_ms.saturating_add(timeout_ms)
}
