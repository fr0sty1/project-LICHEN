//! Rule Set Version 3 SCHC ACK-on-Error fragmentation (RFC 8724 section 8).

use core::{
    cell::{RefCell, RefMut},
    sync::atomic::{AtomicU32, Ordering},
};
use lichen_core::{
    constants::SCHC_FRAG_MAX_PACKET_SIZE,
    error::{BufferTooSmall, TooShort},
};

use crate::{AuthenticatedPeerSchcContext, PeerContextAuthority};

pub const FRAGMENT_M: u8 = 1;
pub const FRAGMENT_N: u8 = 6;
pub const FRAGMENT_T: u8 = 0;
pub const ALL_1_FCN: u8 = (1 << FRAGMENT_N) - 1;
pub const MIC_LENGTH: usize = 4;
pub const RETRANSMISSION_TIMEOUT_S: u32 = 10;
pub const MAX_ACK_REQUESTS: u32 = 4;
pub const INACTIVITY_TIMEOUT_S: u32 = 60;
pub const INACTIVITY_TIMEOUT_MILLIS: u64 = INACTIVITY_TIMEOUT_S as u64 * 1_000;

pub const TILE_SIZE: usize = 179;
pub const WINDOW_SIZE: usize = 63;
pub const BITMAP_MASK: u64 = (1u64 << WINDOW_SIZE) - 1;
pub const MAX_PACKET_SIZE: usize = SCHC_FRAG_MAX_PACKET_SIZE;
pub const FRAGMENT_TOMBSTONE_MILLIS: u64 = 60_000;
pub const RULE_ID_A_TO_B: u8 = 0x78;
pub const RULE_ID_B_TO_A: u8 = 0x79;
#[cfg(feature = "std")]
const FLOOR_RECORD_DOMAIN: &[u8] = b"LICHEN-SCHC-FLOOR-v1\0";
#[cfg(feature = "std")]
const FLOOR_RECORD_SIGNATURE_LEN: usize = 48;
#[cfg(feature = "std")]
const FLOOR_RECORD_BODY_LEN: usize =
    FLOOR_RECORD_DOMAIN.len() + 1 + 8 + 4 + 32 + 32 + 16 + 1 + 8 + 4 + 1 + 1 + 8 + 1 + 1 + 1;
#[cfg(feature = "std")]
const FLOOR_RECORD_LEN: usize = FLOOR_RECORD_BODY_LEN + FLOOR_RECORD_SIGNATURE_LEN;

/// Derive the fixed Rule Set v3 data Rule ID from authenticated endpoint keys.
/// Endpoint A is the lexicographically smaller full signer key; endpoint B is
/// the larger key. Equal keys cannot form a peer fragmentation session.
pub fn canonical_fragmentation_rule(
    local_signer: &[u8; 32],
    remote_signer: &[u8; 32],
    outbound: bool,
) -> Result<u8, FragmentError> {
    match local_signer.cmp(remote_signer) {
        core::cmp::Ordering::Less => Ok(if outbound {
            RULE_ID_A_TO_B
        } else {
            RULE_ID_B_TO_A
        }),
        core::cmp::Ordering::Greater => Ok(if outbound {
            RULE_ID_B_TO_A
        } else {
            RULE_ID_A_TO_B
        }),
        core::cmp::Ordering::Equal => Err(FragmentError::InvalidPeerEvidence),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FragmentError {
    TooShort(TooShort),
    BufferTooSmall(BufferTooSmall),
    UnsupportedRule,
    InvalidWindow,
    InvalidFcn,
    InvalidTileLength,
    InvalidRcs,
    NonZeroPadding,
    MalformedAck,
    NonCanonicalAck,
    UnassignedBitmapBit,
    EmptyPacket,
    InvalidReceiverLimit,
    PacketTooLarge,
    InvalidState,
    VersionMismatch,
    PolicyFull,
    InvalidPeerEvidence,
    SessionBusy,
    ReceiverAllocationRejected {
        response: ReceiverResponse,
    },
    /// A durable floor record was missing, malformed, corrupt, or mismatched.
    InvalidPersistentState,
    /// A valid older record was presented below the caller's committed revision.
    PersistentRollback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FragmentationPolicyEntry {
    signer: [u8; 32],
    generation: u32,
    key_generation: lichen_link::PeerKeyGeneration,
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    authenticated_counter: u32,
    compatible: bool,
    floor_restore_required: bool,
    sender_sessions: [Option<SessionReservation>; 2],
    receiver_sessions: [Option<SessionReservation>; 2],
    sender_tombstones: [Option<TerminalTombstone>; 2],
    receiver_tombstones: [Option<TerminalTombstone>; 2],
    next_session_id: u32,
    last_now_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SessionReservation {
    id: u32,
    expires_at_ms: u64,
    high_counter: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalTombstone {
    until_ms: u64,
    high_counter: u32,
    result: ReceiverResult,
}

/// Opaque, revocable authority to fragment packets for one authenticated peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedFragmentationPermit {
    owner: u32,
    slot: u16,
    generation: u32,
    key_generation: lichen_link::PeerKeyGeneration,
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    signer: [u8; 32],
}

static NEXT_FRAGMENTATION_POLICY_OWNER: AtomicU32 = AtomicU32::new(1);

/// Owner of current authenticated fragmentation policy for a bounded peer set.
pub struct FragmentationPolicy<const MAX_PEERS: usize> {
    owner: u32,
    local_signer: Option<[u8; 32]>,
    // Session operations use interior mutability so live handles can retain a
    // safe reference for RAII cleanup without unsafe back-pointers.
    entries: RefCell<[Option<FragmentationPolicyEntry>; MAX_PEERS]>,
    #[cfg(feature = "std")]
    receiving_link: Option<lichen_link::link_layer::ReceivingLinkIdentity>,
}

/// Private type-erased cleanup hook retained by live session handles.
trait FragmentSessionOwner {
    fn abandon_sender(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        high_counter: u32,
    );

    fn abandon_receiver(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        high_counter: u32,
    );
}

/// Read-only policy state exposed only for executable capability/vector tests.
#[cfg(feature = "test-utils")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragmentationPolicyTestSnapshot {
    pub peer_count: usize,
    pub sender_session_count: usize,
    pub receiver_session_count: usize,
    pub sender_tombstone_count: usize,
    pub receiver_tombstone_count: usize,
    pub max_sender_high_counter: Option<u32>,
    pub max_receiver_high_counter: Option<u32>,
}

impl<const MAX_PEERS: usize> FragmentationPolicy<MAX_PEERS> {
    /// Create a policy owner. Zero capacity and exhausted owner identifiers fail closed.
    pub fn new() -> Result<Self, FragmentError> {
        if MAX_PEERS == 0 || MAX_PEERS > u16::MAX as usize {
            return Err(FragmentError::PolicyFull);
        }
        let owner = NEXT_FRAGMENTATION_POLICY_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| FragmentError::PolicyFull)?;
        Ok(Self {
            owner,
            local_signer: None,
            entries: RefCell::new([None; MAX_PEERS]),
            #[cfg(feature = "std")]
            receiving_link: None,
        })
    }

    /// Snapshot all bounded policy slots without exposing mutation APIs.
    #[cfg(feature = "test-utils")]
    pub fn snapshot_for_tests(&self) -> FragmentationPolicyTestSnapshot {
        let mut snapshot = FragmentationPolicyTestSnapshot::default();
        let entries = self.entries.borrow();
        for entry in entries.iter().flatten() {
            snapshot.peer_count += 1;
            for session in entry.sender_sessions.iter().flatten() {
                snapshot.sender_session_count += 1;
                snapshot.max_sender_high_counter = Some(
                    snapshot
                        .max_sender_high_counter
                        .map_or(session.high_counter, |high| high.max(session.high_counter)),
                );
            }
            for session in entry.receiver_sessions.iter().flatten() {
                snapshot.receiver_session_count += 1;
                snapshot.max_receiver_high_counter = Some(
                    snapshot
                        .max_receiver_high_counter
                        .map_or(session.high_counter, |high| high.max(session.high_counter)),
                );
            }
            for tombstone in entry.sender_tombstones.iter().flatten() {
                snapshot.sender_tombstone_count += 1;
                snapshot.max_sender_high_counter = Some(
                    snapshot
                        .max_sender_high_counter
                        .map_or(tombstone.high_counter, |high| {
                            high.max(tombstone.high_counter)
                        }),
                );
            }
            for tombstone in entry.receiver_tombstones.iter().flatten() {
                snapshot.receiver_tombstone_count += 1;
                snapshot.max_receiver_high_counter = Some(
                    snapshot
                        .max_receiver_high_counter
                        .map_or(tombstone.high_counter, |high| {
                            high.max(tombstone.high_counter)
                        }),
                );
            }
        }
        snapshot
    }

    /// Replace the current policy for an authenticated signer and issue a new permit.
    #[cfg(feature = "std")]
    pub fn accept_peer(
        &mut self,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<AuthenticatedFragmentationPermit, FragmentError> {
        if !peer.is_current_for(link) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let receiving_link = link.receiving_link_identity();
        if self
            .receiving_link
            .as_ref()
            .is_some_and(|owner| !owner.is_same_receiver(&receiving_link))
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        if self.receiving_link.is_none() {
            self.receiving_link = Some(receiving_link);
        }
        self.bind_local_signer(*link.local_public_key().as_bytes())?;
        let permit = self.install_peer(peer, now_ms)?;
        if link.requires_schc_floor_record(peer.signer_identity(), peer.durable_key_generation()) {
            self.current_entry_mut(&permit)?.floor_restore_required = true;
        }
        Ok(permit)
    }

    /// Accept a current peer capability from a bounded no-std link authority.
    pub fn accept_peer_with_authority<const MAX_AUTH_PEERS: usize>(
        &mut self,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<AuthenticatedFragmentationPermit, FragmentError> {
        if !authority.is_current(peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.bind_local_signer(*authority.local_signer())?;
        self.install_peer(peer, now_ms)
    }

    fn bind_local_signer(&mut self, signer: [u8; 32]) -> Result<(), FragmentError> {
        if self.local_signer.is_some_and(|current| current != signer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.local_signer = Some(signer);
        Ok(())
    }

    /// Rule ID for data sent by the local endpoint to this permitted peer.
    pub fn outbound_rule(
        &self,
        permit: &AuthenticatedFragmentationPermit,
    ) -> Result<u8, FragmentError> {
        self.rule_for_permit(permit, true)
    }

    /// Rule ID required for data received from this permitted peer.
    pub fn inbound_rule(
        &self,
        permit: &AuthenticatedFragmentationPermit,
    ) -> Result<u8, FragmentError> {
        self.rule_for_permit(permit, false)
    }

    fn rule_for_permit(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        outbound: bool,
    ) -> Result<u8, FragmentError> {
        if permit.owner != self.owner
            || !self
                .entries
                .borrow()
                .get(permit.slot as usize)
                .is_some_and(|entry| {
                    entry.is_some_and(|entry| {
                        entry.generation == permit.generation
                            && entry.key_generation == permit.key_generation
                            && entry.signer == permit.signer
                    })
                })
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        canonical_fragmentation_rule(
            self.local_signer
                .as_ref()
                .ok_or(FragmentError::InvalidPeerEvidence)?,
            &permit.signer,
            outbound,
        )
    }

    fn install_peer(
        &mut self,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<AuthenticatedFragmentationPermit, FragmentError> {
        let signer = *peer.signer_identity();
        canonical_fragmentation_rule(
            self.local_signer
                .as_ref()
                .ok_or(FragmentError::InvalidPeerEvidence)?,
            &signer,
            true,
        )?;
        let entries = self.entries.get_mut();
        let existing = entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.signer == signer));
        let slot = existing
            .or_else(|| entries.iter().position(Option::is_none))
            .ok_or(FragmentError::PolicyFull)?;
        let prior = entries[slot];
        if let Some(entry) = entries[slot].as_mut() {
            if entry.key_generation == peer.key_generation()
                && entry.durable_key_generation == peer.durable_key_generation()
                && entry.compatible == peer.allows_dodag_join()
            {
                if peer.authenticated_counter() <= entry.authenticated_counter
                    || now_ms < entry.last_now_ms
                {
                    return Err(FragmentError::InvalidPeerEvidence);
                }
                entry.authenticated_counter = peer.authenticated_counter();
                entry.last_now_ms = now_ms;
                if !entry.compatible {
                    return Err(FragmentError::VersionMismatch);
                }
                return Ok(AuthenticatedFragmentationPermit {
                    owner: self.owner,
                    slot: slot as u16,
                    generation: entry.generation,
                    key_generation: entry.key_generation,
                    durable_key_generation: entry.durable_key_generation,
                    signer,
                });
            }
        }
        let generation = prior.map_or(1, |entry| entry.generation.checked_add(1).unwrap_or(0));
        if generation == 0 {
            if let Some(entry) = entries[slot].as_mut() {
                entry.compatible = false;
            }
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let compatible = peer.allows_dodag_join();
        if prior.is_some_and(|entry| now_ms < entry.last_now_ms) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        // A different opaque key generation is a distinct fragmentation
        // owner even when the public-key bytes are identical. Replacing the
        // entry atomically discards every old active session, tombstone, floor,
        // and prepared reservation; stale handles fail the generation check.
        entries[slot] = Some(FragmentationPolicyEntry {
            signer,
            generation,
            key_generation: peer.key_generation(),
            durable_key_generation: peer.durable_key_generation(),
            authenticated_counter: peer.authenticated_counter(),
            compatible,
            floor_restore_required: false,
            sender_sessions: [None; 2],
            receiver_sessions: [None; 2],
            sender_tombstones: [None; 2],
            receiver_tombstones: [None; 2],
            next_session_id: 1,
            last_now_ms: now_ms,
        });
        if !compatible {
            return Err(FragmentError::VersionMismatch);
        }
        Ok(AuthenticatedFragmentationPermit {
            owner: self.owner,
            slot: slot as u16,
            generation,
            key_generation: peer.key_generation(),
            durable_key_generation: peer.durable_key_generation(),
            signer,
        })
    }

    fn accepts_entry(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        peer: &AuthenticatedPeerSchcContext,
    ) -> bool {
        peer.signer_identity() == &permit.signer
            && peer.key_generation() == permit.key_generation
            && peer.durable_key_generation() == permit.durable_key_generation
            && permit.owner == self.owner
            && self
                .entries
                .borrow()
                .get(permit.slot as usize)
                .is_some_and(|entry| {
                    entry.is_some_and(|entry| {
                        entry.compatible
                            && !entry.floor_restore_required
                            && entry.generation == permit.generation
                            && entry.key_generation == permit.key_generation
                            && entry.durable_key_generation == permit.durable_key_generation
                            && entry.signer == permit.signer
                            && entry.authenticated_counter == peer.authenticated_counter()
                    })
                })
    }

    fn accepts_with_authority<const MAX_AUTH_PEERS: usize>(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
    ) -> bool {
        authority.is_current(peer) && self.accepts_entry(permit, peer)
    }

    fn current_entry_mut(
        &self,
        permit: &AuthenticatedFragmentationPermit,
    ) -> Result<RefMut<'_, FragmentationPolicyEntry>, FragmentError> {
        if permit.owner != self.owner {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        RefMut::filter_map(self.entries.borrow_mut(), |entries| {
            entries
                .get_mut(permit.slot as usize)
                .and_then(Option::as_mut)
                .filter(|entry| {
                    entry.generation == permit.generation
                        && entry.signer == permit.signer
                        && entry.key_generation == permit.key_generation
                        && entry.durable_key_generation == permit.durable_key_generation
                })
        })
        .map_err(|_| FragmentError::InvalidPeerEvidence)
    }

    fn reserve_sender(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        now: u64,
        initial_counter: u32,
    ) -> Result<u32, FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now)?;
        if let Some(session) = entry.sender_sessions[index] {
            if now < session.expires_at_ms {
                return Err(FragmentError::SessionBusy);
            }
            entry.sender_sessions[index] = None;
            entry.sender_tombstones[index] = Some(TerminalTombstone {
                until_ms: now.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
                high_counter: session.high_counter,
                result: ReceiverResult::default(),
            });
            return Err(FragmentError::SessionBusy);
        }
        if entry.sender_tombstones[index].is_some_and(|tombstone| now < tombstone.until_ms) {
            return Err(FragmentError::SessionBusy);
        }
        entry.sender_tombstones[index] = None;
        let id = next_session_id(&mut entry)?;
        entry.sender_sessions[index] = Some(SessionReservation {
            id,
            expires_at_ms: now.saturating_add(INACTIVITY_TIMEOUT_MILLIS),
            high_counter: initial_counter,
        });
        Ok(id)
    }

    fn reserve_receiver(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        now: u64,
        initial_counter: u32,
    ) -> Result<(u32, u32), FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now)?;
        if let Some(session) = entry.receiver_sessions[index] {
            if now < session.expires_at_ms {
                return Err(FragmentError::SessionBusy);
            }
            entry.receiver_sessions[index] = None;
            entry.receiver_tombstones[index] = Some(TerminalTombstone {
                until_ms: now.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
                high_counter: session.high_counter,
                result: ReceiverResult::default(),
            });
            return Err(FragmentError::SessionBusy);
        }
        let admission_floor = if let Some(tombstone) = entry.receiver_tombstones[index] {
            if now < tombstone.until_ms {
                return Err(FragmentError::SessionBusy);
            }
            tombstone.high_counter.max(initial_counter)
        } else {
            initial_counter
        };
        entry.receiver_tombstones[index] = None;
        let id = next_session_id(&mut entry)?;
        entry.receiver_sessions[index] = Some(SessionReservation {
            id,
            expires_at_ms: now.saturating_add(INACTIVITY_TIMEOUT_MILLIS),
            high_counter: admission_floor,
        });
        Ok((id, admission_floor))
    }

    fn release_sender(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        now: u64,
        high_counter: u32,
    ) -> Result<(), FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now)?;
        if entry.sender_sessions[index].is_none_or(|session| session.id != session_id) {
            return Err(FragmentError::InvalidState);
        }
        entry.sender_sessions[index] = None;
        entry.sender_tombstones[index] = Some(TerminalTombstone {
            until_ms: now.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
            high_counter,
            result: ReceiverResult::default(),
        });
        Ok(())
    }

    fn release_receiver(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        now: u64,
        high_counter: u32,
        result: ReceiverResult,
    ) -> Result<(), FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now)?;
        let Some(session) = entry.receiver_sessions[index] else {
            return Err(FragmentError::InvalidState);
        };
        if session.id != session_id {
            return Err(FragmentError::InvalidState);
        }
        entry.receiver_sessions[index] = None;
        entry.receiver_tombstones[index] = Some(TerminalTombstone {
            until_ms: now.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
            high_counter: high_counter.max(session.high_counter),
            // A duplicate terminal control may need the same final ACK/abort,
            // but the completed packet remains owned by the released receiver.
            // Never advertise an old buffer length after that receiver is gone.
            result: ReceiverResult {
                packet_len: None,
                ..result
            },
        });
        Ok(())
    }

    fn touch_sender(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        now_ms: u64,
    ) -> Result<(), FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now_ms)?;
        let Some(session) = entry.sender_sessions[index].as_mut() else {
            return Err(FragmentError::InvalidState);
        };
        if session.id != session_id || now_ms >= session.expires_at_ms {
            return Err(FragmentError::InvalidState);
        }
        session.expires_at_ms = now_ms.saturating_add(INACTIVITY_TIMEOUT_MILLIS);
        Ok(())
    }

    fn touch_receiver(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        now_ms: u64,
        counter: u32,
    ) -> Result<(), FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now_ms)?;
        let Some(session) = entry.receiver_sessions[index].as_mut() else {
            return Err(FragmentError::InvalidState);
        };
        if session.id != session_id || now_ms >= session.expires_at_ms {
            return Err(FragmentError::InvalidState);
        }
        session.expires_at_ms = now_ms.saturating_add(INACTIVITY_TIMEOUT_MILLIS);
        session.high_counter = session.high_counter.max(counter);
        Ok(())
    }

    /// Reclaim every state for a retired signer without evicting live peers.
    pub fn retire_peer(&mut self, signer: &[u8; 32]) {
        for entry in self.entries.get_mut() {
            if entry.is_some_and(|entry| &entry.signer == signer) {
                *entry = None;
            }
        }
    }

    fn replay_receiver_terminal(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        counter: u32,
        now_ms: u64,
        payload: &[u8],
    ) -> Result<Option<ReceiverResult>, FragmentError> {
        let mut entry = self.current_entry_mut(permit)?;
        let index = rule_index(rule_id)?;
        observe_policy_now(&mut entry, now_ms)?;
        let Some(tombstone) = entry.receiver_tombstones[index] else {
            return Ok(None);
        };
        if counter <= tombstone.high_counter {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let ack_request = payload.len() == 2 && payload[0] == rule_id && payload[1] & 0x7f == 0;
        let mut tile = [0u8; TILE_SIZE];
        let parsed = Fragment::from_bytes(payload, &mut tile).ok();
        let all_1 =
            parsed.is_some_and(|fragment| fragment.rule_id == rule_id && fragment.is_all_1());
        let opener = parsed.is_some_and(|fragment| {
            fragment.rule_id == rule_id
                && fragment.window == 0
                && fragment.fcn == WINDOW_SIZE as u8 - 1
                && !fragment.is_all_1()
        });
        if now_ms >= tombstone.until_ms && opener {
            // The caller may now allocate a replacement context. Its immutable
            // admission floor is copied from this retained tombstone.
            return Ok(None);
        }
        if let Some(stored) = entry.receiver_tombstones[index].as_mut() {
            // Every authenticated late message advances the barrier, including
            // regular fragments that produce no cached control response.
            stored.high_counter = counter;
        }
        Ok((now_ms < tombstone.until_ms && (ack_request || all_1)).then_some(tombstone.result))
    }

    /// Seal one receiver tombstone/admission floor for atomic durable storage.
    ///
    /// The caller commits this record in the same transaction as the link
    /// trust/replay state and retains `revision` as that transaction's
    /// anti-rollback version.  The local identity signs the entire record.
    #[cfg(feature = "std")]
    pub fn persist_receiver_floor(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        revision: u64,
        out: &mut [u8],
    ) -> Result<usize, FragmentError> {
        if revision == 0 || !self.accepts_current(permit, link, peer) {
            return Err(FragmentError::InvalidPersistentState);
        }
        let rule_id = self.inbound_rule(permit)?;
        let entry = self.current_entry_mut(permit)?;
        let tombstone = entry.receiver_tombstones[rule_index(rule_id)?]
            .ok_or(FragmentError::InvalidPersistentState)?;
        let body = encode_floor_record_body(
            revision,
            peer.authenticated_counter(),
            self.local_signer
                .ok_or(FragmentError::InvalidPersistentState)?,
            permit.signer,
            permit.durable_key_generation,
            rule_id,
            tombstone,
        )?;
        let needed = FLOOR_RECORD_LEN;
        debug_assert_eq!(body.len(), FLOOR_RECORD_BODY_LEN);
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        let signature = link.sign_digest(&body);
        out[..body.len()].copy_from_slice(&body);
        out[body.len()..needed].copy_from_slice(&signature);
        Ok(needed)
    }

    /// Restore a sealed floor after exact trust-generation and replay checks.
    ///
    /// Validation is completed before the policy is mutated. `committed_revision`
    /// is the exact version returned by link trust/replay restoration; a floor
    /// from any other transaction therefore fails closed.
    #[cfg(feature = "std")]
    pub fn restore_receiver_floor(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        record: &[u8],
        committed_revision: u64,
        now_ms: u64,
    ) -> Result<u64, FragmentError> {
        if !peer.is_current_for(link)
            || record.len() != FLOOR_RECORD_LEN
            || !link.matches_required_schc_floor_record(
                peer.signer_identity(),
                peer.durable_key_generation(),
                record,
            )
        {
            return Err(FragmentError::InvalidPersistentState);
        }
        let split = FLOOR_RECORD_BODY_LEN;
        let (body, signature) = record.split_at(split);
        if !lichen_link::schnorr::verify_profile_message(&link.local_public_key(), body, signature)
        {
            return Err(FragmentError::InvalidPersistentState);
        }
        let decoded = decode_floor_record_body(body)?;
        if decoded.revision < committed_revision {
            return Err(FragmentError::PersistentRollback);
        }
        if decoded.revision != committed_revision {
            return Err(FragmentError::InvalidPersistentState);
        }
        let local_signer = self
            .local_signer
            .ok_or(FragmentError::InvalidPersistentState)?;
        let rule_id = self.inbound_rule(permit)?;
        if decoded.local_signer != local_signer
            || decoded.remote_signer != permit.signer
            || decoded.durable_key_generation != permit.durable_key_generation.as_bytes()
            || decoded.rule_id != rule_id
            || peer.durable_key_generation() != permit.durable_key_generation
            || peer.authenticated_counter() < decoded.replay_counter
        {
            return Err(FragmentError::InvalidPersistentState);
        }

        let index = rule_index(rule_id)?;
        {
            let entry = self.current_entry_mut(permit)?;
            if !entry.compatible
                || !entry.floor_restore_required
                || now_ms < entry.last_now_ms
                || entry.receiver_sessions[index].is_some()
                || entry.receiver_tombstones[index]
                    .is_some_and(|current| current.high_counter > decoded.tombstone.high_counter)
            {
                return Err(FragmentError::PersistentRollback);
            }
        }
        let rebased_deadline = now_ms
            .checked_add(decoded.restart_hold_down_ms)
            .ok_or(FragmentError::InvalidPersistentState)?;
        let mut tombstone = decoded.tombstone;
        tombstone.until_ms = rebased_deadline;
        tombstone.high_counter = tombstone.high_counter.max(peer.authenticated_counter());
        if !link.consume_schc_floor_record(
            peer.signer_identity(),
            peer.durable_key_generation(),
            record,
        ) {
            return Err(FragmentError::InvalidPersistentState);
        }
        let mut entry = self.current_entry_mut(permit)?;
        entry.last_now_ms = now_ms;
        entry.receiver_tombstones[index] = Some(tombstone);
        entry.floor_restore_required = false;
        Ok(decoded.revision)
    }

    #[cfg(feature = "std")]
    fn accepts_current(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
    ) -> bool {
        peer.is_current_for(link)
            && self
                .receiving_link
                .as_ref()
                .is_some_and(|owner| owner.is_same_receiver(&link.receiving_link_identity()))
            && self.accepts_entry(permit, peer)
    }
}

impl<const MAX_PEERS: usize> FragmentSessionOwner for FragmentationPolicy<MAX_PEERS> {
    fn abandon_sender(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        high_counter: u32,
    ) {
        let Ok(index) = rule_index(rule_id) else {
            return;
        };
        let Ok(mut entry) = self.current_entry_mut(permit) else {
            return;
        };
        let Some(session) = entry.sender_sessions[index] else {
            return;
        };
        if session.id != session_id {
            return;
        }
        entry.sender_sessions[index] = None;
        entry.sender_tombstones[index] = Some(TerminalTombstone {
            until_ms: entry.last_now_ms.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
            high_counter: session.high_counter.max(high_counter),
            result: ReceiverResult::default(),
        });
    }

    fn abandon_receiver(
        &self,
        permit: &AuthenticatedFragmentationPermit,
        rule_id: u8,
        session_id: u32,
        high_counter: u32,
    ) {
        let Ok(index) = rule_index(rule_id) else {
            return;
        };
        let Ok(mut entry) = self.current_entry_mut(permit) else {
            return;
        };
        let Some(session) = entry.receiver_sessions[index] else {
            return;
        };
        if session.id != session_id {
            return;
        }
        entry.receiver_sessions[index] = None;
        entry.receiver_tombstones[index] = Some(TerminalTombstone {
            until_ms: entry.last_now_ms.saturating_add(FRAGMENT_TOMBSTONE_MILLIS),
            high_counter: session.high_counter.max(high_counter),
            result: ReceiverResult {
                aborted: true,
                ..ReceiverResult::default()
            },
        });
    }
}

impl core::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "fragmentation message {e}"),
            Self::BufferTooSmall(e) => write!(f, "fragmentation message {e}"),
            Self::UnsupportedRule => write!(f, "unsupported fragmentation rule"),
            Self::InvalidWindow => write!(f, "invalid window"),
            Self::InvalidFcn => write!(f, "invalid FCN"),
            Self::InvalidTileLength => write!(f, "invalid tile length"),
            Self::InvalidRcs => write!(f, "invalid RCS"),
            Self::NonZeroPadding => write!(f, "non-zero end padding"),
            Self::MalformedAck => write!(f, "malformed ACK or control"),
            Self::NonCanonicalAck => write!(f, "non-canonical compressed ACK"),
            Self::UnassignedBitmapBit => write!(f, "unassigned bitmap bit is set"),
            Self::EmptyPacket => write!(f, "empty packets cannot be fragmented"),
            Self::InvalidReceiverLimit => write!(f, "receiver limit out of range"),
            Self::PacketTooLarge => write!(f, "packet exceeds receiver reassembly limit"),
            Self::InvalidState => write!(f, "invalid fragmentation state"),
            Self::VersionMismatch => write!(f, "authenticated peer SCHC version mismatch"),
            Self::PolicyFull => write!(f, "authenticated peer policy capacity is full"),
            Self::InvalidPeerEvidence => write!(f, "stale or foreign peer evidence"),
            Self::SessionBusy => write!(f, "fragmentation tuple is active or in hold-down"),
            Self::ReceiverAllocationRejected { .. } => {
                write!(f, "receiver allocation failed; send Receiver-Abort")
            }
            Self::InvalidPersistentState => write!(f, "invalid persistent fragmentation state"),
            Self::PersistentRollback => write!(f, "persistent fragmentation rollback"),
        }
    }
}

impl core::error::Error for FragmentError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for FragmentError {
    fn from(value: TooShort) -> Self {
        Self::TooShort(value)
    }
}

impl From<BufferTooSmall> for FragmentError {
    fn from(value: BufferTooSmall) -> Self {
        Self::BufferTooSmall(value)
    }
}

fn receiver_allocation_error(rule_id: u8, error: FragmentError) -> FragmentError {
    match error {
        FragmentError::InvalidReceiverLimit | FragmentError::PolicyFull => {
            FragmentError::ReceiverAllocationRejected {
                response: ReceiverResponse::ReceiverAbort { rule_id },
            }
        }
        error => error,
    }
}

fn check_rule(rule_id: u8) -> Result<(), FragmentError> {
    if matches!(rule_id, RULE_ID_A_TO_B | RULE_ID_B_TO_A) {
        Ok(())
    } else {
        Err(FragmentError::UnsupportedRule)
    }
}

fn rule_index(rule_id: u8) -> Result<usize, FragmentError> {
    match rule_id {
        RULE_ID_A_TO_B => Ok(0),
        RULE_ID_B_TO_A => Ok(1),
        _ => Err(FragmentError::UnsupportedRule),
    }
}

fn observe_policy_now(
    entry: &mut FragmentationPolicyEntry,
    now_ms: u64,
) -> Result<(), FragmentError> {
    if now_ms < entry.last_now_ms {
        return Err(FragmentError::InvalidPeerEvidence);
    }
    entry.last_now_ms = now_ms;
    Ok(())
}

fn next_session_id(entry: &mut FragmentationPolicyEntry) -> Result<u32, FragmentError> {
    let id = entry.next_session_id;
    entry.next_session_id = entry
        .next_session_id
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or(FragmentError::PolicyFull)?;
    Ok(id)
}

#[cfg(feature = "std")]
#[derive(Clone, Copy)]
struct DecodedFloorRecord {
    revision: u64,
    replay_counter: u32,
    local_signer: [u8; 32],
    remote_signer: [u8; 32],
    durable_key_generation: [u8; 16],
    rule_id: u8,
    tombstone: TerminalTombstone,
    restart_hold_down_ms: u64,
}

#[cfg(feature = "std")]
fn encode_floor_record_body(
    revision: u64,
    replay_counter: u32,
    local_signer: [u8; 32],
    remote_signer: [u8; 32],
    durable_key_generation: lichen_link::DurablePeerKeyGeneration,
    rule_id: u8,
    tombstone: TerminalTombstone,
) -> Result<std::vec::Vec<u8>, FragmentError> {
    if tombstone.result.packet_len.is_some() {
        return Err(FragmentError::InvalidPersistentState);
    }
    let (response_tag, ack_window, ack_bitmap, ack_complete) = match tombstone.result.response {
        None => (0, 0, 0, false),
        Some(ReceiverResponse::Ack(ack))
            if ack.rule_id == rule_id
                && ack.window <= 1
                && ack.bitmap & !BITMAP_MASK == 0
                && (!ack.complete || ack.bitmap == 0)
                && !tombstone.result.aborted =>
        {
            (1, ack.window, ack.bitmap, ack.complete)
        }
        Some(ReceiverResponse::ReceiverAbort {
            rule_id: abort_rule,
        }) if abort_rule == rule_id && tombstone.result.aborted => (2, 0, 0, false),
        _ => return Err(FragmentError::InvalidPersistentState),
    };
    let mic_ok = match tombstone.result.mic_ok {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    let mut body = std::vec::Vec::with_capacity(192);
    body.extend_from_slice(FLOOR_RECORD_DOMAIN);
    body.push(2);
    body.extend_from_slice(&revision.to_be_bytes());
    body.extend_from_slice(&replay_counter.to_be_bytes());
    body.extend_from_slice(&local_signer);
    body.extend_from_slice(&remote_signer);
    body.extend_from_slice(&durable_key_generation.as_bytes());
    body.push(rule_id);
    // Persist a duration, never a process-monotonic absolute timestamp. A
    // restored process conservatively starts this complete hold-down again.
    body.extend_from_slice(&FRAGMENT_TOMBSTONE_MILLIS.to_be_bytes());
    body.extend_from_slice(&tombstone.high_counter.to_be_bytes());
    body.push(response_tag);
    body.push(ack_window);
    body.extend_from_slice(&ack_bitmap.to_be_bytes());
    body.push(u8::from(ack_complete));
    body.push(u8::from(tombstone.result.aborted));
    body.push(mic_ok);
    Ok(body)
}

#[cfg(feature = "std")]
fn decode_floor_record_body(body: &[u8]) -> Result<DecodedFloorRecord, FragmentError> {
    if body.len() != FLOOR_RECORD_BODY_LEN || !body.starts_with(FLOOR_RECORD_DOMAIN) {
        return Err(FragmentError::InvalidPersistentState);
    }
    let mut cursor = FLOOR_RECORD_DOMAIN.len();
    if body[cursor] != 2 {
        return Err(FragmentError::InvalidPersistentState);
    }
    cursor += 1;
    let revision = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if revision == 0 {
        return Err(FragmentError::InvalidPersistentState);
    }
    let replay_counter = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let local_signer = body[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let remote_signer = body[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let durable_key_generation = body[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    if durable_key_generation == [0; 16] {
        return Err(FragmentError::InvalidPersistentState);
    }
    let rule_id = body[cursor];
    cursor += 1;
    check_rule(rule_id)?;
    let restart_hold_down_ms = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if restart_hold_down_ms == 0 || restart_hold_down_ms > FRAGMENT_TOMBSTONE_MILLIS {
        return Err(FragmentError::InvalidPersistentState);
    }
    let high_counter = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap());
    cursor += 4;
    let response_tag = body[cursor];
    cursor += 1;
    let ack_window = body[cursor];
    cursor += 1;
    let ack_bitmap = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let ack_complete = match body[cursor] {
        0 => false,
        1 => true,
        _ => return Err(FragmentError::InvalidPersistentState),
    };
    cursor += 1;
    let aborted = match body[cursor] {
        0 => false,
        1 => true,
        _ => return Err(FragmentError::InvalidPersistentState),
    };
    cursor += 1;
    let mic_ok = match body[cursor] {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(FragmentError::InvalidPersistentState),
    };
    let response = match response_tag {
        0 if ack_window == 0 && ack_bitmap == 0 && !ack_complete => None,
        1 if ack_window <= 1
            && ack_bitmap & !BITMAP_MASK == 0
            && (!ack_complete || ack_bitmap == 0) =>
        {
            Some(ReceiverResponse::Ack(Ack::new(
                rule_id,
                ack_window,
                ack_bitmap,
                ack_complete,
            )))
        }
        2 if ack_window == 0 && ack_bitmap == 0 && !ack_complete => {
            Some(ReceiverResponse::ReceiverAbort { rule_id })
        }
        _ => return Err(FragmentError::InvalidPersistentState),
    };
    if matches!(response, Some(ReceiverResponse::Ack(_))) && aborted
        || matches!(response, Some(ReceiverResponse::ReceiverAbort { .. })) && !aborted
        || mic_ok == Some(true) && !ack_complete
        || mic_ok == Some(false) && (response_tag != 1 || ack_complete)
    {
        return Err(FragmentError::InvalidPersistentState);
    }
    Ok(DecodedFloorRecord {
        revision,
        replay_counter,
        local_signer,
        remote_signer,
        durable_key_generation,
        rule_id,
        tombstone: TerminalTombstone {
            until_ms: 0,
            high_counter,
            result: ReceiverResult {
                response,
                packet_len: None,
                mic_ok,
                aborted,
            },
        },
        restart_hold_down_ms,
    })
}

/// CRC-32/ISO-HDLC over the SCHC Packet followed by the All-1 zero pad bit,
/// byte-extended as one zero octet.
pub fn compute_mic(data: &[u8]) -> [u8; MIC_LENGTH] {
    let mut crc = 0xffff_ffffu32;
    for byte in data.iter().copied().chain(core::iter::once(0)) {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    (!crc).to_be_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub rule_id: u8,
    pub window: u8,
    pub fcn: u8,
    pub payload: &'a [u8],
    pub mic: [u8; MIC_LENGTH],
}

impl<'a> Fragment<'a> {
    pub const fn is_all_1(&self) -> bool {
        self.fcn == ALL_1_FCN
    }

    pub const fn is_all_0(&self) -> bool {
        self.fcn == 0
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        check_rule(self.rule_id)?;
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.fcn > ALL_1_FCN {
            return Err(FragmentError::InvalidFcn);
        }
        if self.is_all_1() {
            if !(1..=TILE_SIZE).contains(&self.payload.len()) {
                return Err(FragmentError::InvalidTileLength);
            }
        } else if self.payload.len() != TILE_SIZE || self.mic != [0; MIC_LENGTH] {
            return Err(FragmentError::InvalidTileLength);
        } else if self.window == 1 && self.is_all_0() {
            return Err(FragmentError::InvalidFcn);
        }

        let content_len = self.payload.len() + if self.is_all_1() { MIC_LENGTH } else { 0 };
        let needed = content_len + 2;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[..needed].fill(0);
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << 7) | ((self.fcn & ((1 << FRAGMENT_N) - 1)) << 1);
        let mut index = 0;
        if self.is_all_1() {
            for byte in self.mic {
                out[1 + index] |= byte >> 7;
                out[2 + index] = byte << 1;
                index += 1;
            }
        }
        for &byte in self.payload {
            out[1 + index] |= byte >> 7;
            out[2 + index] = byte << 1;
            index += 1;
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &[u8], out: &'a mut [u8]) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let rule_id = data[0];
        let window = (data[1] >> 7) & 1;
        let fcn = (data[1] >> 1) & ((1 << FRAGMENT_N) - 1);
        let content_len = data.len() - 2;
        let content_offset = if fcn == ALL_1_FCN { MIC_LENGTH } else { 0 };
        let payload_len = content_len - content_offset;
        if fcn == ALL_1_FCN {
            if !(MIC_LENGTH + 1..=MIC_LENGTH + TILE_SIZE).contains(&content_len) {
                return Err(FragmentError::InvalidTileLength);
            }
        } else if data.len() != TILE_SIZE + 2 {
            return Err(FragmentError::InvalidTileLength);
        } else if window == 1 && fcn == 0 {
            return Err(FragmentError::InvalidFcn);
        }
        if out.len() < payload_len {
            return Err(BufferTooSmall::new(payload_len, out.len()).into());
        }
        if fcn != ALL_1_FCN && data[data.len() - 1] & 1 != 0 {
            return Err(FragmentError::NonZeroPadding);
        }
        for (i, byte) in out[..payload_len].iter_mut().enumerate() {
            let wire = 1 + content_offset + i;
            *byte = (data[wire] << 7) | (data[wire + 1] >> 1);
        }
        let mut mic = [0; MIC_LENGTH];
        if fcn == ALL_1_FCN {
            for i in 0..MIC_LENGTH {
                mic[i] = (data[1 + i] << 7) | (data[2 + i] >> 1);
            }
        }
        Ok(Fragment {
            rule_id,
            window,
            fcn,
            payload: &out[..payload_len],
            mic,
        })
    }
}

/// A T=0 reassembly context may only be opened by the first regular tile:
/// W=0, FCN=62. All-1 and control messages can never allocate state.
fn is_receiver_session_opener(payload: &[u8], rule_id: u8) -> bool {
    let mut tile = [0u8; TILE_SIZE];
    Fragment::from_bytes(payload, &mut tile).is_ok_and(|fragment| {
        fragment.rule_id == rule_id
            && fragment.window == 0
            && fragment.fcn == WINDOW_SIZE as u8 - 1
            && !fragment.is_all_1()
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub rule_id: u8,
    pub window: u8,
    /// Position 0 (FCN 62) is bit 62; position 62 (FCN 0 or All-1) is bit 0.
    pub bitmap: u64,
    pub complete: bool,
}

impl Ack {
    pub fn new(rule_id: u8, window: u8, bitmap: u64, complete: bool) -> Self {
        Self {
            rule_id,
            window,
            bitmap: bitmap & BITMAP_MASK,
            complete,
        }
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        check_rule(self.rule_id)?;
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.complete {
            if self.bitmap != 0 {
                return Err(FragmentError::MalformedAck);
            }
            if out.len() < 2 {
                return Err(BufferTooSmall::new(2, out.len()).into());
            }
            out[0] = self.rule_id;
            out[1] = (self.window << 7) | 0x40;
            return Ok(2);
        }

        let trailing = (self.bitmap & BITMAP_MASK).trailing_ones() as usize;
        let n = WINDOW_SIZE - trailing;
        let remaining = n.saturating_sub(6);
        let body_bytes = remaining.div_ceil(8);
        let needed = 2 + body_bytes;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[..needed].fill(0);
        out[0] = self.rule_id;
        let first_byte_bits = n.min(6);
        for i in 0..first_byte_bits {
            if self.bitmap & (1u64 << (62 - i)) != 0 {
                out[1] |= 1 << (5 - i);
            }
        }
        for i in 0..remaining {
            if self.bitmap & (1u64 << (56 - i)) != 0 {
                let byte_idx = 2 + i / 8;
                let bit_idx = 7 - (i % 8);
                out[byte_idx] |= 1 << bit_idx;
            }
        }
        // Trailing 1s can be elided per RFC 8724, but to byte-align we must
        // restore some of them. Only do this if there are trailing 1s to restore.
        if trailing > 0 {
            let restored = body_bytes * 8 - remaining;
            if restored > 0 {
                let last_byte = &mut out[needed - 1];
                *last_byte |= (1u8 << restored) - 1;
            }
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FragmentError> {
        Self::from_bytes_for(data, None)
    }

    pub fn from_bytes_for(data: &[u8], assigned: Option<u64>) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        if data.len() == 2 {
            if data[1] & 0x40 == 0 {
                return Err(TooShort::new(3, data.len()).into());
            }
            let rule_id = data[0];
            let window = (data[1] >> 7) & 1;
            let ack = Self::new(rule_id, window, 0, true);
            let mut canonical = [0u8; 2];
            let length = ack.write_to(&mut canonical)?;
            if &canonical[..length] != data {
                return Err(FragmentError::NonCanonicalAck);
            }
            return Ok(ack);
        }
        let rule_id = data[0];
        let window = (data[1] >> 7) & 1;
        let total_bits = 6 + (data.len() - 2) * 8;
        let mut bitmap = 0u64;
        for i in 0..total_bits.min(63) {
            let val = if i < 6 {
                (data[1] >> (5 - i)) & 1
            } else {
                let byte_idx = 2 + (i - 6) / 8;
                let bit_idx = 7 - ((i - 6) % 8);
                (data[byte_idx] >> bit_idx) & 1
            };
            if val != 0 {
                bitmap |= 1u64 << (62 - i);
            }
        }
        if total_bits < 63 {
            let mask = (1u64 << (63 - total_bits)) - 1;
            bitmap |= mask;
        }
        bitmap &= BITMAP_MASK;
        let trailing = (bitmap & BITMAP_MASK).trailing_ones() as usize;
        let n = WINDOW_SIZE - trailing;
        if n > WINDOW_SIZE {
            return Err(FragmentError::MalformedAck);
        }
        let remaining = n.saturating_sub(6);
        let body_bytes = remaining.div_ceil(8);
        let expected_len = 2 + body_bytes;
        if expected_len != data.len() {
            return Err(FragmentError::NonCanonicalAck);
        }
        let ack = Self::new(rule_id, window, bitmap, false);
        let mut canonical = [0u8; 10];
        let length = ack.write_to(&mut canonical)?;
        if &canonical[..length] != data {
            return Err(FragmentError::NonCanonicalAck);
        }
        if assigned.is_some_and(|mask| bitmap & !mask & BITMAP_MASK != 0) {
            return Err(FragmentError::UnassignedBitmapBit);
        }
        Ok(ack)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    AckRequest { rule_id: u8, window: u8 },
    SenderAbort { rule_id: u8 },
    ReceiverAbort { rule_id: u8 },
}

impl Control {
    pub fn write_to(self, out: &mut [u8]) -> Result<usize, FragmentError> {
        let (rule_id, body, needed) = match self {
            Self::AckRequest { rule_id, window } if window <= 1 => (rule_id, window << 7, 2),
            Self::AckRequest { .. } => return Err(FragmentError::InvalidWindow),
            Self::SenderAbort { rule_id } => (rule_id, 0xfe, 2),
            Self::ReceiverAbort { rule_id } => (rule_id, 0xff, 3),
        };
        check_rule(rule_id)?;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = rule_id;
        out[1] = body;
        if needed == 3 {
            out[2] = 0xff;
        }
        Ok(needed)
    }
}

pub const fn ack_request(rule_id: u8, window: u8) -> Control {
    Control::AckRequest { rule_id, window }
}

pub const fn sender_abort(rule_id: u8) -> Control {
    Control::SenderAbort { rule_id }
}

pub const fn receiver_abort(rule_id: u8) -> Control {
    Control::ReceiverAbort { rule_id }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderStatus {
    Ready,
    Active,
    Succeeded,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderOutput {
    None,
    Success,
    Abort {
        written: bool,
    },
    Retransmit {
        window: u8,
        missing: u64,
        position: u8,
        request: bool,
    },
    AckRequest {
        written: bool,
    },
}

#[must_use = "dropping a live sender abandons its reserved fragmentation session"]
pub struct FragmentSender<'a, 'policy> {
    payload: &'a [u8],
    policy_owner: Option<&'policy dyn FragmentSessionOwner>,
    rule_id: u8,
    count: usize,
    mic: [u8; MIC_LENGTH],
    attempts: u8,
    status: SenderStatus,
    remote_signer: [u8; 32],
    permit: AuthenticatedFragmentationPermit,
    ack_high_counter: Option<u32>,
    session_id: u32,
    reservation_active: bool,
}

impl core::fmt::Debug for FragmentSender<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FragmentSender")
            .field("rule_id", &self.rule_id)
            .field("count", &self.count)
            .field("attempts", &self.attempts)
            .field("status", &self.status)
            .field("remote_signer", &"[REDACTED]")
            .finish()
    }
}

impl<'a, 'policy> FragmentSender<'a, 'policy> {
    /// Construct a sender only with a current permit from the owning peer policy.
    /// The outbound Rule ID is derived from the full authenticated endpoint keys.
    #[cfg(feature = "std")]
    pub fn new<const MAX_PEERS: usize>(
        policy: &'policy FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        payload: &'a [u8],
        receiver_limit: usize,
        now_ms: u64,
    ) -> Result<Self, FragmentError> {
        if !policy.accepts_current(permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let rule_id = policy.outbound_rule(permit)?;
        let mut sender =
            Self::new_unchecked(payload, rule_id, receiver_limit, *permit, Some(policy))?;
        sender.session_id =
            policy.reserve_sender(permit, rule_id, now_ms, peer.authenticated_counter())?;
        sender.reservation_active = true;
        Ok(sender)
    }

    /// Construct a sender using a current no-std peer authority, deriving the
    /// outbound Rule ID from the authority's local key and the peer signer.
    pub fn new_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        policy: &'policy FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        payload: &'a [u8],
        receiver_limit: usize,
        now_ms: u64,
    ) -> Result<Self, FragmentError> {
        if !policy.accepts_with_authority(permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let rule_id = policy.outbound_rule(permit)?;
        let mut sender =
            Self::new_unchecked(payload, rule_id, receiver_limit, *permit, Some(policy))?;
        sender.session_id =
            policy.reserve_sender(permit, rule_id, now_ms, peer.authenticated_counter())?;
        sender.reservation_active = true;
        Ok(sender)
    }

    fn new_unchecked(
        payload: &'a [u8],
        rule_id: u8,
        receiver_limit: usize,
        permit: AuthenticatedFragmentationPermit,
        policy_owner: Option<&'policy dyn FragmentSessionOwner>,
    ) -> Result<Self, FragmentError> {
        check_rule(rule_id)?;
        if !(1..=MAX_PACKET_SIZE).contains(&receiver_limit) {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        if payload.is_empty() {
            return Err(FragmentError::EmptyPacket);
        }
        if payload.len() > SCHC_FRAG_MAX_PACKET_SIZE {
            return Err(BufferTooSmall::new(SCHC_FRAG_MAX_PACKET_SIZE, payload.len()).into());
        }
        if payload.len() > receiver_limit {
            return Err(FragmentError::PacketTooLarge);
        }
        Ok(FragmentSender {
            payload,
            policy_owner,
            rule_id,
            count: payload.len().div_ceil(TILE_SIZE),
            mic: compute_mic(payload),
            attempts: 0,
            status: SenderStatus::Ready,
            remote_signer: permit.signer,
            permit,
            ack_high_counter: None,
            session_id: 0,
            reservation_active: false,
        })
    }

    pub const fn fragment_count(&self) -> usize {
        self.count
    }

    /// Canonical direction Rule ID derived when this session was reserved.
    pub const fn rule_id(&self) -> u8 {
        self.rule_id
    }

    pub const fn window_count(&self) -> usize {
        self.final_window() as usize + 1
    }

    pub const fn final_window(&self) -> u8 {
        ((self.count - 1) / WINDOW_SIZE) as u8
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn status(&self) -> SenderStatus {
        self.status
    }

    /// Authenticated remote signer this sender is authorized for.
    pub const fn remote_signer(&self) -> &[u8; 32] {
        &self.remote_signer
    }

    fn start_inner(&mut self) -> Result<(), FragmentError> {
        if self.status != SenderStatus::Ready {
            return Err(FragmentError::InvalidState);
        }
        self.status = SenderStatus::Active;
        self.attempts = 1;
        Ok(())
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn start(&mut self) -> Result<(), FragmentError> {
        self.start_inner()
    }

    /// State-producing transition with current std link/policy revalidation.
    #[cfg(feature = "std")]
    pub fn start_current<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<(), FragmentError> {
        if !policy.accepts_current(&self.permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        self.start_inner()
    }

    /// State-producing transition with current no-std authority revalidation.
    pub fn start_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<(), FragmentError> {
        if !policy.accepts_with_authority(&self.permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        self.start_inner()
    }

    fn get_fragment_inner(&self, index: usize) -> Option<Fragment<'a>> {
        if index >= self.count {
            return None;
        }
        let final_fragment = index + 1 == self.count;
        let start = index * TILE_SIZE;
        let end = (start + TILE_SIZE).min(self.payload.len());
        Some(Fragment {
            rule_id: self.rule_id,
            window: (index / WINDOW_SIZE) as u8,
            fcn: if final_fragment {
                ALL_1_FCN
            } else {
                62 - (index % WINDOW_SIZE) as u8
            },
            payload: &self.payload[start..end],
            mic: if final_fragment {
                self.mic
            } else {
                [0; MIC_LENGTH]
            },
        })
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn get_fragment(&self, index: usize) -> Option<Fragment<'a>> {
        self.get_fragment_inner(index)
    }

    #[cfg(feature = "std")]
    pub fn get_fragment_current<const MAX_PEERS: usize>(
        &self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        index: usize,
        now_ms: u64,
    ) -> Result<Option<Fragment<'a>>, FragmentError> {
        if !policy.accepts_current(&self.permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        Ok(self.get_fragment_inner(index))
    }

    pub fn get_fragment_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        index: usize,
        now_ms: u64,
    ) -> Result<Option<Fragment<'a>>, FragmentError> {
        if !policy.accepts_with_authority(&self.permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        Ok(self.get_fragment_inner(index))
    }

    fn iter_inner(&self) -> FragmentIter<'_, 'a, 'policy> {
        FragmentIter {
            sender: self,
            index: 0,
        }
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn iter(&self) -> FragmentIter<'_, 'a, 'policy> {
        self.iter_inner()
    }

    fn assigned_bitmap_inner(&self, window: u8) -> u64 {
        self.iter_inner()
            .filter(|fragment| fragment.window == window)
            .fold(0, |bitmap, fragment| bitmap | fragment_bit(fragment))
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn assigned_bitmap(&self, window: u8) -> u64 {
        self.assigned_bitmap_inner(window)
    }

    fn handle_ack_bytes_inner(&mut self, data: &[u8]) -> Result<SenderOutput, FragmentError> {
        if self.status != SenderStatus::Active || data.first().copied() != Some(self.rule_id) {
            return Ok(SenderOutput::None);
        }
        let mut control = [0u8; 3];
        let abort_len = receiver_abort(self.rule_id).write_to(&mut control)?;
        if data == &control[..abort_len] {
            self.status = SenderStatus::Aborted;
            return Ok(SenderOutput::None);
        }
        let ack = Ack::from_bytes(data)?;
        if ack.complete {
            return Ok(self.handle_ack_inner(ack));
        }
        if ack.window > self.final_window() {
            return Ok(SenderOutput::None);
        }
        let ack = Ack::from_bytes_for(data, Some(self.assigned_bitmap_inner(ack.window)))?;
        Ok(self.handle_ack_inner(ack))
    }

    fn validate_authenticated_control(&self, data: &[u8]) -> Result<(), FragmentError> {
        if self.status != SenderStatus::Active || data.first().copied() != Some(self.rule_id) {
            return Err(FragmentError::MalformedAck);
        }
        let mut control = [0u8; 3];
        let abort_len = receiver_abort(self.rule_id).write_to(&mut control)?;
        if data == &control[..abort_len] {
            return Ok(());
        }
        let ack = Ack::from_bytes(data)?;
        if ack.complete {
            return (ack.window == self.final_window())
                .then_some(())
                .ok_or(FragmentError::MalformedAck);
        }
        if ack.window > self.final_window() {
            return Err(FragmentError::MalformedAck);
        }
        Ack::from_bytes_for(data, Some(self.assigned_bitmap_inner(ack.window)))?;
        Ok(())
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn handle_ack_bytes(&mut self, data: &[u8]) -> Result<SenderOutput, FragmentError> {
        self.handle_ack_bytes_inner(data)
    }

    /// Accept an ACK/control only from a fresh authenticated unicast frame
    /// signed by this session's peer and addressed to this exact local link.
    #[cfg(feature = "std")]
    pub fn handle_ack_frame<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        frame: &lichen_link::link_layer::AuthenticatedFrame,
    ) -> Result<SenderOutput, FragmentError> {
        let counter = (u32::from(frame.epoch()) << 16) | u32::from(u16::from(frame.seqnum()));
        let now_ms = frame
            .receipt()
            .monotonic_millis()
            .ok_or(FragmentError::InvalidPeerEvidence)?;
        if !policy.accepts_current(&self.permit, link, peer)
            || !frame.is_current()
            || frame.sender().pubkey.as_bytes() != &self.remote_signer
            || !frame.is_unicast_for(link)
            || self.ack_high_counter.is_some_and(|high| counter <= high)
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.validate_authenticated_control(frame.payload())?;
        let output = self.handle_ack_bytes_inner(frame.payload())?;
        self.ack_high_counter = Some(counter);
        if matches!(self.status, SenderStatus::Succeeded | SenderStatus::Aborted) {
            policy.release_sender(&self.permit, self.rule_id, self.session_id, now_ms, counter)?;
            self.reservation_active = false;
        } else {
            policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        }
        Ok(output)
    }

    /// no-std ACK/control ingress after the owning link has verified signer,
    /// local destination, replay counter, and receipt clock domain.
    pub fn handle_ack_link_verified<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        input: lichen_link::AuthenticatedLinkFrame<'_>,
    ) -> Result<SenderOutput, FragmentError> {
        if !policy.accepts_with_authority(&self.permit, authority, peer)
            || peer.signer_identity() != &self.remote_signer
            || input.signer() != self.remote_signer
            || input.destination_mode() != lichen_link::frame::AddrMode::Extended
            || input.destination() != authority.local_eui64()
            || input.receipt().clock_domain() != peer.receipt_clock_domain()
            || !input.is_current()
            || self
                .ack_high_counter
                .is_some_and(|high| input.authenticated_counter() <= high)
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.validate_authenticated_control(input.payload())?;
        let output = self.handle_ack_bytes_inner(input.payload())?;
        self.ack_high_counter = Some(input.authenticated_counter());
        if matches!(self.status, SenderStatus::Succeeded | SenderStatus::Aborted) {
            let now_ms = input
                .receipt()
                .monotonic_millis()
                .ok_or(FragmentError::InvalidPeerEvidence)?;
            policy.release_sender(
                &self.permit,
                self.rule_id,
                self.session_id,
                now_ms,
                input.authenticated_counter(),
            )?;
            self.reservation_active = false;
        } else {
            let now_ms = input
                .receipt()
                .monotonic_millis()
                .ok_or(FragmentError::InvalidPeerEvidence)?;
            policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        }
        Ok(output)
    }

    fn handle_ack_inner(&mut self, ack: Ack) -> SenderOutput {
        if self.status != SenderStatus::Active || ack.rule_id != self.rule_id {
            return SenderOutput::None;
        }
        if ack.complete {
            if ack.window != self.final_window() {
                return SenderOutput::None;
            }
            self.status = SenderStatus::Succeeded;
            return SenderOutput::Success;
        }
        if ack.window > self.final_window() {
            return SenderOutput::None;
        }
        let assigned = self.assigned_bitmap_inner(ack.window);
        if ack.bitmap & !assigned & BITMAP_MASK != 0 {
            return SenderOutput::None;
        }
        let missing = assigned & !ack.bitmap;
        if missing == 0 {
            if ack.window == self.final_window() {
                return self.abort_output();
            }
            return SenderOutput::None;
        }
        if u32::from(self.attempts) >= MAX_ACK_REQUESTS {
            return self.abort_output();
        }
        self.attempts += 1;
        let all1_missing = ack.window == self.final_window() && missing & 1 != 0;
        SenderOutput::Retransmit {
            window: ack.window,
            missing,
            position: 0,
            request: !all1_missing,
        }
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn handle_ack(&mut self, ack: Ack) -> SenderOutput {
        self.handle_ack_inner(ack)
    }

    fn timeout_inner(&mut self) -> Result<SenderOutput, FragmentError> {
        if self.status != SenderStatus::Active {
            return Err(FragmentError::InvalidState);
        }
        if u32::from(self.attempts) >= MAX_ACK_REQUESTS {
            return Ok(self.abort_output());
        }
        self.attempts += 1;
        Ok(SenderOutput::AckRequest { written: false })
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn timeout(&mut self) -> Result<SenderOutput, FragmentError> {
        self.timeout_inner()
    }

    /// Timeout transition after revalidating std policy and peer evidence.
    #[cfg(feature = "std")]
    pub fn timeout_current<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<SenderOutput, FragmentError> {
        if !policy.accepts_current(&self.permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        let output = self.timeout_inner()?;
        if self.status == SenderStatus::Aborted {
            policy.release_sender(
                &self.permit,
                self.rule_id,
                self.session_id,
                now_ms,
                self.ack_high_counter
                    .unwrap_or(peer.authenticated_counter()),
            )?;
            self.reservation_active = false;
        }
        Ok(output)
    }

    /// Timeout transition after revalidating no-std policy and peer evidence.
    pub fn timeout_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        now_ms: u64,
    ) -> Result<SenderOutput, FragmentError> {
        if !policy.accepts_with_authority(&self.permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        let output = self.timeout_inner()?;
        if self.status == SenderStatus::Aborted {
            policy.release_sender(
                &self.permit,
                self.rule_id,
                self.session_id,
                now_ms,
                self.ack_high_counter
                    .unwrap_or(peer.authenticated_counter()),
            )?;
            self.reservation_active = false;
        }
        Ok(output)
    }

    /// Explicitly cancel a live tuple and enter terminal hold-down.
    pub fn cancel<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        now_ticks: u64,
    ) -> Result<(), FragmentError> {
        if !matches!(self.status, SenderStatus::Ready | SenderStatus::Active) {
            return Err(FragmentError::InvalidState);
        }
        self.status = SenderStatus::Aborted;
        policy.release_sender(
            &self.permit,
            self.rule_id,
            self.session_id,
            now_ticks,
            self.ack_high_counter.unwrap_or(0),
        )?;
        self.reservation_active = false;
        Ok(())
    }

    fn abort_output(&mut self) -> SenderOutput {
        self.status = SenderStatus::Aborted;
        SenderOutput::Abort { written: false }
    }

    /// Write the next selected retransmission/control message without allocation.
    fn write_next_inner(
        &self,
        output: &mut SenderOutput,
        out: &mut [u8],
    ) -> Result<Option<usize>, FragmentError> {
        match output {
            SenderOutput::None | SenderOutput::Success => Ok(None),
            SenderOutput::Abort { written } => {
                if *written {
                    return Ok(None);
                }
                let length = sender_abort(self.rule_id).write_to(out)?;
                *written = true;
                Ok(Some(length))
            }
            SenderOutput::AckRequest { written } => {
                if self.status != SenderStatus::Active || *written {
                    return Ok(None);
                }
                let length = ack_request(self.rule_id, self.final_window()).write_to(out)?;
                *written = true;
                Ok(Some(length))
            }
            SenderOutput::Retransmit {
                window,
                missing,
                position,
                request,
            } => {
                if self.status != SenderStatus::Active {
                    return Ok(None);
                }
                let mut current = *position;
                while usize::from(current) < WINDOW_SIZE {
                    if *missing & (1u64 << (62 - current)) == 0 {
                        current += 1;
                        continue;
                    }
                    if let Some(fragment) = self.fragment_at_position(*window, current) {
                        let length = fragment.write_to(out)?;
                        *position = current + 1;
                        return Ok(Some(length));
                    }
                    current += 1;
                }
                if *request {
                    let length = ack_request(self.rule_id, self.final_window()).write_to(out)?;
                    *position = WINDOW_SIZE as u8;
                    *request = false;
                    return Ok(Some(length));
                }
                Ok(None)
            }
        }
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn write_next(
        &self,
        output: &mut SenderOutput,
        out: &mut [u8],
    ) -> Result<Option<usize>, FragmentError> {
        self.write_next_inner(output, out)
    }

    #[cfg(feature = "std")]
    pub fn write_next_current<const MAX_PEERS: usize>(
        &self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        output: &mut SenderOutput,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<Option<usize>, FragmentError> {
        if !policy.accepts_current(&self.permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        self.write_next_inner(output, out)
    }

    pub fn write_next_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        output: &mut SenderOutput,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<Option<usize>, FragmentError> {
        if !policy.accepts_with_authority(&self.permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.touch_sender(&self.permit, self.rule_id, self.session_id, now_ms)?;
        self.write_next_inner(output, out)
    }

    fn fragment_at_position(&self, window: u8, position: u8) -> Option<Fragment<'a>> {
        self.iter_inner().find(|fragment| {
            fragment.window == window
                && if fragment.is_all_1() {
                    position == 62
                } else {
                    position == 62 - fragment.fcn
                }
        })
    }
}

#[cfg(feature = "raw-fragment-codec")]
impl<'a> FragmentSender<'a, 'static> {
    /// Construct the unauthenticated codec-only sender used by vector and fuzz
    /// tooling. Production sessions must use an authenticated constructor.
    pub fn new_raw(
        payload: &'a [u8],
        rule_id: u8,
        receiver_limit: usize,
    ) -> Result<Self, FragmentError> {
        Self::new_unchecked(
            payload,
            rule_id,
            receiver_limit,
            AuthenticatedFragmentationPermit {
                owner: 0,
                slot: 0,
                generation: 0,
                key_generation: lichen_link::PeerKeyGeneration::invalid_for_raw_codec(),
                durable_key_generation:
                    lichen_link::DurablePeerKeyGeneration::invalid_for_raw_codec(),
                signer: [0; 32],
            },
            None,
        )
    }
}

impl Drop for FragmentSender<'_, '_> {
    fn drop(&mut self) {
        if self.reservation_active {
            if let Some(policy_owner) = self.policy_owner {
                policy_owner.abandon_sender(
                    &self.permit,
                    self.rule_id,
                    self.session_id,
                    self.ack_high_counter.unwrap_or(0),
                );
            }
            self.reservation_active = false;
        }
    }
}

fn fragment_bit(fragment: Fragment<'_>) -> u64 {
    if fragment.is_all_1() {
        1
    } else {
        1u64 << fragment.fcn
    }
}

pub struct FragmentIter<'s, 'payload, 'policy> {
    sender: &'s FragmentSender<'payload, 'policy>,
    index: usize,
}

impl<'payload> Iterator for FragmentIter<'_, 'payload, '_> {
    type Item = Fragment<'payload>;

    fn next(&mut self) -> Option<Self::Item> {
        let fragment = self.sender.get_fragment_inner(self.index)?;
        self.index += 1;
        Some(fragment)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverResponse {
    Ack(Ack),
    ReceiverAbort { rule_id: u8 },
}

impl ReceiverResponse {
    pub fn write_to(self, out: &mut [u8]) -> Result<usize, FragmentError> {
        match self {
            Self::Ack(ack) => ack.write_to(out),
            Self::ReceiverAbort { rule_id } => receiver_abort(rule_id).write_to(out),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiverResult {
    pub response: Option<ReceiverResponse>,
    pub packet_len: Option<usize>,
    pub mic_ok: Option<bool>,
    pub aborted: bool,
}

pub struct FragmentReceiver<'a> {
    storage: &'a mut [u8],
    limit: usize,
    rule_id: Option<u8>,
    bitmaps: [u64; 2],
    all1: bool,
    all1_window: u8,
    all1_mic: [u8; MIC_LENGTH],
    final_tile: [u8; TILE_SIZE],
    final_len: usize,
    attempts: u8,
    done: bool,
    packet_len: Option<usize>,
}

/// One bounded, authenticated T=0 reassembly session.
///
/// The policy reservation makes the tuple `(local receiver, signer, rule)`
/// unique until a terminal result enters hold-down. Invalid evidence is
/// rejected before the inner reassembly state is touched and produces no ACK.
#[must_use = "dropping a live receiver abandons its reserved reassembly session"]
pub struct AuthenticatedFragmentReceiver<'a, 'policy> {
    inner: FragmentReceiver<'a>,
    policy_owner: &'policy dyn FragmentSessionOwner,
    permit: AuthenticatedFragmentationPermit,
    rule_id: u8,
    signer: [u8; 32],
    high_counter: Option<u32>,
    admission_floor: u32,
    terminal: bool,
    session_id: u32,
}

impl<'a, 'policy> AuthenticatedFragmentReceiver<'a, 'policy> {
    /// Answer a repeated terminal All-1/ACK REQ without allocating or
    /// resurrecting a reassembly session.
    #[cfg(feature = "std")]
    pub fn replay_terminal_frame<const MAX_PEERS: usize>(
        policy: &FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        frame: &lichen_link::link_layer::AuthenticatedFrame,
    ) -> Result<Option<ReceiverResult>, FragmentError> {
        if !policy.accepts_current(permit, link, peer)
            || !frame.is_current()
            || !frame.is_unicast_for(link)
            || frame.sender().pubkey.as_bytes() != peer.signer_identity()
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let now_ms = frame
            .receipt()
            .monotonic_millis()
            .ok_or(FragmentError::InvalidPeerEvidence)?;
        let rule_id = *frame
            .payload()
            .first()
            .ok_or(FragmentError::TooShort(TooShort::new(
                1,
                frame.payload().len(),
            )))?;
        if rule_id != policy.inbound_rule(permit)? {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let counter = (u32::from(frame.epoch()) << 16) | u32::from(frame.seqnum().get());
        policy.replay_receiver_terminal(permit, rule_id, counter, now_ms, frame.payload())
    }

    pub fn replay_terminal_link_evidence<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        policy: &FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        frame: lichen_link::AuthenticatedLinkFrame<'_>,
    ) -> Result<Option<ReceiverResult>, FragmentError> {
        if !policy.accepts_with_authority(permit, authority, peer)
            || !frame.is_current()
            || frame.signer() != *peer.signer_identity()
            || frame.destination_mode() != lichen_link::frame::AddrMode::Extended
            || frame.destination() != authority.local_eui64()
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let now_ms = frame
            .receipt()
            .monotonic_millis()
            .ok_or(FragmentError::InvalidPeerEvidence)?;
        let rule_id = *frame
            .payload()
            .first()
            .ok_or(FragmentError::TooShort(TooShort::new(
                1,
                frame.payload().len(),
            )))?;
        if rule_id != policy.inbound_rule(permit)? {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        policy.replay_receiver_terminal(
            permit,
            rule_id,
            frame.authenticated_counter(),
            now_ms,
            frame.payload(),
        )
    }

    #[cfg(feature = "std")]
    /// Reserve an inbound session whose Rule ID is derived from the full
    /// authenticated endpoint keys.
    pub fn new<const MAX_PEERS: usize>(
        policy: &'policy FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        storage: &'a mut [u8],
        now_ms: u64,
    ) -> Result<Self, FragmentError> {
        let rule_id = policy.inbound_rule(permit)?;
        check_rule(rule_id)?;
        if !policy.accepts_current(permit, link, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let inner = FragmentReceiver::new_inner(storage)
            .map_err(|error| receiver_allocation_error(rule_id, error))?;
        let (session_id, admission_floor) = policy
            .reserve_receiver(permit, rule_id, now_ms, peer.authenticated_counter())
            .map_err(|error| receiver_allocation_error(rule_id, error))?;
        Ok(Self {
            inner,
            policy_owner: policy,
            permit: *permit,
            rule_id,
            signer: *peer.signer_identity(),
            high_counter: None,
            admission_floor,
            terminal: false,
            session_id,
        })
    }

    /// Reserve an inbound no-std session with its canonical derived Rule ID.
    pub fn new_with_authority<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        policy: &'policy FragmentationPolicy<MAX_PEERS>,
        permit: &AuthenticatedFragmentationPermit,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        storage: &'a mut [u8],
        now_ms: u64,
    ) -> Result<Self, FragmentError> {
        let rule_id = policy.inbound_rule(permit)?;
        check_rule(rule_id)?;
        if !policy.accepts_with_authority(permit, authority, peer) {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        let inner = FragmentReceiver::new_inner(storage)
            .map_err(|error| receiver_allocation_error(rule_id, error))?;
        let (session_id, admission_floor) = policy
            .reserve_receiver(permit, rule_id, now_ms, peer.authenticated_counter())
            .map_err(|error| receiver_allocation_error(rule_id, error))?;
        Ok(Self {
            inner,
            policy_owner: policy,
            permit: *permit,
            rule_id,
            signer: *peer.signer_identity(),
            high_counter: None,
            admission_floor,
            terminal: false,
            session_id,
        })
    }

    #[cfg(feature = "std")]
    pub fn receive_frame<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        link: &lichen_link::link_layer::LinkLayer,
        peer: &AuthenticatedPeerSchcContext,
        frame: &lichen_link::link_layer::AuthenticatedFrame,
    ) -> Result<ReceiverResult, FragmentError> {
        let counter = (u32::from(frame.epoch()) << 16) | u32::from(u16::from(frame.seqnum()));
        let now_ms = frame
            .receipt()
            .monotonic_millis()
            .ok_or(FragmentError::InvalidPeerEvidence)?;
        if self.terminal
            || !policy.accepts_current(&self.permit, link, peer)
            || !frame.is_current()
            || frame.sender().pubkey.as_bytes() != &self.signer
            || !frame.is_unicast_for(link)
            || frame.payload().first().copied() != Some(self.rule_id)
            || self.high_counter.is_none()
                && (counter <= self.admission_floor
                    || !is_receiver_session_opener(frame.payload(), self.rule_id))
            || self.high_counter.is_some_and(|high| counter <= high)
            || frame.receipt().clock_domain() != peer.receipt_clock_domain()
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.receive_verified(policy, frame.payload(), counter, now_ms)
    }

    /// no-std TCB ingress after the owning link has verified signature,
    /// destination, replay counter, signer, and receipt clock domain.
    pub fn receive_link_verified<const MAX_PEERS: usize, const MAX_AUTH_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        authority: &PeerContextAuthority<MAX_AUTH_PEERS>,
        peer: &AuthenticatedPeerSchcContext,
        input: lichen_link::AuthenticatedLinkFrame<'_>,
    ) -> Result<ReceiverResult, FragmentError> {
        if self.terminal
            || !policy.accepts_with_authority(&self.permit, authority, peer)
            || peer.signer_identity() != &self.signer
            || input.signer() != self.signer
            || input.destination_mode() != lichen_link::frame::AddrMode::Extended
            || input.destination() != authority.local_eui64()
            || input.payload().first().copied() != Some(self.rule_id)
            || self.high_counter.is_none()
                && (input.authenticated_counter() <= self.admission_floor
                    || !is_receiver_session_opener(input.payload(), self.rule_id))
            || self
                .high_counter
                .is_some_and(|high| input.authenticated_counter() <= high)
            || input.receipt().clock_domain() != peer.receipt_clock_domain()
            || !input.is_current()
        {
            return Err(FragmentError::InvalidPeerEvidence);
        }
        self.receive_verified(
            policy,
            input.payload(),
            input.authenticated_counter(),
            input
                .receipt()
                .monotonic_millis()
                .ok_or(FragmentError::InvalidPeerEvidence)?,
        )
    }

    fn receive_verified<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        payload: &[u8],
        counter: u32,
        receipt_ticks: u64,
    ) -> Result<ReceiverResult, FragmentError> {
        let result = self.inner.receive_bytes_inner(payload)?;
        self.high_counter = Some(counter);
        if result.aborted || result.packet_len.is_some() {
            policy.release_receiver(
                &self.permit,
                self.rule_id,
                self.session_id,
                receipt_ticks,
                counter,
                result,
            )?;
            self.terminal = true;
        } else {
            policy.touch_receiver(
                &self.permit,
                self.rule_id,
                self.session_id,
                receipt_ticks,
                counter,
            )?;
        }
        Ok(result)
    }

    pub fn packet(&self) -> Option<&[u8]> {
        self.inner.packet()
    }

    pub fn cancel<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        now_ticks: u64,
    ) -> Result<(), FragmentError> {
        if self.terminal {
            return Err(FragmentError::InvalidState);
        }
        policy.release_receiver(
            &self.permit,
            self.rule_id,
            self.session_id,
            now_ticks,
            self.high_counter.unwrap_or(0),
            ReceiverResult {
                aborted: true,
                ..ReceiverResult::default()
            },
        )?;
        self.terminal = true;
        Ok(())
    }

    /// Expire an inactive reassembly and retain a replay-safe tombstone.
    pub fn timeout<const MAX_PEERS: usize>(
        &mut self,
        policy: &FragmentationPolicy<MAX_PEERS>,
        now_ms: u64,
    ) -> Result<(), FragmentError> {
        if self.terminal {
            return Err(FragmentError::InvalidState);
        }
        policy.release_receiver(
            &self.permit,
            self.rule_id,
            self.session_id,
            now_ms,
            self.high_counter.unwrap_or(0),
            ReceiverResult::default(),
        )?;
        self.terminal = true;
        Ok(())
    }
}

impl Drop for AuthenticatedFragmentReceiver<'_, '_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.policy_owner.abandon_receiver(
                &self.permit,
                self.rule_id,
                self.session_id,
                self.high_counter.unwrap_or(0),
            );
            self.terminal = true;
        }
    }
}

impl<'a> FragmentReceiver<'a> {
    fn new_inner(storage: &'a mut [u8]) -> Result<Self, FragmentError> {
        let limit = storage.len().min(MAX_PACKET_SIZE);
        if limit == 0 {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        Ok(Self {
            storage,
            limit,
            rule_id: None,
            bitmaps: [0; 2],
            all1: false,
            all1_window: 0,
            all1_mic: [0; MIC_LENGTH],
            final_tile: [0; TILE_SIZE],
            final_len: 0,
            attempts: 0,
            done: false,
            packet_len: None,
        })
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn new(storage: &'a mut [u8]) -> Result<Self, FragmentError> {
        Self::new_inner(storage)
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn with_limit(storage: &'a mut [u8], limit: usize) -> Result<Self, FragmentError> {
        if !(1..=MAX_PACKET_SIZE).contains(&limit) || limit > storage.len() {
            return Err(FragmentError::InvalidReceiverLimit);
        }
        let mut receiver = Self::new_inner(storage)?;
        receiver.limit = limit;
        Ok(receiver)
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn is_done(&self) -> bool {
        self.done
    }

    pub fn packet(&self) -> Option<&[u8]> {
        self.packet_len.map(|length| &self.storage[..length])
    }

    fn receive_bytes_inner(&mut self, data: &[u8]) -> Result<ReceiverResult, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        check_rule(data[0])?;
        let rule_id = data[0];
        let mut control = [0u8; 3];
        for abort in [sender_abort(rule_id), receiver_abort(rule_id)] {
            let length = abort.write_to(&mut control)?;
            if data == &control[..length] {
                self.release();
                return Ok(ReceiverResult {
                    aborted: true,
                    ..ReceiverResult::default()
                });
            }
        }
        let window = data[1] >> 7;
        let request_len = ack_request(rule_id, window).write_to(&mut control)?;
        if data == &control[..request_len] {
            if self.done {
                self.reset();
            }
            return self.receive_ack_request(rule_id);
        }
        let mut tile = [0u8; TILE_SIZE];
        match Fragment::from_bytes(data, &mut tile) {
            Ok(fragment) => {
                if self.done {
                    self.reset();
                }
                Ok(self.receive_inner(&fragment))
            }
            Err(_) if self.done => Ok(ReceiverResult::default()),
            Err(_) => Ok(self.abort(rule_id)),
        }
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn receive_bytes(&mut self, data: &[u8]) -> Result<ReceiverResult, FragmentError> {
        self.receive_bytes_inner(data)
    }

    fn receive_inner(&mut self, fragment: &Fragment<'_>) -> ReceiverResult {
        let valid = check_rule(fragment.rule_id).is_ok()
            && fragment.window <= 1
            && fragment.fcn <= ALL_1_FCN
            && (fragment.is_all_1() || fragment.window == 0 || fragment.fcn != 0)
            && (fragment.is_all_1() && (1..=TILE_SIZE).contains(&fragment.payload.len())
                || !fragment.is_all_1()
                    && fragment.payload.len() == TILE_SIZE
                    && fragment.mic == [0; MIC_LENGTH]);
        if self.done {
            if !valid {
                return ReceiverResult::default();
            }
            self.reset();
        }
        if !valid {
            return self.abort(fragment.rule_id);
        }
        if let Some(active) = self.rule_id {
            if active != fragment.rule_id {
                return self.abort(active);
            }
        } else {
            self.rule_id = Some(fragment.rule_id);
        }

        if fragment.is_all_1() {
            return self.receive_all1(fragment);
        }
        if fragment.window == 1 && fragment.fcn == 0 {
            return self.abort(fragment.rule_id);
        }
        if self.all1
            && (fragment.window > self.all1_window
                || (fragment.window == self.all1_window && fragment.fcn == 0))
        {
            return self.abort(fragment.rule_id);
        }
        let ordinal = usize::from(fragment.window) * WINDOW_SIZE + 62 - usize::from(fragment.fcn);
        let end = (ordinal + 1) * TILE_SIZE;
        if end > self.limit {
            return self.abort(fragment.rule_id);
        }
        let bit = 1u64 << fragment.fcn;
        let bitmap = &mut self.bitmaps[usize::from(fragment.window)];
        let destination = &mut self.storage[ordinal * TILE_SIZE..end];
        if *bitmap & bit != 0 {
            if destination != fragment.payload {
                return self.abort(fragment.rule_id);
            }
            return ReceiverResult::default();
        }
        destination.copy_from_slice(fragment.payload);
        *bitmap |= bit;
        ReceiverResult::default()
    }

    #[cfg(feature = "raw-fragment-codec")]
    pub fn receive(&mut self, fragment: &Fragment<'_>) -> ReceiverResult {
        self.receive_inner(fragment)
    }

    fn receive_all1(&mut self, fragment: &Fragment<'_>) -> ReceiverResult {
        if self
            .bitmaps
            .iter()
            .skip(usize::from(fragment.window) + 1)
            .any(|&b| b != 0)
            || self.bitmaps[usize::from(fragment.window)] & 1 != 0
        {
            return self.abort(fragment.rule_id);
        }
        if self.all1 {
            if self.all1_window != fragment.window
                || self.all1_mic != fragment.mic
                || self.final_tile[..self.final_len] != *fragment.payload
            {
                return self.abort(fragment.rule_id);
            }
            return self.finalize();
        }
        let retained = (self.bitmaps[0].count_ones() + self.bitmaps[1].count_ones()) as usize
            * TILE_SIZE
            + fragment.payload.len();
        if retained > self.limit {
            return self.abort(fragment.rule_id);
        }
        self.all1 = true;
        self.all1_window = fragment.window;
        self.all1_mic = fragment.mic;
        self.final_len = fragment.payload.len();
        self.final_tile[..self.final_len].copy_from_slice(fragment.payload);
        self.finalize()
    }

    fn receive_ack_request(&mut self, rule_id: u8) -> Result<ReceiverResult, FragmentError> {
        if let Some(active) = self.rule_id {
            if active != rule_id {
                return Ok(self.abort(active));
            }
        } else {
            self.rule_id = Some(rule_id);
        }
        if self.all1 {
            return Ok(self.finalize());
        }
        let window = u8::from(self.bitmaps[0] == BITMAP_MASK);
        Ok(self.respond(Ack::new(
            rule_id,
            window,
            self.bitmaps[usize::from(window)],
            false,
        )))
    }

    fn finalize(&mut self) -> ReceiverResult {
        let rule_id = self.rule_id.unwrap_or(RULE_ID_A_TO_B);
        if self.all1_window == 1 && self.bitmaps[0] != BITMAP_MASK {
            return self.respond(Ack::new(rule_id, 0, self.bitmaps[0], false));
        }
        let final_base = usize::from(self.all1_window) * WINDOW_SIZE;
        let bitmap = self.bitmaps[usize::from(self.all1_window)];
        let regular_count = if bitmap == 0 {
            0
        } else {
            WINDOW_SIZE - bitmap.trailing_zeros() as usize
        };
        let required = if regular_count == 0 {
            0
        } else {
            BITMAP_MASK & !(BITMAP_MASK >> regular_count)
        };
        if bitmap & required != required {
            return self.respond(Ack::new(rule_id, self.all1_window, bitmap | 1, false));
        }
        let packet_len = (final_base + regular_count) * TILE_SIZE + self.final_len;
        if packet_len > self.limit {
            return self.abort(rule_id);
        }
        let final_offset = (final_base + regular_count) * TILE_SIZE;
        self.storage[final_offset..packet_len].copy_from_slice(&self.final_tile[..self.final_len]);
        if compute_mic(&self.storage[..packet_len]) == self.all1_mic {
            self.packet_len = Some(packet_len);
            let result = self.respond_with_packet(Ack::new(rule_id, self.all1_window, 0, true));
            self.done = true;
            result
        } else {
            // RFC 8724 section 8.4.2.3: When MIC fails, indicate whether All-1 needs
            // retransmission. If all expected regular fragments (per trailing_zeros)
            // are present AND contiguous from bit 62, the All-1 payload/MIC is likely
            // corrupt; request its retransmission (bit 0 = 0). Otherwise, fragments
            // might be missing; mark All-1 as received (bit 0 = 1) so the sender only
            // retransmits the missing regular fragments.
            let full_window = bitmap == required && bitmap.count_ones() == regular_count as u32;
            let ack_bitmap = if full_window && regular_count > 1 {
                bitmap
            } else {
                bitmap | 1
            };
            self.respond_with_mic_failure(Ack::new(rule_id, self.all1_window, ack_bitmap, false))
        }
    }

    fn respond(&mut self, ack: Ack) -> ReceiverResult {
        if u32::from(self.attempts) >= MAX_ACK_REQUESTS {
            return self.abort(ack.rule_id);
        }
        self.attempts += 1;
        ReceiverResult {
            response: Some(ReceiverResponse::Ack(ack)),
            ..ReceiverResult::default()
        }
    }

    fn respond_with_packet(&mut self, ack: Ack) -> ReceiverResult {
        let packet_len = self.packet_len;
        let mut result = self.respond(ack);
        if !result.aborted {
            result.packet_len = packet_len;
            result.mic_ok = Some(true);
        }
        result
    }

    fn respond_with_mic_failure(&mut self, ack: Ack) -> ReceiverResult {
        let mut result = self.respond(ack);
        if !result.aborted {
            result.mic_ok = Some(false);
        }
        result
    }

    fn abort(&mut self, rule_id: u8) -> ReceiverResult {
        self.release();
        ReceiverResult {
            response: Some(ReceiverResponse::ReceiverAbort { rule_id }),
            aborted: true,
            ..ReceiverResult::default()
        }
    }

    pub fn expire(&mut self) -> Option<ReceiverResponse> {
        let rule_id = self.rule_id?;
        if self.done {
            return None;
        }
        self.release();
        Some(ReceiverResponse::ReceiverAbort { rule_id })
    }

    pub fn release(&mut self) {
        self.reset();
        self.done = true;
    }

    fn reset(&mut self) {
        self.bitmaps = [0; 2];
        self.all1 = false;
        self.rule_id = None;
        self.final_len = 0;
        self.attempts = 0;
        self.packet_len = None;
        self.done = false;
    }
}

#[derive(Debug)]
pub struct RetransmitIter<'s, 'payload, 'policy, 'bitmap> {
    sender: &'s FragmentSender<'payload, 'policy>,
    start: usize,
    end: usize,
    bitmap: &'bitmap [bool],
    pos: usize,
}

impl<'payload> Iterator for RetransmitIter<'_, 'payload, '_, '_> {
    type Item = Fragment<'payload>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.end {
                return None;
            }
            let abs_pos = self.pos;
            let rel_pos = abs_pos - self.start;
            self.pos += 1;
            let received = rel_pos < self.bitmap.len() && self.bitmap[rel_pos];
            if !received {
                return self.sender.get_fragment_inner(abs_pos);
            }
        }
    }
}

// ─── std-only: all_fragments convenience method ───────────────────────────────

#[cfg(all(feature = "std", feature = "raw-fragment-codec"))]
mod std_ext {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    impl<'a> FragmentSender<'a, '_> {
        /// Collect all fragments into a Vec (convenience for tests and sim).
        pub fn all_fragments(&self) -> Vec<Fragment<'a>> {
            self.iter().collect()
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-utils")]
    #[allow(clippy::too_many_arguments)]
    fn authenticated_input<'a>(
        payload: &'a [u8],
        destination: &'a [u8; 8],
        signer: [u8; 32],
        counter: u16,
        now_ms: u64,
        key_generation: u64,
        receiving_link_retired: &'a core::sync::atomic::AtomicBool,
        peer_generation_retired: &'a core::sync::atomic::AtomicBool,
    ) -> lichen_link::AuthenticatedLinkFrame<'a> {
        lichen_link::AuthenticatedLinkFrame::from_test_parts(
            payload,
            destination,
            lichen_link::frame::AddrMode::Extended,
            signer,
            [0; 8],
            0,
            lichen_link::LinkSeqNum::new(counter),
            lichen_link::ReceiptEvidence::from_test_parts(7, now_ms, Some(now_ms)),
            lichen_link::PeerKeyGeneration::from_test_value(key_generation).unwrap(),
            lichen_link::DurablePeerKeyGeneration::from_test_value(key_generation).unwrap(),
            receiving_link_retired,
            peer_generation_retired,
        )
    }

    fn authorized_peer(
        counter: u32,
    ) -> (
        PeerContextAuthority<1>,
        AuthenticatedPeerSchcContext,
        FragmentationPolicy<1>,
        AuthenticatedFragmentationPermit,
    ) {
        let mut authority = PeerContextAuthority::<1>::new([0x24; 32]).unwrap();
        let peer = authority
            .issue_test_peer([0x42; 32], counter, 3, 7, u64::from(counter))
            .unwrap();
        let mut policy = FragmentationPolicy::<1>::new().unwrap();
        let permit = policy
            .accept_peer_with_authority(&authority, &peer, u64::from(counter))
            .unwrap();
        (authority, peer, policy, permit)
    }

    #[test]
    fn public_profile_constants_describe_the_fixed_v3_window() {
        assert_eq!(WINDOW_SIZE, (1usize << FRAGMENT_N) - 1);
        assert_eq!(WINDOW_SIZE, 63);
        assert_eq!(BITMAP_MASK.count_ones() as usize, WINDOW_SIZE);
        assert_eq!([RULE_ID_A_TO_B, RULE_ID_B_TO_A], [0x78, 0x79]);
    }

    #[test]
    fn full_signer_order_derives_both_directions_and_rejects_self_sessions() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        assert_eq!(
            canonical_fragmentation_rule(&a, &b, true),
            Ok(RULE_ID_A_TO_B)
        );
        assert_eq!(
            canonical_fragmentation_rule(&a, &b, false),
            Ok(RULE_ID_B_TO_A)
        );
        assert_eq!(
            canonical_fragmentation_rule(&b, &a, true),
            Ok(RULE_ID_B_TO_A)
        );
        assert_eq!(
            canonical_fragmentation_rule(&b, &a, false),
            Ok(RULE_ID_A_TO_B)
        );
        assert_eq!(
            canonical_fragmentation_rule(&a, &a, true),
            Err(FragmentError::InvalidPeerEvidence)
        );
    }

    #[test]
    fn crc_includes_zero_octet() {
        assert_eq!(compute_mic(b"123456789"), [0x00, 0xc4, 0x9e, 0x49]);
    }

    #[test]
    fn literal_regular_fragment() {
        let tile = [0u8; TILE_SIZE];
        let fragment = Fragment {
            rule_id: RULE_ID_A_TO_B,
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; MIC_LENGTH],
        };
        let mut wire = [0xff; TILE_SIZE + 2];
        assert_eq!(fragment.write_to(&mut wire), Ok(wire.len()));
        assert_eq!(&wire[..2], &[RULE_ID_A_TO_B, 0x7c]);
        assert!(wire[2..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn literal_ack_and_controls() {
        let ack = Ack::new(RULE_ID_A_TO_B, 1, 0, true);
        let mut wire = [0; 10];
        assert_eq!(ack.write_to(&mut wire), Ok(2));
        assert_eq!(&wire[..2], &[RULE_ID_A_TO_B, 0xc0]);
        assert_eq!(sender_abort(RULE_ID_A_TO_B).write_to(&mut wire), Ok(2));
        assert_eq!(&wire[..2], &[RULE_ID_A_TO_B, 0xfe]);
        assert_eq!(receiver_abort(RULE_ID_A_TO_B).write_to(&mut wire), Ok(3));
        assert_eq!(&wire[..3], &[RULE_ID_A_TO_B, 0xff, 0xff]);
    }

    #[test]
    fn receiver_limit_rejection_does_not_consume_tuple() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let payload = [0x55; 65];
        assert!(matches!(
            FragmentSender::new_with_authority(
                &policy, &permit, &authority, &peer, &payload, 64, 1,
            ),
            Err(FragmentError::PacketTooLarge)
        ));
        let _sender = FragmentSender::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &payload[..64],
            64,
            1,
        )
        .unwrap();
    }

    #[test]
    fn dropping_authenticated_handles_releases_live_reservations() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let payload = [0x55; 16];
        let sender = FragmentSender::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &payload,
            payload.len(),
            1,
        )
        .unwrap();
        let outbound = rule_index(sender.rule_id()).unwrap();
        assert!(policy.current_entry_mut(&permit).unwrap().sender_sessions[outbound].is_some());
        drop(sender);
        let entry = policy.current_entry_mut(&permit).unwrap();
        assert!(entry.sender_sessions[outbound].is_none());
        assert!(entry.sender_tombstones[outbound].is_some());
        drop(entry);

        let inbound_rule = policy.inbound_rule(&permit).unwrap();
        let inbound = rule_index(inbound_rule).unwrap();
        let mut storage = [0u8; 256];
        let receiver = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut storage,
            1,
        )
        .unwrap();
        assert!(policy.current_entry_mut(&permit).unwrap().receiver_sessions[inbound].is_some());
        drop(receiver);
        let entry = policy.current_entry_mut(&permit).unwrap();
        assert!(entry.receiver_sessions[inbound].is_none());
        assert!(entry.receiver_tombstones[inbound].is_some());
    }

    #[test]
    fn t_zero_tuple_is_unique_and_policy_retirement_blocks_transition() {
        let (mut authority, peer, policy, permit) = authorized_peer(1);
        let payload = [0x55; 16];
        let mut first = FragmentSender::new_with_authority(
            &policy, &permit, &authority, &peer, &payload, 64, 1,
        )
        .unwrap();
        assert!(matches!(
            FragmentSender::new_with_authority(
                &policy, &permit, &authority, &peer, &payload, 64, 1,
            ),
            Err(FragmentError::SessionBusy)
        ));
        authority.retire(peer.signer_identity());
        assert_eq!(
            first.start_with_authority(&policy, &authority, &peer, 2),
            Err(FragmentError::InvalidPeerEvidence)
        );
        assert_eq!(
            first.get_fragment_with_authority(&policy, &authority, &peer, 0, 2),
            Err(FragmentError::InvalidPeerEvidence)
        );
        assert_eq!(first.status(), SenderStatus::Ready);
    }

    #[test]
    fn inactivity_enters_hold_down_and_stale_owner_cannot_release_replacement() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let payload = [0x55; 16];
        let mut stale = FragmentSender::new_with_authority(
            &policy, &permit, &authority, &peer, &payload, 64, 1,
        )
        .unwrap();
        assert!(matches!(
            FragmentSender::new_with_authority(
                &policy,
                &permit,
                &authority,
                &peer,
                &payload,
                64,
                1 + INACTIVITY_TIMEOUT_MILLIS,
            ),
            Err(FragmentError::SessionBusy)
        ));
        let _replacement = FragmentSender::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &payload,
            64,
            1 + INACTIVITY_TIMEOUT_MILLIS + FRAGMENT_TOMBSTONE_MILLIS,
        )
        .unwrap();
        assert_eq!(
            stale.cancel(
                &policy,
                2 + INACTIVITY_TIMEOUT_MILLIS + FRAGMENT_TOMBSTONE_MILLIS,
            ),
            Err(FragmentError::InvalidState)
        );
        assert!(matches!(
            FragmentSender::new_with_authority(
                &policy,
                &permit,
                &authority,
                &peer,
                &payload,
                64,
                2 + INACTIVITY_TIMEOUT_MILLIS + FRAGMENT_TOMBSTONE_MILLIS,
            ),
            Err(FragmentError::SessionBusy)
        ));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn authenticated_sender_ack_high_water_rejects_replay() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let payload = [0x55; 16];
        let mut sender = FragmentSender::new_with_authority(
            &policy, &permit, &authority, &peer, &payload, 64, 1,
        )
        .unwrap();
        sender
            .start_with_authority(&policy, &authority, &peer, 1)
            .unwrap();
        let mut ack_wire = [0u8; 10];
        let ack_len = Ack::new(RULE_ID_A_TO_B, 0, 0, true)
            .write_to(&mut ack_wire)
            .unwrap();
        let receiving_link_retired = core::sync::atomic::AtomicBool::new(false);
        let peer_generation_retired = core::sync::atomic::AtomicBool::new(false);
        let receipt = lichen_link::ReceiptEvidence::from_test_parts(7, 2, Some(2));
        let input = lichen_link::AuthenticatedLinkFrame::from_test_parts(
            &ack_wire[..ack_len],
            authority.local_eui64(),
            lichen_link::frame::AddrMode::Extended,
            *peer.signer_identity(),
            [0; 8],
            0,
            lichen_link::LinkSeqNum::new(2),
            receipt,
            lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
            lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
            &receiving_link_retired,
            &peer_generation_retired,
        );
        assert_eq!(
            sender
                .handle_ack_link_verified(&policy, &authority, &peer, input)
                .unwrap(),
            SenderOutput::Success
        );
        assert_eq!(
            sender.handle_ack_link_verified(&policy, &authority, &peer, input),
            Err(FragmentError::InvalidPeerEvidence)
        );
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn authenticated_receiver_allocation_failure_carries_receiver_abort() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let inbound_rule = policy.inbound_rule(&permit).unwrap();
        let mut storage = [];
        let result = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut storage,
            1,
        );
        assert!(matches!(
            result,
            Err(FragmentError::ReceiverAllocationRejected {
                response: ReceiverResponse::ReceiverAbort {
                    rule_id
                }
            }) if rule_id == inbound_rule
        ));
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn authenticated_receiver_rejects_replay_before_state_mutation() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let inbound_rule = policy.inbound_rule(&permit).unwrap();
        let mut storage = [0u8; 256];
        let mut receiver = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut storage,
            1,
        )
        .unwrap();
        let tile = [0x23; TILE_SIZE];
        let wrong_direction = Fragment {
            rule_id: policy.outbound_rule(&permit).unwrap(),
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; MIC_LENGTH],
        };
        let mut wrong_wire = [0u8; TILE_SIZE + 2];
        let wrong_len = wrong_direction.write_to(&mut wrong_wire).unwrap();
        let fragment = Fragment {
            rule_id: inbound_rule,
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; MIC_LENGTH],
        };
        let mut wire = [0u8; TILE_SIZE + 2];
        let len = fragment.write_to(&mut wire).unwrap();
        let receiving_link_retired = core::sync::atomic::AtomicBool::new(false);
        let peer_generation_retired = core::sync::atomic::AtomicBool::new(false);
        let receipt = lichen_link::ReceiptEvidence::from_test_parts(7, 2, Some(2));
        let wrong_input = lichen_link::AuthenticatedLinkFrame::from_test_parts(
            &wrong_wire[..wrong_len],
            authority.local_eui64(),
            lichen_link::frame::AddrMode::Extended,
            *peer.signer_identity(),
            [0; 8],
            0,
            lichen_link::LinkSeqNum::new(2),
            receipt,
            lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
            lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
            &receiving_link_retired,
            &peer_generation_retired,
        );
        assert_eq!(
            receiver.receive_link_verified(&policy, &authority, &peer, wrong_input),
            Err(FragmentError::InvalidPeerEvidence)
        );
        let input = lichen_link::AuthenticatedLinkFrame::from_test_parts(
            &wire[..len],
            authority.local_eui64(),
            lichen_link::frame::AddrMode::Extended,
            *peer.signer_identity(),
            [0; 8],
            0,
            lichen_link::LinkSeqNum::new(2),
            receipt,
            lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
            lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
            &receiving_link_retired,
            &peer_generation_retired,
        );
        receiver
            .receive_link_verified(&policy, &authority, &peer, input)
            .unwrap();
        assert!(matches!(
            receiver.receive_link_verified(&policy, &authority, &peer, input),
            Err(FragmentError::InvalidPeerEvidence)
        ));
        assert!(receiver.packet().is_none());
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn terminal_late_messages_advance_durable_replacement_floor() {
        let (authority, peer, policy, permit) = authorized_peer(1);
        let rule_id = policy.inbound_rule(&permit).unwrap();
        let tile = [0x23; TILE_SIZE];
        let opener = Fragment {
            rule_id,
            window: 0,
            fcn: 62,
            payload: &tile,
            mic: [0; MIC_LENGTH],
        };
        let late_regular = Fragment { fcn: 61, ..opener };
        let late_all1 = Fragment {
            fcn: ALL_1_FCN,
            payload: &[0x55],
            mic: compute_mic(&[0x55]),
            ..opener
        };
        let mut opener_wire = [0u8; TILE_SIZE + 2];
        let opener_len = opener.write_to(&mut opener_wire).unwrap();
        let mut regular_wire = [0u8; TILE_SIZE + 2];
        let regular_len = late_regular.write_to(&mut regular_wire).unwrap();
        let mut all1_wire = [0u8; TILE_SIZE + MIC_LENGTH + 2];
        let all1_len = late_all1.write_to(&mut all1_wire).unwrap();
        let receiving_link_retired = core::sync::atomic::AtomicBool::new(false);
        let peer_generation_retired = core::sync::atomic::AtomicBool::new(false);

        let mut storage = [0u8; MAX_PACKET_SIZE];
        let mut receiver = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut storage,
            1,
        )
        .unwrap();
        receiver
            .receive_link_verified(
                &policy,
                &authority,
                &peer,
                authenticated_input(
                    &opener_wire[..opener_len],
                    authority.local_eui64(),
                    *peer.signer_identity(),
                    2,
                    2,
                    1,
                    &receiving_link_retired,
                    &peer_generation_retired,
                ),
            )
            .unwrap();
        receiver.cancel(&policy, 3).unwrap();
        drop(receiver);

        assert_eq!(
            AuthenticatedFragmentReceiver::replay_terminal_link_evidence(
                &policy,
                &permit,
                &authority,
                &peer,
                authenticated_input(
                    &regular_wire[..regular_len],
                    authority.local_eui64(),
                    *peer.signer_identity(),
                    3,
                    4,
                    1,
                    &receiving_link_retired,
                    &peer_generation_retired,
                ),
            ),
            Ok(None)
        );
        assert_eq!(
            policy.snapshot_for_tests().max_receiver_high_counter,
            Some(3)
        );
        assert!(
            AuthenticatedFragmentReceiver::replay_terminal_link_evidence(
                &policy,
                &permit,
                &authority,
                &peer,
                authenticated_input(
                    &all1_wire[..all1_len],
                    authority.local_eui64(),
                    *peer.signer_identity(),
                    4,
                    5,
                    1,
                    &receiving_link_retired,
                    &peer_generation_retired,
                ),
            )
            .unwrap()
            .is_some_and(|result| result.aborted)
        );

        let after_hold_down = 3 + FRAGMENT_TOMBSTONE_MILLIS;
        assert_eq!(
            AuthenticatedFragmentReceiver::replay_terminal_link_evidence(
                &policy,
                &permit,
                &authority,
                &peer,
                authenticated_input(
                    &regular_wire[..regular_len],
                    authority.local_eui64(),
                    *peer.signer_identity(),
                    5,
                    after_hold_down,
                    1,
                    &receiving_link_retired,
                    &peer_generation_retired,
                ),
            ),
            Ok(None)
        );
        assert_eq!(
            policy.snapshot_for_tests().max_receiver_high_counter,
            Some(5)
        );

        let mut replacement_storage = [0u8; MAX_PACKET_SIZE];
        let mut replacement = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &permit,
            &authority,
            &peer,
            &mut replacement_storage,
            after_hold_down + 1,
        )
        .unwrap();
        replacement
            .receive_link_verified(
                &policy,
                &authority,
                &peer,
                authenticated_input(
                    &opener_wire[..opener_len],
                    authority.local_eui64(),
                    *peer.signer_identity(),
                    6,
                    after_hold_down + 1,
                    1,
                    &receiving_link_retired,
                    &peer_generation_retired,
                ),
            )
            .unwrap();
        assert_eq!(
            policy.snapshot_for_tests().max_receiver_high_counter,
            Some(6)
        );
    }

    #[cfg(feature = "test-utils")]
    #[test]
    fn same_public_key_reinstall_gets_distinct_fragmentation_owner() {
        let mut authority = PeerContextAuthority::<1>::new([0x24; 32]).unwrap();
        let signer = [0x42; 32];
        let old_peer = authority
            .issue_test_peer_for_generation(
                signer,
                1,
                3,
                7,
                1,
                lichen_link::PeerKeyGeneration::from_test_value(1).unwrap(),
                lichen_link::DurablePeerKeyGeneration::from_test_value(1).unwrap(),
            )
            .unwrap();
        let mut policy = FragmentationPolicy::<1>::new().unwrap();
        let old_permit = policy
            .accept_peer_with_authority(&authority, &old_peer, 1)
            .unwrap();
        let mut old_storage = [0u8; MAX_PACKET_SIZE];
        let old_receiver = AuthenticatedFragmentReceiver::new_with_authority(
            &policy,
            &old_permit,
            &authority,
            &old_peer,
            &mut old_storage,
            1,
        )
        .unwrap();
        drop(old_receiver);
        assert_eq!(policy.snapshot_for_tests().receiver_tombstone_count, 1);

        let new_peer = authority
            .issue_test_peer_for_generation(
                signer,
                1,
                3,
                7,
                2,
                lichen_link::PeerKeyGeneration::from_test_value(2).unwrap(),
                lichen_link::DurablePeerKeyGeneration::from_test_value(2).unwrap(),
            )
            .unwrap();
        assert!(!authority.is_current(&old_peer));
        let new_permit = policy
            .accept_peer_with_authority(&authority, &new_peer, 2)
            .unwrap();
        assert_eq!(
            policy.inbound_rule(&old_permit),
            Err(FragmentError::InvalidPeerEvidence)
        );
        assert_eq!(
            policy.inbound_rule(&new_permit),
            canonical_fragmentation_rule(&[0x24; 32], &signer, false)
        );
        let snapshot = policy.snapshot_for_tests();
        assert_eq!(snapshot.receiver_session_count, 0);
        assert_eq!(snapshot.receiver_tombstone_count, 0);
    }

    #[cfg(all(feature = "std", feature = "test-utils"))]
    #[test]
    fn signed_floor_restores_only_with_exact_durable_trust_generation() {
        use lichen_link::identity::{Identity, PeerIdentity};
        use lichen_link::link_layer::LinkLayer;
        use lichen_link::{LinkSeqNum, Seed};

        fn dio_payload(remote: &Identity) -> (std::vec::Vec<u8>, [u8; 16]) {
            let mut source = [0u8; 16];
            source[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
            source[8..].copy_from_slice(&remote.iid);
            let destination = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a];
            let dodag = lichen_link::ygg_addr_from_pubkey(remote.pubkey.as_bytes());
            let mut ipv6 = std::vec![0u8; 40 + 4 + 27];
            ipv6[0] = 0x60;
            ipv6[4..6].copy_from_slice(&(31u16).to_be_bytes());
            ipv6[6] = 58;
            ipv6[7] = 255;
            ipv6[8..24].copy_from_slice(&source);
            ipv6[24..40].copy_from_slice(&destination);
            ipv6[40] = 155;
            ipv6[41] = 1;
            ipv6[44..52].copy_from_slice(&[0, 1, 1, 0, 0x08, 0, 0, 0]);
            ipv6[52..68].copy_from_slice(&dodag);
            ipv6[68..71].copy_from_slice(&[0x13, 0x01, 0x03]);
            let checksum =
                lichen_core::checksum::upper_layer_checksum(&source, &destination, 58, &ipv6[40..]);
            ipv6[42..44].copy_from_slice(&checksum.to_be_bytes());
            let mut payload = std::vec![lichen_core::constants::L2_DISPATCH_SCHC, 0xff];
            payload.extend_from_slice(&ipv6);
            (payload, dodag)
        }

        fn authenticate_dio(
            sender: &LinkLayer,
            receiver: &mut LinkLayer,
            payload: &[u8],
            dodag: &[u8; 16],
            sequence: u16,
            now_ms: u64,
        ) -> AuthenticatedPeerSchcContext {
            let mut wire = [0u8; 256];
            let length = sender
                .build_frame(0, LinkSeqNum::new(sequence), &[], payload, &mut wire)
                .unwrap();
            let frame = receiver.receive_frame_at(&wire[..length], now_ms).unwrap();
            AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
                frame,
                0,
                dodag,
                1,
                crate::ExpectedDioRole::Root,
            )
            .unwrap()
        }

        let remote = Identity::from_seed(Seed::new([0xe5; 32]));
        let local_seed = Seed::new([0xf6; 32]);
        let sender = LinkLayer::new(Identity::from_seed(Seed::new([0xe5; 32])));
        let mut receiver = LinkLayer::new(Identity::from_seed(local_seed.clone()));
        receiver.add_peer(PeerIdentity::from_pubkey(remote.pubkey));
        let (dio, dodag) = dio_payload(&remote);
        let peer = authenticate_dio(&sender, &mut receiver, &dio, &dodag, 1, 1);
        let durable = peer.durable_key_generation();
        let mut policy = FragmentationPolicy::<1>::new().unwrap();
        let permit = policy.accept_peer(&receiver, &peer, 1).unwrap();
        let rule = policy.inbound_rule(&permit).unwrap();
        let opener = Fragment {
            rule_id: rule,
            window: 0,
            fcn: 62,
            payload: &[0x55; TILE_SIZE],
            mic: [0; MIC_LENGTH],
        };
        let mut opener_payload = [0u8; TILE_SIZE + 2];
        let opener_len = opener.write_to(&mut opener_payload).unwrap();
        let mut wire = [0u8; 256];
        let wire_len = sender
            .build_frame(
                0,
                LinkSeqNum::new(2),
                &receiver.local_eui64(),
                &opener_payload[..opener_len],
                &mut wire,
            )
            .unwrap();
        let opener_frame = receiver.receive_frame_at(&wire[..wire_len], 2).unwrap();
        let mut storage = [0u8; MAX_PACKET_SIZE];
        let mut reassembly =
            AuthenticatedFragmentReceiver::new(&policy, &permit, &receiver, &peer, &mut storage, 1)
                .unwrap();
        reassembly
            .receive_frame(&policy, &receiver, &peer, &opener_frame)
            .unwrap();
        reassembly.cancel(&policy, 3).unwrap();
        drop(reassembly);

        let revision = 11;
        let mut floor_record = [0u8; 256];
        let floor_len = policy
            .persist_receiver_floor(&permit, &receiver, &peer, revision, &mut floor_record)
            .unwrap();
        let mut trust_record = [0u8; 256];
        let trust_len = receiver
            .persist_peer_trust_state(
                &remote.iid,
                revision,
                Some(&floor_record[..floor_len]),
                &mut trust_record,
            )
            .unwrap();
        drop(peer);
        drop(receiver);

        let mut restored = LinkLayer::new(Identity::from_seed(local_seed));
        assert_eq!(
            restored.restore_peer_trust_state(&trust_record[..trust_len], revision),
            Ok(revision)
        );
        let restored_peer = authenticate_dio(&sender, &mut restored, &dio, &dodag, 3, 4);
        assert_eq!(restored_peer.durable_key_generation(), durable);
        let mut restored_policy = FragmentationPolicy::<1>::new().unwrap();
        let restored_permit = restored_policy
            .accept_peer(&restored, &restored_peer, 4)
            .unwrap();
        let mut blocked_storage = [0u8; MAX_PACKET_SIZE];
        assert!(matches!(
            AuthenticatedFragmentReceiver::new(
                &restored_policy,
                &restored_permit,
                &restored,
                &restored_peer,
                &mut blocked_storage,
                4,
            ),
            Err(FragmentError::InvalidPeerEvidence)
        ));

        let mut corrupt = floor_record[..floor_len].to_vec();
        corrupt[7] ^= 1;
        let mut oversized = floor_record[..floor_len].to_vec();
        oversized.push(0);
        for malformed in [&floor_record[..floor_len - 1], oversized.as_slice()] {
            assert_eq!(
                restored_policy.restore_receiver_floor(
                    &restored_permit,
                    &restored,
                    &restored_peer,
                    malformed,
                    revision,
                    4,
                ),
                Err(FragmentError::InvalidPersistentState)
            );
        }
        assert_eq!(
            restored_policy.restore_receiver_floor(
                &restored_permit,
                &restored,
                &restored_peer,
                &corrupt,
                revision,
                4,
            ),
            Err(FragmentError::InvalidPersistentState)
        );
        assert_eq!(
            restored_policy.restore_receiver_floor(
                &restored_permit,
                &restored,
                &restored_peer,
                &floor_record[..floor_len],
                revision + 1,
                4,
            ),
            Err(FragmentError::PersistentRollback)
        );
        assert_eq!(
            restored_policy.restore_receiver_floor(
                &restored_permit,
                &restored,
                &restored_peer,
                &floor_record[..floor_len],
                revision,
                u64::MAX,
            ),
            Err(FragmentError::InvalidPersistentState)
        );
        assert_eq!(
            restored_policy.restore_receiver_floor(
                &restored_permit,
                &restored,
                &restored_peer,
                &floor_record[..floor_len],
                revision,
                100_000,
            ),
            Ok(revision)
        );
        assert_eq!(
            restored_policy
                .snapshot_for_tests()
                .max_receiver_high_counter,
            Some(3)
        );
        let mut restart_storage = [0u8; MAX_PACKET_SIZE];
        assert!(matches!(
            AuthenticatedFragmentReceiver::new(
                &restored_policy,
                &restored_permit,
                &restored,
                &restored_peer,
                &mut restart_storage,
                100_000,
            ),
            Err(FragmentError::SessionBusy)
        ));

        restored.unpin_peer(&remote.iid);
        let reinstalled_peer = authenticate_dio(&sender, &mut restored, &dio, &dodag, 4, 5);
        assert_ne!(reinstalled_peer.durable_key_generation(), durable);
        let mut reinstalled_policy = FragmentationPolicy::<1>::new().unwrap();
        let reinstalled_permit = reinstalled_policy
            .accept_peer(&restored, &reinstalled_peer, 5)
            .unwrap();
        assert_eq!(
            reinstalled_policy.restore_receiver_floor(
                &reinstalled_permit,
                &restored,
                &reinstalled_peer,
                &floor_record[..floor_len],
                revision,
                5,
            ),
            Err(FragmentError::InvalidPersistentState)
        );
    }
}
