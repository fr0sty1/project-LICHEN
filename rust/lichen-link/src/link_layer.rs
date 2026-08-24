//! LICHEN link layer: signed frame TX/RX with TOFU peer management.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::vec::Vec;

use sha2::{Digest, Sha256};

#[cfg(feature = "log")]
use log::{debug, warn};

use crate::evidence::{AuthenticatedLinkFrame, ReceiptClock, ReceiptClockError, ReceiptEvidence};
use crate::frame::{
    AddrMode, Encryption, FrameError, LichenFrame, MicLength, Signature, MAX_FRAME_BODY,
};
use crate::identity::{Identity, PeerIdentity};
use crate::keys::PublicKey;
use crate::replay::ReplayWindow;
use crate::schnorr::{self, SIGNATURE_LENGTH};
use crate::seqnum::LinkSeqNum;
use lichen_core::error::TooShort;

const TRUST_STATE_DOMAIN: &[u8] = b"LICHEN-LINK-TRUST-v1\0";
const TRUST_STATE_SIGNATURE_LEN: usize = 48;

/// Error returned by [`LinkLayer::receive_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkRxError {
    Frame(FrameError),
    /// Frame has no signature but all LICHEN frames must be signed.
    Unsigned,
    /// No known peer has a valid signature for this frame (TOFU: frame
    /// arrives from a pubkey not yet in the peer table).
    UnknownSender,
    /// Replay-window check failed (duplicate or too-old seqnum).
    Replay,
    /// Signed MIC is not the required 48-byte Schnorr signature.
    TooShort(TooShort),
    /// A previously-pinned IID appeared with a different public key.
    KeyChange,
    /// The caller-supplied reception timestamp moved backwards.
    ClockRegression,
    /// The caller mixed incompatible reception clock units in one link.
    ClockModeMismatch,
}

/// Failure to export or atomically restore authenticated peer trust state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPersistentStateError {
    Missing,
    Malformed,
    Integrity,
    Rollback,
    Conflict,
    BufferTooSmall,
}

impl std::fmt::Display for LinkPersistentStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "persistent peer state is missing",
            Self::Malformed => "persistent peer state is malformed",
            Self::Integrity => "persistent peer state failed integrity validation",
            Self::Rollback => "persistent peer state rollback detected",
            Self::Conflict => "persistent peer state conflicts with bounded live state",
            Self::BufferTooSmall => "persistent peer state output buffer is too small",
        })
    }
}

impl std::error::Error for LinkPersistentStateError {}

impl std::fmt::Display for LinkRxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame error: {}", e),
            Self::Unsigned => write!(f, "frame has no signature"),
            Self::UnknownSender => write!(f, "unknown sender"),
            Self::Replay => write!(f, "replay detected"),
            Self::TooShort(e) => write!(f, "payload {}", e),
            Self::KeyChange => write!(f, "key change detected"),
            Self::ClockRegression => write!(f, "reception clock moved backwards"),
            Self::ClockModeMismatch => write!(f, "reception clock mode changed"),
        }
    }
}

impl core::error::Error for LinkRxError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(e) => Some(e),
            Self::TooShort(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FrameError> for LinkRxError {
    fn from(e: FrameError) -> Self {
        LinkRxError::Frame(e)
    }
}

impl From<TooShort> for LinkRxError {
    fn from(e: TooShort) -> Self {
        LinkRxError::TooShort(e)
    }
}

impl From<ReceiptClockError> for LinkRxError {
    fn from(error: ReceiptClockError) -> Self {
        match error {
            ReceiptClockError::ClockRegression | ReceiptClockError::DomainExhausted => {
                Self::ClockRegression
            }
            ReceiptClockError::ClockModeMismatch => Self::ClockModeMismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAuthState {
    Unknown,
    Authenticating,
    Authenticated,
}

impl PeerAuthState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Unknown, Self::Unknown)
                | (Self::Unknown, Self::Authenticating)
                | (Self::Authenticating, Self::Authenticating)
                | (Self::Authenticating, Self::Authenticated)
                | (Self::Authenticated, Self::Authenticated)
                | (Self::Authenticated, Self::Authenticating)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPeerAuthTransition {
    pub from: PeerAuthState,
    pub to: PeerAuthState,
}

pub trait PeerAuthMarker {
    const STATE: PeerAuthState;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownPeer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatingPeer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeer;

impl PeerAuthMarker for UnknownPeer {
    const STATE: PeerAuthState = PeerAuthState::Unknown;
}

impl PeerAuthMarker for AuthenticatingPeer {
    const STATE: PeerAuthState = PeerAuthState::Authenticating;
}

impl PeerAuthMarker for AuthenticatedPeer {
    const STATE: PeerAuthState = PeerAuthState::Authenticated;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAuthentication<S: PeerAuthMarker> {
    pub iid: [u8; 8],
    pub pubkey: Option<PublicKey>,
    state: PhantomData<S>,
}

impl PeerAuthentication<UnknownPeer> {
    pub fn unknown(iid: [u8; 8]) -> Self {
        Self {
            iid,
            pubkey: None,
            state: PhantomData,
        }
    }

    pub fn begin(self, peer: PeerIdentity) -> PeerAuthentication<AuthenticatingPeer> {
        PeerAuthentication {
            iid: peer.iid,
            pubkey: Some(peer.pubkey),
            state: PhantomData,
        }
    }
}

impl PeerAuthentication<AuthenticatingPeer> {
    pub fn authenticate(self) -> PeerAuthentication<AuthenticatedPeer> {
        PeerAuthentication {
            iid: self.iid,
            pubkey: self.pubkey,
            state: PhantomData,
        }
    }
}

impl PeerAuthentication<AuthenticatedPeer> {
    pub fn unpin(self) -> PeerAuthentication<AuthenticatingPeer> {
        PeerAuthentication {
            iid: self.iid,
            pubkey: self.pubkey,
            state: PhantomData,
        }
    }
}

impl<S: PeerAuthMarker> PeerAuthentication<S> {
    pub fn state(&self) -> PeerAuthState {
        S::STATE
    }
}

/// A successfully received and authenticated link-layer frame.
///
/// Returned by [`LinkLayer::receive_frame`] after signature verification
/// and replay protection pass. The payload excludes the 48-byte Schnorr
/// MIC; it contains the SCHC-compressed IPv6 packet ready
/// for decompression.
///
/// Note: This is distinct from `lichen_node::ReceivedIpv6` which represents
/// a fully decompressed IPv6 packet with radio metadata attached.
///
/// Authenticated fields are deliberately private. External crates can inspect
/// the detached snapshot but cannot rewrite it before SCHC/RPL elevation:
///
/// ```compile_fail
/// fn forge(frame: &mut lichen_link::link_layer::AuthenticatedFrame) {
///     frame.payload.clear();
/// }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthenticatedFrame {
    payload: Vec<u8>,
    destination: Vec<u8>,
    destination_mode: AddrMode,
    sender: PeerIdentity,
    signer_eui64: [u8; 8],
    epoch: u8,
    seqnum: LinkSeqNum,
    receiving_link_identity: Arc<AtomicBool>,
    peer_key_generation: Arc<AtomicBool>,
    peer_key_generation_id: crate::PeerKeyGeneration,
    durable_peer_key_generation: crate::DurablePeerKeyGeneration,
    receipt: ReceiptEvidence,
    receiving_eui64: [u8; 8],
}

/// Opaque identity of the exact receiving link-layer instance.
///
/// Values are owner-issued and process-local. They may be retained by policy
/// objects to reject evidence presented through a different receiver, but
/// cannot be constructed or serialized by callers.
#[derive(Clone, Debug)]
pub struct ReceivingLinkIdentity(Arc<AtomicBool>);

impl ReceivingLinkIdentity {
    /// Return whether both tokens identify the exact same receiver instance.
    pub fn is_same_receiver(&self, other: &Self) -> bool {
        !self.0.load(Ordering::Acquire)
            && !other.0.load(Ordering::Acquire)
            && Arc::ptr_eq(&self.0, &other.0)
    }
}

impl AuthenticatedFrame {
    /// Authenticated inner payload, excluding link-layer MIC bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Authenticated link destination bytes covered by the signature.
    pub fn destination(&self) -> &[u8] {
        &self.destination
    }

    /// Authenticated destination addressing mode.
    pub const fn destination_mode(&self) -> AddrMode {
        self.destination_mode
    }

    /// Identity whose signature authenticated this frame.
    pub fn sender(&self) -> &PeerIdentity {
        &self.sender
    }

    /// Canonical signer EUI-64 carried on wire and covered by the signature.
    pub const fn signer_eui64(&self) -> [u8; 8] {
        self.signer_eui64
    }

    /// Authenticated replay epoch accepted by the receiving link.
    pub const fn epoch(&self) -> u8 {
        self.epoch
    }

    /// Authenticated replay sequence number accepted by the receiving link.
    pub const fn seqnum(&self) -> LinkSeqNum {
        self.seqnum
    }

    /// Immutable receipt time and exact receiver clock domain.
    pub const fn receipt(&self) -> ReceiptEvidence {
        self.receipt
    }

    /// Canonical EUI-64 of the exact link instance that received the frame.
    pub const fn receiving_eui64(&self) -> [u8; 8] {
        self.receiving_eui64
    }

    /// Whether neither the receiving link nor the authenticated peer-key
    /// generation has subsequently been retired.
    pub fn is_current(&self) -> bool {
        !self.receiving_link_identity.load(Ordering::Acquire)
            && !self.peer_key_generation.load(Ordering::Acquire)
    }

    /// Opaque identity of the exact installed peer-key generation.
    pub const fn peer_key_generation(&self) -> crate::PeerKeyGeneration {
        self.peer_key_generation_id
    }

    /// Stable opaque identity of this key installation in authenticated storage.
    pub const fn durable_peer_key_generation(&self) -> crate::DurablePeerKeyGeneration {
        self.durable_peer_key_generation
    }

    /// Borrow this frame as opaque owner-issued evidence for no-std-capable
    /// upper-layer admission APIs.
    pub fn link_evidence(&self) -> AuthenticatedLinkFrame<'_> {
        AuthenticatedLinkFrame::new(
            &self.payload,
            &self.destination,
            self.destination_mode,
            *self.sender.pubkey.as_bytes(),
            self.signer_eui64,
            self.epoch,
            self.seqnum,
            self.receipt,
            self.peer_key_generation_id,
            self.durable_peer_key_generation,
            &self.receiving_link_identity,
            &self.peer_key_generation,
        )
    }

    /// Whether this frame carries an explicit unicast destination for `link`.
    ///
    /// Fragmentation controls are never broadcast or destination-elided, so
    /// callers that require an exact local target use this stronger predicate
    /// instead of comparing wire EUI-64 bytes with the key-derived IID.
    pub fn is_unicast_for(&self, link: &LinkLayer) -> bool {
        self.destination_mode == AddrMode::Extended
            && self.destination.as_slice() == link.local_eui64()
    }
}

/// Per-peer replay state: tracks highest epoch and current seqnum window.
#[derive(Debug)]
struct PeerReplayState {
    last_epoch: u8,
    window: ReplayWindow,
    last_access: u64,
}

impl PeerReplayState {
    fn new(epoch: u8, last_access: u64) -> Self {
        Self {
            last_epoch: epoch,
            window: ReplayWindow::new(),
            last_access,
        }
    }
}

/// Per-peer replay-window tracker with epoch enforcement.
///
/// SECURITY: Enforces spec section 4.4 acceptance rules:
/// - epoch > LastEpoch: accept, update state
/// - epoch == LastEpoch, seqnum in/above window: accept if not seen
/// - epoch < LastEpoch: reject (replay)
#[derive(Debug)]
pub struct ReplayProtector {
    peers: HashMap<PublicKey, PeerReplayState>,
    /// Logical clock for LRU tracking. Saturates at u64::MAX instead of
    /// wrapping: a wrap would relabel the newest peers "oldest" and invert
    /// eviction order (see [`Self::evict_if_needed`]).
    access_counter: u64,
    /// Peer-table capacity. `NonZeroUsize` makes a zero-capacity table
    /// (which would evict every peer immediately) unrepresentable.
    max_peers: NonZeroUsize,
}

impl ReplayProtector {
    pub fn new() -> Self {
        ReplayProtector {
            peers: HashMap::new(),
            access_counter: 0,
            max_peers: NonZeroUsize::new(64).expect("64 is non-zero"),
        }
    }

    /// Check and advance the window. Returns `true` if the frame is fresh.
    ///
    /// Epochs are finite for a given public key: wrapping from 255 to 0 is a
    /// rollback and requires a new key (and therefore fresh replay state).
    pub fn check_and_update(&mut self, pubkey: &PublicKey, epoch: u8, seqnum: LinkSeqNum) -> bool {
        self.access_counter = self.access_counter.saturating_add(1);
        let access = self.access_counter;
        match self.peers.get_mut(pubkey) {
            None => {
                let mut state = PeerReplayState::new(epoch, access);
                let accepted = state.window.accept(seqnum);
                self.peers.insert(*pubkey, state);
                self.evict_if_needed();
                accepted
            }
            Some(state) => {
                state.last_access = access;
                // SECURITY: Epochs are finite for a given public key. Wrapping from
                // 255 to 0 is a rollback and must be rejected - require key rotation.
                if epoch > state.last_epoch {
                    // Strictly newer epoch: reset replay window
                    state.last_epoch = epoch;
                    state.window = ReplayWindow::new();
                    state.window.accept(seqnum)
                } else if epoch < state.last_epoch {
                    // Older epoch: replay attack
                    false
                } else {
                    // Same epoch: check replay window
                    state.window.accept(seqnum)
                }
            }
        }
    }

    /// Evict least-recently-accessed peers down to capacity.
    ///
    /// Capacity is at least 1 by construction (`NonZeroUsize`), so the loop
    /// always retains one peer and cannot thrash. Ordering uses a saturating
    /// logical clock: once `access_counter` reaches u64::MAX (~10^19 accesses)
    /// new accesses tie with the most-recent tier instead of wrapping to
    /// "oldest", degrading eviction to arbitrary-among-newest rather than
    /// inverting LRU order.
    fn evict_if_needed(&mut self) {
        while self.peers.len() > self.max_peers.get() {
            let oldest = self
                .peers
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.peers.remove(&k);
            } else {
                break;
            }
        }
    }

    pub fn reset_peer(&mut self, pubkey: &PublicKey) {
        self.peers.remove(pubkey);
    }
}

impl Default for ReplayProtector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct TrackedPeer {
    identity: PeerIdentity,
    last_access: u64,
    key_generation: Arc<AtomicBool>,
    key_generation_id: crate::PeerKeyGeneration,
    durable_key_generation: crate::DurablePeerKeyGeneration,
    durable_generation_serial: u64,
    required_schc_floor_commitment: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct PinnedKey {
    pubkey: PublicKey,
}

/// LICHEN link layer: builds signed frames for TX and verifies them on RX.
///
/// The peer table is keyed by the mandatory signer EUI-64 (8 bytes) in a
/// `HashMap` for exact lookup. A successful verify pins the sender. Unknown
/// senders are rejected (no TOFU auto-enrolment — callers handle that via the
/// Announce layer).
///
/// # Signature Verification Cost
///
/// Signed frames carry the signer EUI-64, so RX performs one indexed lookup
/// and one Schnorr verification. Signed frames without that hint are rejected.
///
/// # Key Pinning
///
/// Once an IID is seen with a valid signature, its pubkey is stored in
/// `pinned`. Subsequent frames from the same IID must match the pinned
/// pubkey; a mismatch returns `LinkRxError::KeyChange`.
pub struct LinkLayer {
    identity: Identity,
    peers: HashMap<[u8; 8], TrackedPeer>,
    replay: ReplayProtector,
    pinned: HashMap<[u8; 8], PinnedKey>,
    /// Logical clock for LRU tracking; saturates at u64::MAX instead of
    /// wrapping so eviction order can never invert.
    access_counter: u64,
    /// Peer-table capacity. `NonZeroUsize` makes a zero-capacity table
    /// unrepresentable by construction.
    max_peers: NonZeroUsize,
    receiving_link_identity: Arc<AtomicBool>,
    receipt_clock: ReceiptClock,
    next_durable_generation: u64,
}

impl std::fmt::Debug for LinkLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkLayer")
            .field("identity", &"[REDACTED]")
            .field("peers", &self.peers)
            .field("replay", &self.replay)
            .field("pinned", &self.pinned)
            .finish()
    }
}

impl LinkLayer {
    pub fn new(identity: Identity) -> Self {
        LinkLayer {
            identity,
            peers: HashMap::new(),
            replay: ReplayProtector::new(),
            pinned: HashMap::new(),
            access_counter: 0,
            max_peers: NonZeroUsize::new(64).expect("64 is non-zero"),
            receiving_link_identity: Arc::new(AtomicBool::new(false)),
            receipt_clock: ReceiptClock::default(),
            next_durable_generation: 1,
        }
    }

    /// Remove the key pin for a peer IID (use only for intentional key rotation).
    pub fn unpin_peer(&mut self, iid: &[u8; 8]) {
        self.pinned.remove(iid);
        let replacement = self.peers.get(iid).map(|peer| peer.identity.pubkey);
        let durable_generation = replacement.map(|key| {
            self.allocate_durable_generation(&key)
                .expect("durable peer key-generation identifiers exhausted")
        });
        if let Some(peer) = self.peers.get_mut(iid) {
            peer.key_generation.store(true, Ordering::Release);
            peer.key_generation = Arc::new(AtomicBool::new(false));
            peer.key_generation_id = crate::PeerKeyGeneration::allocate()
                .expect("peer key-generation identifiers exhausted");
            let (durable, serial) =
                durable_generation.expect("configured peer has replacement generation");
            peer.durable_key_generation = durable;
            peer.durable_generation_serial = serial;
            peer.required_schc_floor_commitment = None;
        }
    }

    /// Return the pinned pubkey for an IID, or None if not yet seen.
    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<&PublicKey> {
        self.pinned.get(iid).map(|p| &p.pubkey)
    }

    /// Return this link layer's local public key.
    pub fn local_public_key(&self) -> PublicKey {
        self.identity.pubkey
    }

    /// Local key-derived interface identifier used for addressed controls.
    pub fn local_iid(&self) -> [u8; 8] {
        self.identity.iid
    }

    /// Local EUI-64 used by the link frame's Extended destination mode.
    pub fn local_eui64(&self) -> [u8; 8] {
        let mut eui64 = self.identity.iid;
        eui64[0] ^= 0x02;
        eui64
    }

    /// Sign a digest with this link layer's private key (for DAO origin signatures).
    pub fn sign_digest(&self, digest: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        schnorr::sign(&self.identity.privkey, &self.identity.pubkey, digest)
    }

    pub fn peer_auth_state(&self, iid: &[u8; 8]) -> PeerAuthState {
        match (self.peers.get(iid), self.pinned.get(iid)) {
            (Some(peer), Some(pinned)) if pinned.pubkey == peer.identity.pubkey => {
                PeerAuthState::Authenticated
            }
            (Some(_), _) => PeerAuthState::Authenticating,
            (None, _) => PeerAuthState::Unknown,
        }
    }

    /// Add or refresh a peer, returning any different peer evicted/replaced.
    pub fn add_peer(&mut self, peer: PeerIdentity) -> Option<PeerIdentity> {
        // SECURITY: Never trust a caller-supplied IID.  PeerIdentity remains a
        // convenient public transport type, but the link-layer trust boundary
        // is the public key and its deterministic key-derived IID.
        let peer = PeerIdentity::from_pubkey(peer.pubkey);
        self.access_counter = self.access_counter.saturating_add(1);
        let access = self.access_counter;
        if let Some(existing) = self.peers.get_mut(&peer.iid) {
            if existing.identity.pubkey == peer.pubkey {
                // An idempotent configuration/announcement refresh must not
                // retire evidence or erase the replay high-water mark.
                existing.last_access = access;
                return None;
            }
        }
        let (durable_key_generation, durable_generation_serial) = self
            .allocate_durable_generation(&peer.pubkey)
            .expect("durable peer key-generation identifiers exhausted");
        let tracked = TrackedPeer {
            identity: peer,
            last_access: access,
            key_generation: Arc::new(AtomicBool::new(false)),
            key_generation_id: crate::PeerKeyGeneration::allocate()
                .expect("peer key-generation identifiers exhausted"),
            durable_key_generation,
            durable_generation_serial,
            required_schc_floor_commitment: None,
        };
        let mut retired = None;
        if let Some(replaced) = self.peers.insert(tracked.identity.iid, tracked) {
            replaced.key_generation.store(true, Ordering::Release);
            self.replay.reset_peer(&replaced.identity.pubkey);
            retired = Some(replaced.identity);
        }
        self.evict_if_needed().or(retired)
    }

    pub fn remove_peer(&mut self, iid: &[u8; 8]) {
        if let Some(tracked) = self.peers.remove(iid) {
            tracked.key_generation.store(true, Ordering::Release);
            self.replay.reset_peer(&tracked.identity.pubkey);
        }
        self.pinned.remove(iid);
    }

    /// Atomically remove a peer's configured key, pin, and replay window.
    pub fn forget_peer(&mut self, iid: &[u8; 8]) {
        let peer_key = self.peers.remove(iid).map(|peer| {
            peer.key_generation.store(true, Ordering::Release);
            peer.identity.pubkey
        });
        let pinned_key = self.pinned.remove(iid);
        if let Some(key) = peer_key {
            self.replay.reset_peer(&key);
        }
        if let Some(key) = pinned_key {
            if Some(key.pubkey) != peer_key {
                self.replay.reset_peer(&key.pubkey);
            }
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Return whether detached evidence is still live for this exact receiver
    /// and the current configured/pinned peer-key generation.
    pub fn accepts_authenticated_frame(&self, frame: &AuthenticatedFrame) -> bool {
        Arc::ptr_eq(
            &self.receiving_link_identity,
            &frame.receiving_link_identity,
        ) && frame.is_current()
            && self.peers.get(&frame.sender.iid).is_some_and(|peer| {
                peer.identity.pubkey == frame.sender.pubkey
                    && Arc::ptr_eq(&peer.key_generation, &frame.peer_key_generation)
                    && peer.durable_key_generation == frame.durable_peer_key_generation
            })
            && self
                .pinned
                .get(&frame.sender.iid)
                .is_some_and(|pin| pin.pubkey == frame.sender.pubkey)
    }

    /// Issue an opaque identity token for this exact receiving link instance.
    pub fn receiving_link_identity(&self) -> ReceivingLinkIdentity {
        ReceivingLinkIdentity(Arc::clone(&self.receiving_link_identity))
    }

    fn allocate_durable_generation(
        &mut self,
        peer: &PublicKey,
    ) -> Option<(crate::DurablePeerKeyGeneration, u64)> {
        let serial = self.next_durable_generation;
        self.next_durable_generation = serial.checked_add(1)?;
        durable_generation_for(&self.identity.pubkey, peer, serial)
            .map(|generation| (generation, serial))
    }

    /// Seal one peer's current trust generation and replay window.
    ///
    /// The caller atomically commits this blob with SCHC floor records using
    /// the same nonzero `revision`.
    pub fn persist_peer_trust_state(
        &self,
        iid: &[u8; 8],
        revision: u64,
        schc_floor_record: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<usize, LinkPersistentStateError> {
        if revision == 0 {
            return Err(LinkPersistentStateError::Malformed);
        }
        let peer = self
            .peers
            .get(iid)
            .ok_or(LinkPersistentStateError::Missing)?;
        if self
            .pinned
            .get(iid)
            .is_none_or(|pin| pin.pubkey != peer.identity.pubkey)
        {
            return Err(LinkPersistentStateError::Missing);
        }
        let replay = self
            .replay
            .peers
            .get(&peer.identity.pubkey)
            .ok_or(LinkPersistentStateError::Missing)?;
        let (last_seq, window) = replay
            .window
            .persistent_parts()
            .ok_or(LinkPersistentStateError::Missing)?;
        let mut body = Vec::with_capacity(192);
        body.extend_from_slice(TRUST_STATE_DOMAIN);
        body.push(1);
        body.extend_from_slice(&revision.to_be_bytes());
        body.extend_from_slice(self.identity.pubkey.as_bytes());
        body.extend_from_slice(peer.identity.pubkey.as_bytes());
        body.extend_from_slice(&peer.durable_key_generation.as_bytes());
        body.extend_from_slice(&peer.durable_generation_serial.to_be_bytes());
        body.extend_from_slice(&self.next_durable_generation.to_be_bytes());
        if let Some(record) = schc_floor_record {
            body.push(1);
            body.extend_from_slice(&Sha256::digest(record));
        } else {
            body.push(0);
            body.extend_from_slice(&[0; 32]);
        }
        body.push(replay.last_epoch);
        body.extend_from_slice(&last_seq.to_be_bytes());
        body.extend_from_slice(&window.to_be_bytes());
        let needed = body.len() + TRUST_STATE_SIGNATURE_LEN;
        if out.len() < needed {
            return Err(LinkPersistentStateError::BufferTooSmall);
        }
        let signature = self.sign_digest(&body);
        out[..body.len()].copy_from_slice(&body);
        out[body.len()..needed].copy_from_slice(&signature);
        Ok(needed)
    }

    /// Restore a signed trust/replay transaction into a fresh link owner.
    ///
    /// A new process-local generation token is allocated while the stable
    /// durable generation is retained. Validation completes before mutation.
    pub fn restore_peer_trust_state(
        &mut self,
        record: &[u8],
        minimum_revision: u64,
    ) -> Result<u64, LinkPersistentStateError> {
        const TAIL_LEN: usize = 1 + 8 + 32 + 32 + 16 + 8 + 8 + 1 + 32 + 1 + 2 + 4;
        let body_len = TRUST_STATE_DOMAIN.len() + TAIL_LEN;
        if record.len() != body_len + TRUST_STATE_SIGNATURE_LEN {
            return Err(LinkPersistentStateError::Malformed);
        }
        let (body, signature) = record.split_at(body_len);
        if !schnorr::verify_profile_message(&self.identity.pubkey, body, signature) {
            return Err(LinkPersistentStateError::Integrity);
        }
        let mut cursor = TRUST_STATE_DOMAIN.len();
        if body[cursor] != 1 {
            return Err(LinkPersistentStateError::Malformed);
        }
        cursor += 1;
        let revision = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        if revision == 0 || revision < minimum_revision {
            return Err(LinkPersistentStateError::Rollback);
        }
        if body[cursor..cursor + 32] != *self.identity.pubkey.as_bytes() {
            return Err(LinkPersistentStateError::Integrity);
        }
        cursor += 32;
        let peer_key_bytes: [u8; 32] = body[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let peer_key = PublicKey::new(peer_key_bytes);
        let durable_bytes: [u8; 16] = body[cursor..cursor + 16].try_into().unwrap();
        cursor += 16;
        let durable = crate::DurablePeerKeyGeneration::from_owner_bytes(durable_bytes)
            .ok_or(LinkPersistentStateError::Malformed)?;
        let serial = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let next_serial = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        if serial == 0
            || next_serial <= serial
            || durable_generation_for(&self.identity.pubkey, &peer_key, serial) != Some(durable)
        {
            return Err(LinkPersistentStateError::Integrity);
        }
        let required_schc_floor_commitment = match body[cursor] {
            0 if body[cursor + 1..cursor + 33] == [0; 32] => None,
            1 => Some(body[cursor + 1..cursor + 33].try_into().unwrap()),
            _ => return Err(LinkPersistentStateError::Malformed),
        };
        cursor += 33;
        let last_epoch = body[cursor];
        cursor += 1;
        let last_seq = u16::from_be_bytes(body[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let window = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap());
        let replay_window = ReplayWindow::from_persistent_parts(last_seq, window)
            .ok_or(LinkPersistentStateError::Malformed)?;
        let peer = PeerIdentity::from_pubkey(peer_key);
        if self.peers.len() >= self.max_peers.get()
            || self.replay.peers.len() >= self.replay.max_peers.get()
            || self.peers.contains_key(&peer.iid)
            || self.pinned.contains_key(&peer.iid)
        {
            return Err(LinkPersistentStateError::Conflict);
        }
        let runtime_generation =
            crate::PeerKeyGeneration::allocate().ok_or(LinkPersistentStateError::Conflict)?;

        self.access_counter = self.access_counter.saturating_add(1);
        self.replay.access_counter = self.replay.access_counter.saturating_add(1);
        self.replay.peers.insert(
            peer.pubkey,
            PeerReplayState {
                last_epoch,
                window: replay_window,
                last_access: self.replay.access_counter,
            },
        );
        self.pinned.insert(
            peer.iid,
            PinnedKey {
                pubkey: peer.pubkey,
            },
        );
        self.peers.insert(
            peer.iid,
            TrackedPeer {
                identity: peer,
                last_access: self.access_counter,
                key_generation: Arc::new(AtomicBool::new(false)),
                key_generation_id: runtime_generation,
                durable_key_generation: durable,
                durable_generation_serial: serial,
                required_schc_floor_commitment,
            },
        );
        self.next_durable_generation = self.next_durable_generation.max(next_serial);
        Ok(revision)
    }

    /// Whether restored trust state requires this exact SCHC floor record.
    pub fn requires_schc_floor_record(
        &self,
        signer: &[u8; 32],
        durable: crate::DurablePeerKeyGeneration,
    ) -> bool {
        let iid = crate::iid_from_pubkey(&PublicKey::new(*signer));
        self.peers.get(&iid).is_some_and(|peer| {
            peer.identity.pubkey.as_bytes() == signer
                && peer.durable_key_generation == durable
                && peer.required_schc_floor_commitment.is_some()
        })
    }

    /// Check an expected floor commitment without consuming it.
    pub fn matches_required_schc_floor_record(
        &self,
        signer: &[u8; 32],
        durable: crate::DurablePeerKeyGeneration,
        record: &[u8],
    ) -> bool {
        let iid = crate::iid_from_pubkey(&PublicKey::new(*signer));
        let digest: [u8; 32] = Sha256::digest(record).into();
        self.peers.get(&iid).is_some_and(|peer| {
            peer.identity.pubkey.as_bytes() == signer
                && peer.durable_key_generation == durable
                && peer.required_schc_floor_commitment == Some(digest)
        })
    }

    /// Confirm the exact floor record committed by restored trust state.
    ///
    /// The commitment remains installed so recreating a volatile SCHC policy
    /// in the same process must restore the floor again.
    pub fn consume_schc_floor_record(
        &self,
        signer: &[u8; 32],
        durable: crate::DurablePeerKeyGeneration,
        record: &[u8],
    ) -> bool {
        let iid = crate::iid_from_pubkey(&PublicKey::new(*signer));
        let Some(peer) = self.peers.get(&iid) else {
            return false;
        };
        if peer.identity.pubkey.as_bytes() != signer || peer.durable_key_generation != durable {
            return false;
        }
        let digest: [u8; 32] = Sha256::digest(record).into();
        peer.required_schc_floor_commitment == Some(digest)
    }

    /// Evict least-recently-accessed peers down to capacity.
    ///
    /// Capacity is at least 1 by construction (`NonZeroUsize`), so the loop
    /// always retains one peer and cannot thrash. Ordering uses a saturating
    /// logical clock: once `access_counter` reaches u64::MAX (~10^19 accesses)
    /// new accesses tie with the most-recent tier instead of wrapping to
    /// "oldest", degrading eviction to arbitrary-among-newest rather than
    /// inverting LRU order.
    fn evict_if_needed(&mut self) -> Option<PeerIdentity> {
        let mut evicted = None;
        while self.peers.len() > self.max_peers.get() {
            let oldest_iid = self
                .peers
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                if let Some(tracked) = self.peers.remove(&iid) {
                    tracked.key_generation.store(true, Ordering::Release);
                    self.replay.reset_peer(&tracked.identity.pubkey);
                    self.pinned.remove(&iid);
                    evicted = Some(tracked.identity);
                }
            } else {
                break;
            }
        }
        evicted
    }

    /// Serialise a signed frame into `out`. Returns bytes written.
    ///
    /// The 48-byte signature occupies the frame MIC field.
    ///
    /// Returns `FrameError::FrameTooLarge` if body > 254 bytes.
    /// Returns `FrameError::BufferTooSmall` if `out` is too small.
    /// Callers must provide exactly the capacity returned by
    /// [`LinkLayer::required_frame_buffer_len`] (destination length + payload
    /// length + 61 bytes for the length field, fixed header, signer EUI-64,
    /// and Schnorr-48 signature).
    pub fn build_frame(
        &self,
        epoch: u8,
        seqnum: LinkSeqNum,
        dst_addr: &[u8],
        inner_payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, FrameError> {
        let addr_mode =
            AddrMode::from_addr_len(dst_addr.len()).ok_or(FrameError::AddrLenMismatch)?;
        self.build_frame_with_addr_mode(epoch, seqnum, dst_addr, inner_payload, addr_mode, out)
    }

    /// Return the exact output capacity required by [`LinkLayer::build_frame`].
    ///
    /// The destination length must select a supported address mode (0, 2, or
    /// 8 bytes), and the resulting frame body must fit the one-byte Length
    /// field. Arithmetic is checked before applying the 254-byte body limit.
    pub fn required_frame_buffer_len(
        dst_addr_len: usize,
        inner_payload_len: usize,
    ) -> Result<usize, FrameError> {
        AddrMode::from_addr_len(dst_addr_len).ok_or(FrameError::AddrLenMismatch)?;
        let body_len = 4usize
            .checked_add(dst_addr_len)
            .and_then(|length| length.checked_add(8))
            .and_then(|length| length.checked_add(inner_payload_len))
            .and_then(|length| length.checked_add(SIGNATURE_LENGTH))
            .ok_or(FrameError::FrameTooLarge)?;
        if body_len > MAX_FRAME_BODY {
            return Err(FrameError::FrameTooLarge);
        }
        body_len.checked_add(1).ok_or(FrameError::FrameTooLarge)
    }

    /// Serialise a signed frame with an explicit destination addressing mode.
    ///
    /// Unlike [`LinkLayer::build_frame`], this method can emit
    /// [`AddrMode::Elided`] for an empty destination. Elided addressing means
    /// the destination is derived from the upper-layer IPv6 packet; an empty
    /// destination passed to `build_frame` remains broadcast (`AddrMode::None`)
    /// for compatibility with existing callers.
    ///
    /// Returns `FrameError::FrameTooLarge` if body > 254 bytes,
    /// `FrameError::BufferTooSmall` if `out` too small, or
    /// [`FrameError::AddrLenMismatch`] on bad `dst_addr`.
    pub fn build_frame_with_addr_mode(
        &self,
        epoch: u8,
        seqnum: LinkSeqNum,
        dst_addr: &[u8],
        inner_payload: &[u8],
        addr_mode: AddrMode,
        out: &mut [u8],
    ) -> Result<usize, FrameError> {
        if addr_mode.addr_len() != dst_addr.len() {
            return Err(FrameError::AddrLenMismatch);
        }
        let required_len = Self::required_frame_buffer_len(dst_addr.len(), inner_payload.len())?;
        let llsec = (addr_mode as u8) | (1 << 5) | schnorr::LLSEC_SI_BIT;
        let signer_eui64 = self.local_eui64();
        let frame_length = required_len - 1;
        let sig = schnorr::sign_frame(
            frame_length as u8,
            llsec,
            epoch,
            seqnum,
            dst_addr,
            &signer_eui64,
            inner_payload,
            &self.identity.privkey,
            &self.identity.pubkey,
        );
        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr,
            signer_eui64: &signer_eui64,
            payload: inner_payload,
            mic: &sig,
            addr_mode,
            mic_length: MicLength::Bits32,
            signature: Signature::Present,
            encryption: Encryption::Plaintext,
        };
        frame.write_to(out)
    }

    /// Parse, authenticate, and replay-check an incoming frame.
    pub fn receive_frame(&mut self, wire: &[u8]) -> Result<AuthenticatedFrame, LinkRxError> {
        let receipt = self.receipt_clock.next_logical()?;
        self.receive_frame_with_receipt(wire, receipt)
    }

    /// Parse and authenticate a frame using a timestamp sampled immediately
    /// after radio receipt in this link instance's monotonic clock domain.
    pub fn receive_frame_at(
        &mut self,
        wire: &[u8],
        monotonic_millis: u64,
    ) -> Result<AuthenticatedFrame, LinkRxError> {
        let receipt = self.receipt_clock.observe_millis(monotonic_millis)?;
        self.receive_frame_with_receipt(wire, receipt)
    }

    fn receive_frame_with_receipt(
        &mut self,
        wire: &[u8],
        receipt: ReceiptEvidence,
    ) -> Result<AuthenticatedFrame, LinkRxError> {
        let frame = LichenFrame::from_bytes(wire)?;

        if !frame.signature.is_present() {
            #[cfg(feature = "log")]
            warn!("link_layer: received unsigned frame");
            return Err(LinkRxError::Unsigned);
        }
        if frame.mic.len() != SIGNATURE_LENGTH {
            return Err(TooShort::new(SIGNATURE_LENGTH, frame.mic.len()).into());
        }

        let inner_payload = frame.payload;
        // Recomputed body length must fit the u8 signed into the frame:
        // reject explicitly rather than letting the cast truncate (spec 4.1
        // LENGTH <= MAX_FRAME_BODY; from_bytes() enforces this too, but do
        // not depend on parser internals for signature-input integrity).
        let frame_length = rx_frame_length(
            frame.dst_addr.len(),
            frame.signer_eui64.len(),
            inner_payload.len(),
        )?;
        let signer_eui64: [u8; 8] = frame
            .signer_eui64
            .try_into()
            .map_err(|_| FrameError::SignatureSignerMismatch)?;
        let mut signer_iid = signer_eui64;
        signer_iid[0] ^= 0x02;
        let Some(tracked_sender) = self.peers.get(&signer_iid) else {
            #[cfg(feature = "log")]
            debug!("link_layer: frame from unknown sender");
            return Err(LinkRxError::UnknownSender);
        };
        let sender = tracked_sender.identity.clone();
        let canonical_eui64 = {
            let mut value = sender.iid;
            value[0] ^= 0x02;
            value
        };
        if signer_eui64 != canonical_eui64
            || !schnorr::verify_frame(
                frame_length,
                frame.llsec_byte(),
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                frame.mic,
                &sender.pubkey,
            )
        {
            return Err(LinkRxError::UnknownSender);
        }

        let old_state = self.peer_auth_state(&sender.iid);
        match self.pinned.get(&sender.iid) {
            Some(pinned) if pinned.pubkey != sender.pubkey => {
                #[cfg(feature = "log")]
                warn!(
                    "link_layer: key change detected for IID {:02x?}",
                    &sender.iid[6..]
                );
                return Err(LinkRxError::KeyChange);
            }
            _ => {}
        }

        if !self
            .replay
            .check_and_update(&sender.pubkey, frame.epoch, frame.seqnum)
        {
            #[cfg(feature = "log")]
            debug!(
                "link_layer: replay detected (epoch={}, seq={})",
                frame.epoch,
                u16::from(frame.seqnum)
            );
            return Err(LinkRxError::Replay);
        }

        self.access_counter = self.access_counter.saturating_add(1);
        let access = self.access_counter;
        if let Some(tracked) = self.peers.get_mut(&sender.iid) {
            tracked.last_access = access;
        }
        self.pinned.insert(
            sender.iid,
            PinnedKey {
                pubkey: sender.pubkey,
            },
        );
        let new_state = self.peer_auth_state(&sender.iid);
        if !old_state.can_transition_to(new_state) {
            #[cfg(feature = "log")]
            warn!(
                "link_layer: illegal peer auth state transition {:?}->{:?}",
                old_state, new_state
            );
            return Err(LinkRxError::KeyChange);
        }

        let peer_key_generation = Arc::clone(
            &self
                .peers
                .get(&sender.iid)
                .expect("verified sender remains configured")
                .key_generation,
        );
        let peer_key_generation_id = self
            .peers
            .get(&sender.iid)
            .expect("verified sender remains configured")
            .key_generation_id;
        let durable_peer_key_generation = self
            .peers
            .get(&sender.iid)
            .expect("verified sender remains configured")
            .durable_key_generation;
        Ok(AuthenticatedFrame {
            payload: inner_payload.to_vec(),
            destination: frame.dst_addr.to_vec(),
            destination_mode: frame.addr_mode,
            sender,
            signer_eui64,
            epoch: frame.epoch,
            seqnum: frame.seqnum,
            receiving_link_identity: Arc::clone(&self.receiving_link_identity),
            peer_key_generation,
            peer_key_generation_id,
            durable_peer_key_generation,
            receipt,
            receiving_eui64: self.local_eui64(),
        })
    }
}

impl Drop for LinkLayer {
    fn drop(&mut self) {
        // Retained frames/contexts must stop being capabilities as soon as the
        // exact receiver that authenticated them is destroyed.
        self.receiving_link_identity.store(true, Ordering::Release);
        for peer in self.peers.values() {
            peer.key_generation.store(true, Ordering::Release);
        }
    }
}

fn durable_generation_for(
    local: &PublicKey,
    peer: &PublicKey,
    serial: u64,
) -> Option<crate::DurablePeerKeyGeneration> {
    let mut digest = Sha256::new();
    digest.update(b"LICHEN-PEER-GENERATION-v1\0");
    digest.update(local.as_bytes());
    digest.update(peer.as_bytes());
    digest.update(serial.to_be_bytes());
    let hash = digest.finalize();
    crate::DurablePeerKeyGeneration::from_owner_bytes(hash[..16].try_into().ok()?)
}

/// Recompute the frame body length on the RX path, rejecting any value that
/// would not fit in the u8 consumed by [`schnorr::verify_frame`].
///
/// Arithmetic is checked so adversarially large component lengths cannot
/// overflow before the range check.
fn rx_frame_length(
    dst_addr_len: usize,
    signer_eui64_len: usize,
    payload_len: usize,
) -> Result<u8, FrameError> {
    let total = 4usize
        .checked_add(dst_addr_len)
        .and_then(|n| n.checked_add(signer_eui64_len))
        .and_then(|n| n.checked_add(payload_len))
        .and_then(|n| n.checked_add(SIGNATURE_LENGTH));
    match total {
        Some(n) if n <= MAX_FRAME_BODY => Ok(n as u8),
        _ => Err(FrameError::FrameTooLarge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keys::Seed;
    use std::vec;

    fn make_ll(seed: u8) -> LinkLayer {
        LinkLayer::new(Identity::from_seed(Seed::new([seed; 32])))
    }

    fn seq(n: u16) -> LinkSeqNum {
        LinkSeqNum::new(n)
    }

    #[test]
    fn tx_rx_basic() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));

        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = LinkLayer::new(Identity::from_seed(Seed::new([0x02u8; 32])));
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire)
            .unwrap();

        let rx = ll_bob.receive_frame(&wire[..n]).unwrap();
        assert_eq!(rx.payload, b"hello");
    }

    #[test]
    fn build_frame_buffer_contract_is_exact_and_checked() {
        let layer = make_ll(0x41);
        let payload = b"capacity-contract";
        for destination in [&[][..], &[0x12, 0x34][..], &[0x55; 8][..]] {
            let required =
                LinkLayer::required_frame_buffer_len(destination.len(), payload.len()).unwrap();
            assert_eq!(required, destination.len() + payload.len() + 61);

            let mut exact = vec![0u8; required];
            assert_eq!(
                layer
                    .build_frame(1, seq(1), destination, payload, &mut exact)
                    .unwrap(),
                required
            );
            let mut short = vec![0u8; required - 1];
            assert!(matches!(
                layer.build_frame(1, seq(1), destination, payload, &mut short),
                Err(FrameError::BufferTooSmall(_))
            ));
        }

        assert_eq!(
            LinkLayer::required_frame_buffer_len(1, 0),
            Err(FrameError::AddrLenMismatch)
        );
        assert_eq!(
            LinkLayer::required_frame_buffer_len(0, usize::MAX),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn authenticated_frame_is_a_detached_immutable_evidence_snapshot() {
        let alice = Identity::from_seed(Seed::new([0x31; 32]));
        let expected_sender = PeerIdentity::from_pubkey(alice.pubkey);
        let mut bob = make_ll(0x32);
        bob.add_peer(expected_sender.clone());
        let alice_layer = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let length = alice_layer
            .build_frame(7, seq(0x1234), &[], b"signed-dio-and-options", &mut wire)
            .unwrap();

        let evidence = bob.receive_frame(&wire[..length]).unwrap();
        wire.fill(0xa5);
        bob.unpin_peer(&expected_sender.iid);

        assert_eq!(evidence.payload(), b"signed-dio-and-options");
        assert_eq!(evidence.sender(), &expected_sender);
        assert_eq!(evidence.epoch(), 7);
        assert_eq!(evidence.seqnum(), seq(0x1234));
        assert_eq!(evidence.payload(), evidence.payload());
        assert_eq!(evidence.sender(), evidence.sender());
    }

    #[test]
    fn explicit_elided_destination_roundtrips_and_authenticates() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let mut bob = make_ll(0x02);
        bob.add_peer(PeerIdentity::from_pubkey(alice.pubkey));

        let alice_layer = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = alice_layer
            .build_frame_with_addr_mode(1, seq(1), &[], b"hello", AddrMode::Elided, &mut wire)
            .unwrap();

        let frame = LichenFrame::from_bytes(&wire[..n]).unwrap();
        assert_eq!(frame.addr_mode, AddrMode::Elided);
        assert_eq!(frame.dst_addr, &[] as &[u8]);
        assert_eq!(bob.receive_frame(&wire[..n]).unwrap().payload, b"hello");
    }

    #[test]
    fn explicit_address_mode_rejects_wrong_destination_length() {
        let layer = make_ll(0x01);
        let mut wire = [0u8; 256];

        assert_eq!(
            layer.build_frame_with_addr_mode(
                1,
                seq(1),
                &[0xaa],
                b"hello",
                AddrMode::Elided,
                &mut wire,
            ),
            Err(FrameError::AddrLenMismatch)
        );
    }

    #[test]
    fn receive_accepts_short_payload_with_48_byte_mic() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let mut bob = make_ll(0x02);
        bob.add_peer(PeerIdentity::from_pubkey(alice.pubkey));
        let alice_layer = LinkLayer::new(alice);
        let mut wire = [0u8; 128];
        let n = alice_layer
            .build_frame(1, seq(1), &[], &[0xaa], &mut wire)
            .unwrap();

        let received = bob.receive_frame(&wire[..n]).unwrap();
        assert_eq!(received.payload, &[0xaa]);
    }

    #[test]
    fn peer_auth_typestate_transitions_unknown_to_authenticated() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let peer = PeerIdentity::from_pubkey(alice.pubkey);
        let auth = PeerAuthentication::<UnknownPeer>::unknown(peer.iid);
        assert_eq!(auth.state(), PeerAuthState::Unknown);

        let auth = auth.begin(peer);
        assert_eq!(auth.state(), PeerAuthState::Authenticating);
        assert_eq!(auth.pubkey, Some(alice.pubkey));

        let auth = auth.authenticate();
        assert_eq!(auth.state(), PeerAuthState::Authenticated);

        let auth = auth.unpin();
        assert_eq!(auth.state(), PeerAuthState::Authenticating);
    }

    #[test]
    fn link_layer_peer_auth_state_tracks_pin_lifecycle() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let mut ll_bob = make_ll(0x02);
        assert_eq!(ll_bob.peer_auth_state(&alice_iid), PeerAuthState::Unknown);

        ll_bob.add_peer(alice_peer);
        assert_eq!(
            ll_bob.peer_auth_state(&alice_iid),
            PeerAuthState::Authenticating
        );

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire)
            .unwrap();
        ll_bob.receive_frame(&wire[..n]).unwrap();
        assert_eq!(
            ll_bob.peer_auth_state(&alice_iid),
            PeerAuthState::Authenticated
        );

        ll_bob.unpin_peer(&alice_iid);
        assert_eq!(
            ll_bob.peer_auth_state(&alice_iid),
            PeerAuthState::Authenticating
        );
    }

    #[test]
    fn replay_rejected() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let bob_seed = Seed::new([0x02u8; 32]);

        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = LinkLayer::new(Identity::from_seed(bob_seed));
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(42), &[], b"data", &mut wire)
            .unwrap();

        ll_bob.receive_frame(&wire[..n]).unwrap();
        let err = ll_bob.receive_frame(&wire[..n]).unwrap_err();
        assert_eq!(err, LinkRxError::Replay);
    }

    #[test]
    fn idempotent_same_key_pin_preserves_replay_window() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut bob = make_ll(0x02);
        bob.add_peer(alice_peer.clone());
        let sender = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let len = sender
            .build_frame(1, seq(42), &[], b"data", &mut wire)
            .unwrap();
        bob.receive_frame(&wire[..len]).unwrap();
        assert!(bob.add_peer(alice_peer).is_none());
        assert!(matches!(
            bob.receive_frame(&wire[..len]),
            Err(LinkRxError::Replay)
        ));
    }

    #[test]
    fn dropping_receiver_revokes_detached_authenticated_frames() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let sender = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let len = sender
            .build_frame(1, seq(1), &[], b"data", &mut wire)
            .unwrap();
        let frame = {
            let mut receiver = make_ll(0x02);
            receiver.add_peer(alice_peer);
            let frame = receiver.receive_frame(&wire[..len]).unwrap();
            assert!(frame.is_current());
            frame
        };
        assert!(!frame.is_current());
        assert!(!frame.link_evidence().is_current());
    }

    #[test]
    fn old_epoch_rejected() {
        // SECURITY: Per spec section 4.4, epoch < LastEpoch must be rejected.
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);

        // Accept frame with epoch=10
        let mut wire1 = [0u8; 256];
        let n1 = ll_alice
            .build_frame(10, seq(1), &[], b"epoch10", &mut wire1)
            .unwrap();
        ll_bob.receive_frame(&wire1[..n1]).unwrap();

        // Reject frame with epoch=5 (< 10)
        let mut wire2 = [0u8; 256];
        let n2 = ll_alice
            .build_frame(5, seq(1), &[], b"epoch5", &mut wire2)
            .unwrap();
        assert_eq!(
            ll_bob.receive_frame(&wire2[..n2]).unwrap_err(),
            LinkRxError::Replay
        );

        // Accept frame with epoch=11 (> 10)
        let mut wire3 = [0u8; 256];
        let n3 = ll_alice
            .build_frame(11, seq(1), &[], b"epoch11", &mut wire3)
            .unwrap();
        ll_bob.receive_frame(&wire3[..n3]).unwrap();
    }

    #[test]
    fn epoch_wraparound_rejected_for_same_pubkey() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);

        let mut wire1 = [0u8; 256];
        let n1 = ll_alice
            .build_frame(254, seq(1), &[], b"e254", &mut wire1)
            .unwrap();
        ll_bob.receive_frame(&wire1[..n1]).unwrap();

        let mut wire2 = [0u8; 256];
        let n2 = ll_alice
            .build_frame(255, seq(1), &[], b"e255", &mut wire2)
            .unwrap();
        ll_bob.receive_frame(&wire2[..n2]).unwrap();

        let mut wire3 = [0u8; 256];
        let n3 = ll_alice
            .build_frame(0, seq(1), &[], b"e0wrap", &mut wire3)
            .unwrap();
        assert_eq!(
            ll_bob.receive_frame(&wire3[..n3]).unwrap_err(),
            LinkRxError::Replay
        );
    }

    #[test]
    fn new_pubkey_has_fresh_replay_state() {
        let old_key = Identity::from_seed(Seed::new([0x01; 32])).pubkey;
        let new_key = Identity::from_seed(Seed::new([0x02; 32])).pubkey;
        let mut replay = ReplayProtector::new();

        assert!(replay.check_and_update(&old_key, 255, seq(65535)));
        assert!(!replay.check_and_update(&old_key, 0, seq(0)));
        assert!(replay.check_and_update(&new_key, 0, seq(0)));
    }

    #[test]
    fn replay_rejected_after_unpin_does_not_reauthenticate_peer() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(42), &[], b"data", &mut wire)
            .unwrap();

        ll_bob.receive_frame(&wire[..n]).unwrap();
        ll_bob.unpin_peer(&alice_iid);
        assert_eq!(
            ll_bob.peer_auth_state(&alice_iid),
            PeerAuthState::Authenticating
        );

        assert_eq!(
            ll_bob.receive_frame(&wire[..n]).unwrap_err(),
            LinkRxError::Replay
        );
        assert_eq!(
            ll_bob.peer_auth_state(&alice_iid),
            PeerAuthState::Authenticating
        );
    }

    #[test]
    fn unknown_sender_rejected() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let mut ll_bob = make_ll(0x02);
        // Alice is NOT added as a peer

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(1), &[], b"hi", &mut wire)
            .unwrap();

        assert_eq!(
            ll_bob.receive_frame(&wire[..n]).unwrap_err(),
            LinkRxError::UnknownSender
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire)
            .unwrap();

        // Flip a bit in the inner payload region
        wire[6] ^= 0xFF;
        assert_eq!(
            ll_bob.receive_frame(&wire[..n]).unwrap_err(),
            LinkRxError::UnknownSender
        );
    }

    #[test]
    fn peer_count_tracked() {
        let mut ll = make_ll(0x01);
        assert_eq!(ll.peer_count(), 0);
        let peer_a = PeerIdentity::from_pubkey(Identity::from_seed(Seed::new([0x02u8; 32])).pubkey);
        let iid_a = peer_a.iid;
        ll.add_peer(peer_a);
        assert_eq!(ll.peer_count(), 1);
        ll.remove_peer(&iid_a);
        assert_eq!(ll.peer_count(), 0);
    }

    #[test]
    fn key_change_detected() {
        // Pin alice's IID to alice's pubkey on first successful RX.
        // Then swap alice's peer entry for an impersonator with the same IID
        // (achieved by manually overwriting the pin). Second RX must fail with KeyChange.
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let alice_pubkey = alice_peer.pubkey;
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire1 = [0u8; 256];
        let n1 = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire1)
            .unwrap();

        // First RX succeeds and pins alice_iid → alice's pubkey.
        ll_bob.receive_frame(&wire1[..n1]).unwrap();
        assert_eq!(ll_bob.pinned_pubkey_for(&alice_iid), Some(&alice_pubkey));

        // Simulate key change: overwrite pin with a different pubkey.
        let impostor_pk = Identity::from_seed(Seed::new([0x99u8; 32])).pubkey;
        ll_bob.pinned.insert(
            alice_iid,
            PinnedKey {
                pubkey: impostor_pk,
            },
        );

        // Second RX with same alice frame must now fail with KeyChange.
        let ll_alice2 = LinkLayer::new(Identity::from_seed(Seed::new([0x01u8; 32])));
        let mut wire2 = [0u8; 256];
        let n2 = ll_alice2
            .build_frame(1, seq(2), &[], b"hi", &mut wire2)
            .unwrap();
        assert_eq!(
            ll_bob.receive_frame(&wire2[..n2]).unwrap_err(),
            LinkRxError::KeyChange
        );
    }

    #[test]
    fn unpin_allows_key_rotation() {
        let alice = Identity::from_seed(Seed::new([0x01u8; 32]));
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(Identity::from_seed(Seed::new([0x01u8; 32])));
        let mut wire = [0u8; 256];
        let n = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire)
            .unwrap();
        ll_bob.receive_frame(&wire[..n]).unwrap();

        // Admin unpins: allows accepting a new key for this IID.
        ll_bob.unpin_peer(&alice_iid);
        assert_eq!(ll_bob.pinned_pubkey_for(&alice_iid), None);

        // New key accepted and re-pinned.
        let new_alice = Identity::from_seed(Seed::new([0xAAu8; 32]));
        let new_alice_peer = PeerIdentity::from_pubkey(new_alice.pubkey);
        let new_alice_iid = new_alice_peer.iid;
        let new_alice_pubkey = new_alice_peer.pubkey;
        ll_bob.remove_peer(&alice_iid);
        ll_bob.add_peer(new_alice_peer);

        let ll_new = LinkLayer::new(new_alice);
        let mut wire2 = [0u8; 256];
        let n2 = ll_new
            .build_frame(1, seq(1), &[], b"rotated", &mut wire2)
            .unwrap();
        ll_bob.receive_frame(&wire2[..n2]).unwrap();
        assert_eq!(
            ll_bob.pinned_pubkey_for(&new_alice_iid),
            Some(&new_alice_pubkey)
        );
    }

    #[test]
    fn forget_peer_clears_peer_pin_and_replay_state() {
        let alice = Identity::from_seed(Seed::new([0x42; 32]));
        let peer = PeerIdentity::from_pubkey(alice.pubkey);
        let iid = peer.iid;
        let mut bob = make_ll(0x24);
        bob.add_peer(peer.clone());
        let mut wire = [0u8; 256];
        let len = LinkLayer::new(alice)
            .build_frame(1, seq(1), &[], b"hello", &mut wire)
            .unwrap();
        bob.receive_frame(&wire[..len]).unwrap();

        bob.forget_peer(&iid);
        assert_eq!(bob.peer_count(), 0);
        assert_eq!(bob.pinned_pubkey_for(&iid), None);
        bob.add_peer(peer);
        assert!(bob.receive_frame(&wire[..len]).is_ok());
    }

    #[test]
    fn authenticated_evidence_is_bound_to_receiver_and_peer_generation() {
        let alice = Identity::from_seed(Seed::new([0x43; 32]));
        let peer = PeerIdentity::from_pubkey(alice.pubkey);
        let iid = peer.iid;
        let sender = LinkLayer::new(alice);
        let mut first_receiver = make_ll(0x24);
        first_receiver.add_peer(peer.clone());
        let mut second_receiver = make_ll(0x25);
        second_receiver.add_peer(peer.clone());
        let mut wire = [0u8; 256];
        let len = sender
            .build_frame(1, seq(1), &[], b"authenticated", &mut wire)
            .unwrap();
        let evidence = first_receiver.receive_frame(&wire[..len]).unwrap();

        assert!(first_receiver.accepts_authenticated_frame(&evidence));
        assert!(!second_receiver.accepts_authenticated_frame(&evidence));

        first_receiver.forget_peer(&iid);
        assert!(!first_receiver.accepts_authenticated_frame(&evidence));
        first_receiver.add_peer(peer);
        assert!(!first_receiver.accepts_authenticated_frame(&evidence));
        assert!(!evidence.is_current());
    }

    #[test]
    fn authenticated_evidence_captures_monotonic_clock_domain() {
        let alice = Identity::from_seed(Seed::new([0x44; 32]));
        let peer = PeerIdentity::from_pubkey(alice.pubkey);
        let sender = LinkLayer::new(alice);
        let mut receiver = make_ll(0x45);
        receiver.add_peer(peer.clone());
        let mut other_receiver = make_ll(0x46);
        other_receiver.add_peer(peer);
        let mut first_wire = [0u8; 256];
        let first_len = sender
            .build_frame(1, seq(1), &[], b"first", &mut first_wire)
            .unwrap();
        let first = receiver
            .receive_frame_at(&first_wire[..first_len], 1_000)
            .unwrap();
        assert_eq!(first.receipt().monotonic_ticks(), 1_000);

        let mut second_wire = [0u8; 256];
        let second_len = sender
            .build_frame(1, seq(2), &[], b"second", &mut second_wire)
            .unwrap();
        let second = receiver
            .receive_frame_at(&second_wire[..second_len], 1_025)
            .unwrap();
        assert_eq!(second.receipt().elapsed_since(&first.receipt()), Some(25));
        assert!(matches!(
            receiver.receive_frame_at(&second_wire[..second_len], 999),
            Err(LinkRxError::ClockRegression)
        ));

        let mut foreign_wire = [0u8; 256];
        let foreign_len = sender
            .build_frame(1, seq(3), &[], b"foreign", &mut foreign_wire)
            .unwrap();
        let foreign = other_receiver
            .receive_frame_at(&foreign_wire[..foreign_len], 1_025)
            .unwrap();
        assert_eq!(foreign.receipt().elapsed_since(&first.receipt()), None);
    }

    // ── RX frame_length validation (no u8 truncation) ────────────────────

    #[test]
    fn rx_frame_length_accepts_max_and_rejects_over() {
        // Boundary includes the mandatory eight-byte signer EUI-64.
        let max_payload = MAX_FRAME_BODY - 4 - 2 - 8 - SIGNATURE_LENGTH;
        assert_eq!(rx_frame_length(2, 8, max_payload), Ok(MAX_FRAME_BODY as u8));
        assert_eq!(
            rx_frame_length(2, 8, max_payload + 1),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn rx_frame_length_rejects_adversarial_lengths_without_overflow() {
        assert_eq!(
            rx_frame_length(usize::MAX, 8, usize::MAX),
            Err(FrameError::FrameTooLarge)
        );
        assert_eq!(
            rx_frame_length(0, 8, usize::MAX),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn signed_trust_state_restores_fresh_runtime_generation_and_replay() {
        let sender_identity = Identity::from_seed(Seed::new([0xa1; 32]));
        let receiver_seed = Seed::new([0xb2; 32]);
        let receiver_identity = Identity::from_seed(receiver_seed.clone());
        let peer = PeerIdentity::from_pubkey(sender_identity.pubkey);
        let peer_iid = peer.iid;
        let sender = LinkLayer::new(sender_identity);
        let mut receiver = LinkLayer::new(receiver_identity);
        receiver.add_peer(peer);

        let mut wire = [0u8; 128];
        let length = sender
            .build_frame(
                7,
                LinkSeqNum::new(41),
                &receiver.local_eui64(),
                b"state",
                &mut wire,
            )
            .unwrap();
        let authenticated = receiver.receive_frame_at(&wire[..length], 1).unwrap();
        let old_runtime = authenticated.peer_key_generation();
        let durable = authenticated.durable_peer_key_generation();

        let mut record = [0u8; 256];
        let record_len = receiver
            .persist_peer_trust_state(&peer_iid, 9, None, &mut record)
            .unwrap();
        drop(authenticated);
        drop(receiver);

        let mut restored = LinkLayer::new(Identity::from_seed(receiver_seed));
        assert_eq!(
            restored.restore_peer_trust_state(&record[..record_len], 9),
            Ok(9)
        );
        assert!(matches!(
            restored.receive_frame_at(&wire[..length], 2),
            Err(LinkRxError::Replay)
        ));

        let next_len = sender
            .build_frame(
                7,
                LinkSeqNum::new(42),
                &restored.local_eui64(),
                b"next",
                &mut wire,
            )
            .unwrap();
        let next = restored.receive_frame_at(&wire[..next_len], 3).unwrap();
        assert_ne!(next.peer_key_generation(), old_runtime);
        assert_eq!(next.durable_peer_key_generation(), durable);
    }

    #[test]
    fn trust_state_rejects_corruption_rollback_and_same_key_reinstall_aliasing() {
        let sender_identity = Identity::from_seed(Seed::new([0xc3; 32]));
        let receiver_seed = Seed::new([0xd4; 32]);
        let peer = PeerIdentity::from_pubkey(sender_identity.pubkey);
        let peer_iid = peer.iid;
        let sender = LinkLayer::new(sender_identity);
        let mut receiver = LinkLayer::new(Identity::from_seed(receiver_seed.clone()));
        receiver.add_peer(peer.clone());
        let mut wire = [0u8; 128];
        let length = sender
            .build_frame(
                1,
                LinkSeqNum::new(1),
                &receiver.local_eui64(),
                b"pin",
                &mut wire,
            )
            .unwrap();
        let first = receiver.receive_frame_at(&wire[..length], 1).unwrap();
        let old_durable = first.durable_peer_key_generation();
        drop(first);
        let mut record = [0u8; 256];
        let record_len = receiver
            .persist_peer_trust_state(&peer_iid, 4, None, &mut record)
            .unwrap();

        let mut corrupt = record[..record_len].to_vec();
        corrupt[TRUST_STATE_DOMAIN.len() + 3] ^= 1;
        let mut target = LinkLayer::new(Identity::from_seed(receiver_seed.clone()));
        assert_eq!(
            target.restore_peer_trust_state(&corrupt, 4),
            Err(LinkPersistentStateError::Integrity)
        );
        assert_eq!(target.peer_count(), 0);
        assert_eq!(
            target.restore_peer_trust_state(&record[..record_len], 5),
            Err(LinkPersistentStateError::Rollback)
        );
        assert_eq!(target.peer_count(), 0);

        let mut capped = LinkLayer::new(Identity::from_seed(receiver_seed.clone()));
        capped.max_peers = NonZeroUsize::new(1).unwrap();
        capped.replay.max_peers = NonZeroUsize::new(1).unwrap();
        capped.add_peer(PeerIdentity::from_pubkey(
            Identity::from_seed(Seed::new([0xee; 32])).pubkey,
        ));
        assert_eq!(
            capped.restore_peer_trust_state(&record[..record_len], 4),
            Err(LinkPersistentStateError::Conflict)
        );
        assert_eq!(capped.peer_count(), 1);

        assert_eq!(
            target.restore_peer_trust_state(&record[..record_len], 4),
            Ok(4)
        );
        let next_len = sender
            .build_frame(
                1,
                LinkSeqNum::new(2),
                &target.local_eui64(),
                b"next",
                &mut wire,
            )
            .unwrap();
        let restored_frame = target.receive_frame_at(&wire[..next_len], 2).unwrap();
        assert_eq!(restored_frame.durable_peer_key_generation(), old_durable);
        drop(restored_frame);
        target.unpin_peer(&peer_iid);
        let reinstall_len = sender
            .build_frame(
                1,
                LinkSeqNum::new(3),
                &target.local_eui64(),
                b"reinstall",
                &mut wire,
            )
            .unwrap();
        let reinstalled = target.receive_frame_at(&wire[..reinstall_len], 3).unwrap();
        assert_ne!(reinstalled.durable_peer_key_generation(), old_durable);
    }

    #[test]
    fn persistent_state_errors_have_stable_diagnostics() {
        assert_eq!(
            std::format!("{}", LinkPersistentStateError::Rollback),
            "persistent peer state rollback detected"
        );
        assert!(std::error::Error::source(&LinkPersistentStateError::Integrity).is_none());
    }

    #[test]
    fn receive_rejects_jumbo_wire_without_verification() {
        let mut bob = make_ll(0x02);

        // Wire longer than the 255-byte maximum: rejected outright.
        let jumbo = vec![0xFFu8; 300];
        assert_eq!(
            bob.receive_frame(&jumbo).unwrap_err(),
            LinkRxError::Frame(FrameError::FrameTooLarge)
        );

        // Short wire whose LENGTH byte claims 255 (> MAX_FRAME_BODY):
        // rejected by the parser, never reaching a truncated length cast.
        let lying_len = vec![0xFFu8; 100];
        assert_eq!(
            bob.receive_frame(&lying_len).unwrap_err(),
            LinkRxError::Frame(FrameError::FrameTooLarge)
        );
    }

    // ── LRU ordering under access_counter saturation ─────────────────────

    fn pubkey_n(n: u8) -> PublicKey {
        Identity::from_seed(Seed::new([n; 32])).pubkey
    }

    #[test]
    fn replay_lru_eviction_survives_counter_saturation() {
        let mut rp = ReplayProtector::new();
        rp.max_peers = NonZeroUsize::new(3).expect("non-zero");
        let k0 = pubkey_n(0xA1);
        let k1 = pubkey_n(0xA2);
        let k2 = pubkey_n(0xA3);
        let k3 = pubkey_n(0xA4);

        rp.access_counter = u64::MAX - 2;
        assert!(rp.check_and_update(&k0, 1, seq(1))); // last_access = MAX-1
        rp.access_counter = u64::MAX - 1;
        assert!(rp.check_and_update(&k1, 1, seq(1))); // saturates to MAX
        assert!(rp.check_and_update(&k2, 1, seq(1))); // MAX
        assert!(rp.check_and_update(&k3, 1, seq(1))); // insert #4 evicts k0

        // The genuinely oldest (pre-saturation) peer was evicted; the
        // saturated most-recent tier survived. With wrapping_add, k1 would
        // have wrapped to 0 ("oldest") and been evicted instead.
        assert!(!rp.peers.contains_key(&k0), "oldest must be evicted");
        assert!(rp.peers.contains_key(&k1), "newest must survive wrap");
        assert!(rp.peers.contains_key(&k2));
        assert!(rp.peers.contains_key(&k3));
    }

    #[test]
    fn link_layer_lru_eviction_survives_counter_saturation() {
        let mut ll = make_ll(0x02);
        ll.max_peers = NonZeroUsize::new(2).expect("non-zero");
        let p0 = PeerIdentity::from_pubkey(pubkey_n(0xB1));
        let p1 = PeerIdentity::from_pubkey(pubkey_n(0xB2));
        let p2 = PeerIdentity::from_pubkey(pubkey_n(0xB3));
        let iid0 = p0.iid;
        let iid1 = p1.iid;
        let iid2 = p2.iid;

        ll.access_counter = u64::MAX - 2;
        ll.add_peer(p0); // last_access = MAX-1
        ll.access_counter = u64::MAX - 1;
        ll.add_peer(p1); // saturates to MAX
        ll.add_peer(p2); // insert #3 evicts p0

        assert_eq!(ll.peer_count(), 2);
        assert_eq!(ll.peer_auth_state(&iid0), PeerAuthState::Unknown);
        assert_ne!(ll.peer_auth_state(&iid1), PeerAuthState::Unknown);
        assert_ne!(ll.peer_auth_state(&iid2), PeerAuthState::Unknown);
    }

    // ── peer-table capacity invariant (max_peers != 0) ───────────────────

    #[test]
    fn max_peers_zero_is_unrepresentable() {
        // Type-level guarantee: capacity cannot be constructed as zero.
        assert!(NonZeroUsize::new(0).is_none());

        let ll = make_ll(0x01);
        assert_eq!(ll.max_peers.get(), 64);

        let rp = ReplayProtector::new();
        assert_eq!(rp.max_peers.get(), 64);
    }

    #[test]
    fn link_layer_trims_to_capacity_keeping_newest_peers() {
        let mut ll = make_ll(0x01);
        let iid_first = PeerIdentity::from_pubkey(pubkey_n(0xC1)).iid;
        let iid_second = PeerIdentity::from_pubkey(pubkey_n(0xC2)).iid;
        let iid_last = PeerIdentity::from_pubkey(pubkey_n(42)).iid;

        for i in 1..=66u8 {
            ll.add_peer(PeerIdentity::from_pubkey(pubkey_n(i)));
        }

        assert_eq!(ll.peer_count(), 64);
        assert_eq!(ll.peer_auth_state(&iid_first), PeerAuthState::Unknown);
        assert_eq!(ll.peer_auth_state(&iid_second), PeerAuthState::Unknown);
        assert_ne!(ll.peer_auth_state(&iid_last), PeerAuthState::Unknown);
    }

    #[test]
    fn add_peer_canonicalizes_caller_supplied_iid() {
        let identity = Identity::from_seed(Seed::new([0xD1; 32]));
        let canonical = PeerIdentity::from_pubkey(identity.pubkey);
        let forged_iid = [0xA5; 8];
        assert_ne!(forged_iid, canonical.iid);

        let mut ll = make_ll(0xD2);
        ll.add_peer(PeerIdentity {
            pubkey: identity.pubkey,
            iid: forged_iid,
        });

        assert_eq!(ll.peer_auth_state(&forged_iid), PeerAuthState::Unknown);
        assert_eq!(
            ll.peer_auth_state(&canonical.iid),
            PeerAuthState::Authenticating
        );
    }

    #[test]
    fn replay_protector_trims_to_capacity() {
        let mut rp = ReplayProtector::new();
        for i in 1..=66u8 {
            assert!(rp.check_and_update(&pubkey_n(i), 1, seq(1)));
        }
        assert_eq!(rp.peers.len(), 64);
    }
}
