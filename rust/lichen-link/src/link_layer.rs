//! LICHEN link layer: signed frame TX/RX with TOFU peer management.

use core::marker::PhantomData;
use std::collections::{HashMap, VecDeque};
use std::vec::Vec;

#[cfg(feature = "log")]
use log::{debug, warn};

use crate::frame::{
    AddrMode, Encryption, FrameError, LichenFrame, MicLength, Signature, MAX_FRAME_BODY,
};
use crate::identity::{Identity, PeerIdentity};
use crate::keys::PublicKey;
use crate::replay::ReplayWindow;
use crate::schnorr::{self, SIGNATURE_LENGTH};
use crate::seqnum::LinkSeqNum;
use lichen_core::error::TooShort;

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
}

impl std::fmt::Display for LinkRxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame error: {}", e),
            Self::Unsigned => write!(f, "frame has no signature"),
            Self::UnknownSender => write!(f, "unknown sender"),
            Self::Replay => write!(f, "replay detected"),
            Self::TooShort(e) => write!(f, "payload {}", e),
            Self::KeyChange => write!(f, "key change detected"),
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
#[derive(Debug)]
pub struct AuthenticatedFrame {
    /// The inner payload, excluding link-layer MIC bytes.
    pub payload: Vec<u8>,
    /// Identity of the authenticated sender.
    pub sender: PeerIdentity,
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
    access_counter: u64,
    max_peers: usize,
}

impl ReplayProtector {
    pub fn new() -> Self {
        ReplayProtector {
            peers: HashMap::new(),
            access_counter: 0,
            max_peers: 32,
        }
    }

    /// Check and advance the window. Returns `true` if the frame is fresh.
    ///
    /// Epochs are finite for a given public key: wrapping from 255 to 0 is a
    /// rollback and requires a new key (and therefore fresh replay state).
    pub fn check_and_update(&mut self, pubkey: &PublicKey, epoch: u8, seqnum: LinkSeqNum) -> bool {
        self.access_counter = self.access_counter.wrapping_add(1);
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
                let epoch_diff = epoch.wrapping_sub(state.last_epoch) as i8;

                if epoch_diff > 0 {
                    state.last_epoch = epoch;
                    state.window = ReplayWindow::new();
                    state.window.accept(seqnum)
                } else if epoch_diff < 0 {
                    false
                } else {
                    state.window.accept(seqnum)
                }
            }
        }
    }

    fn evict_if_needed(&mut self) {
        while self.peers.len() > self.max_peers {
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
}

#[derive(Debug, Clone)]
struct PinnedKey {
    pubkey: PublicKey,
    last_access: u64,
}

/// LICHEN link layer: builds signed frames for TX and verifies them on RX.
///
/// Peer table is keyed by IID (8 bytes) in a HashMap for O(1) lookup.
/// On RX, every known peer is tried; the first successful verify pins the
/// sender. Unknown senders are rejected (no TOFU auto-enrolment — callers
/// handle that via the Announce layer).
///
/// # Signature Verification Cost
///
/// Since frames do not include the sender IID, RX must scan peers to find
/// whose public key verifies the signature. Worst-case is O(n) Schnorr
/// verifications where n = peer count. Keep peer count low (e.g., <20 direct
/// neighbors) or implement sender IID hints in upper layers for larger networks.
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
    access_counter: u64,
    max_peers: usize,
    verify_cache: VecDeque<(PublicKey, [u8; 8])>,
    max_cache: usize,
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
            max_peers: 32,
            verify_cache: VecDeque::new(),
            max_cache: 16,
        }
    }

    /// Remove the key pin for a peer IID (use only for intentional key rotation).
    pub fn unpin_peer(&mut self, iid: &[u8; 8]) {
        self.pinned.remove(iid);
    }

    /// Return the pinned pubkey for an IID, or None if not yet seen.
    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<&PublicKey> {
        self.pinned.get(iid).map(|p| &p.pubkey)
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

    pub fn add_peer(&mut self, peer: PeerIdentity) {
        self.access_counter = self.access_counter.wrapping_add(1);
        let access = self.access_counter;
        let tracked = TrackedPeer {
            identity: peer,
            last_access: access,
        };
        self.peers.insert(tracked.identity.iid, tracked);
        self.evict_if_needed();
    }

    pub fn remove_peer(&mut self, iid: &[u8; 8]) {
        if let Some(tracked) = self.peers.remove(iid) {
            self.replay.reset_peer(&tracked.identity.pubkey);
            self.evict_cache_by_iid(iid);
        }
        self.pinned.remove(iid);
    }

    /// Atomically remove a peer's configured key, pin, and replay window.
    pub fn forget_peer(&mut self, iid: &[u8; 8]) {
        let peer_key = self.peers.remove(iid).map(|peer| peer.pubkey);
        let pinned_key = self.pinned.remove(iid);
        if let Some(key) = peer_key {
            self.replay.reset_peer(&key);
            self.evict_cache_by_pubkey(&key);
        }
        if let Some(key) = pinned_key {
            if Some(key) != peer_key {
                self.replay.reset_peer(&key);
                self.evict_cache_by_pubkey(&key);
            }
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn evict_if_needed(&mut self) {
        while self.peers.len() > self.max_peers {
            let oldest_iid = self
                .peers
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                if let Some(tracked) = self.peers.remove(&iid) {
                    self.replay.reset_peer(&tracked.identity.pubkey);
                    self.pinned.remove(&iid);
                    self.evict_cache_by_pubkey(&tracked.identity.pubkey);
                }
            } else {
                break;
            }
        }
    }

    fn evict_cache_by_iid(&mut self, iid: &[u8; 8]) {
        self.verify_cache.retain(|(_, cached_iid)| cached_iid != iid);
    }

    fn evict_cache_by_pubkey(&mut self, pubkey: &PublicKey) {
        self.verify_cache.retain(|(pk, _)| pk != pubkey);
    }

    /// Serialise a signed frame into `out`. Returns bytes written.
    ///
    /// The 48-byte signature occupies the frame MIC field.
    ///
    /// Returns `FrameError::FrameTooLarge` if body > 254 bytes.
    /// Returns `FrameError::BufferTooSmall` if `out` is too small.
    /// Callers must provide a buffer of at least `inner_payload.len() + 53`
    /// bytes.
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
        let llsec = (addr_mode as u8) | (1 << 5);
        let frame_length = 4 + dst_addr.len() + inner_payload.len() + SIGNATURE_LENGTH;
        if frame_length > MAX_FRAME_BODY {
            return Err(FrameError::FrameTooLarge);
        }
        let sig = schnorr::sign_frame(
            frame_length as u8,
            llsec,
            epoch,
            seqnum,
            dst_addr,
            inner_payload,
            &self.identity.privkey,
            &self.identity.pubkey,
        );
        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr,
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
        let frame_length = 4 + frame.dst_addr.len() + inner_payload.len() + SIGNATURE_LENGTH;

        // Try the LRU verify cache first (O(cache_size), typical hit for bursty traffic).
        let sender = self
            .verify_cache
            .iter()
            .find_map(|(pubkey, iid)| {
                let tracked = self.peers.get(iid)?;
                if tracked.identity.pubkey != *pubkey {
                    return None;
                }
                schnorr::verify_frame(
                    frame_length as u8,
                    frame.llsec_byte(),
                    frame.epoch,
                    frame.seqnum,
                    frame.dst_addr,
                    frame.payload,
                    frame.mic,
                    pubkey,
                )
                .then(|| tracked.identity.clone())
            })
            .or_else(|| {
                // Cache miss — O(n) scan over all known peers
                self.peers.values().find_map(|p| {
                    schnorr::verify_frame(
                        frame_length as u8,
                        frame.llsec_byte(),
                        frame.epoch,
                        frame.seqnum,
                        frame.dst_addr,
                        frame.payload,
                        frame.mic,
                        &p.identity.pubkey,
                    )
                    .then(|| p.identity.clone())
                })
            });

        let Some(sender) = sender else {
            #[cfg(feature = "log")]
            debug!("link_layer: frame from unknown sender");
            return Err(LinkRxError::UnknownSender);
        };

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

        self.access_counter = self.access_counter.wrapping_add(1);
        let access = self.access_counter;
        if let Some(tracked) = self.peers.get_mut(&sender.iid) {
            tracked.last_access = access;
        }
        self.pinned.insert(
            sender.iid,
            PinnedKey {
                pubkey: sender.pubkey,
                last_access: access,
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

        // Promote sender to front of verify LRU cache.
        self.cache_verify_hit(sender.pubkey, sender.iid);

        Ok(AuthenticatedFrame {
            payload: inner_payload.to_vec(),
            sender,
        })
    }

    /// Record a successful verification in the LRU cache.
    fn cache_verify_hit(&mut self, pubkey: PublicKey, iid: [u8; 8]) {
        // Remove stale entry for this pubkey, if present.
        if let Some(pos) = self.verify_cache.iter().position(|(pk, _)| *pk == pubkey) {
            self.verify_cache.remove(pos);
        }
        self.verify_cache.push_front((pubkey, iid));
        while self.verify_cache.len() > self.max_cache {
            self.verify_cache.pop_back();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keys::Seed;

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
                last_access: 0,
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
}
