//! LICHEN link layer: signed frame TX/RX with TOFU peer management.

use core::marker::PhantomData;
use std::collections::HashMap;
use std::vec::Vec;

#[cfg(feature = "log")]
use log::{debug, warn};

use crate::frame::{Encryption, FrameError, LichenFrame, Signature};
use crate::identity::{Identity, PeerIdentity};
use crate::keys::PublicKey;
use crate::replay::ReplayWindow;
use crate::schnorr::{self, SIGNATURE_LENGTH};
use crate::seqnum::LinkSeqNum;
use lichen_core::error::TooShort;

/// Error returned by [`LinkLayer::receive_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRxError {
    Frame(FrameError),
    /// Frame has no signature but all LICHEN frames must be signed.
    Unsigned,
    /// No known peer has a valid signature for this frame (TOFU: frame
    /// arrives from a pubkey not yet in the peer table).
    UnknownSender,
    /// Replay-window check failed (duplicate or too-old seqnum).
    Replay,
    /// Payload shorter than the mandatory 48-byte signature trailer.
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
/// signature trailer; it contains the SCHC-compressed IPv6 packet ready
/// for decompression.
///
/// Note: This is distinct from `lichen_node::ReceivedIpv6` which represents
/// a fully decompressed IPv6 packet with radio metadata attached.
#[derive(Debug)]
pub struct AuthenticatedFrame {
    /// The inner payload (everything before the 48-byte signature trailer).
    pub payload: Vec<u8>,
    /// Identity of the authenticated sender.
    pub sender: PeerIdentity,
}

/// Per-peer replay-window tracker keyed by `(pubkey, epoch)`.
#[derive(Debug)]
pub struct ReplayProtector {
    windows: HashMap<(PublicKey, u8), ReplayWindow>,
}

impl ReplayProtector {
    pub fn new() -> Self {
        ReplayProtector {
            windows: HashMap::new(),
        }
    }

    /// Check and advance the window. Returns `true` if the frame is fresh.
    pub fn check_and_update(&mut self, pubkey: &PublicKey, epoch: u8, seqnum: LinkSeqNum) -> bool {
        self.windows
            .entry((*pubkey, epoch))
            .or_default()
            .accept(seqnum)
    }

    pub fn reset_peer(&mut self, pubkey: &PublicKey) {
        self.windows.retain(|(pk, _), _| pk != pubkey);
    }
}

impl Default for ReplayProtector {
    fn default() -> Self {
        Self::new()
    }
}

/// LICHEN link layer: builds signed frames for TX and verifies them on RX.
///
/// Peer table is keyed by IID (8 bytes). On RX, every known peer is tried;
/// the first successful verify pins the sender. Unknown senders are rejected
/// (no TOFU auto-enrolment — callers handle that via the Announce layer).
///
/// Key pinning: once an IID is seen with a valid signature, its pubkey is
/// stored in `pinned`. Subsequent frames from the same IID must match the
/// pinned pubkey; a mismatch returns `LinkRxError::KeyChange`.
pub struct LinkLayer {
    identity: Identity,
    peers: HashMap<[u8; 8], PeerIdentity>,
    replay: ReplayProtector,
    pinned: HashMap<[u8; 8], PublicKey>,
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
        }
    }

    /// Remove the key pin for a peer IID (use only for intentional key rotation).
    pub fn unpin_peer(&mut self, iid: &[u8; 8]) {
        self.pinned.remove(iid);
    }

    /// Return the pinned pubkey for an IID, or None if not yet seen.
    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<&PublicKey> {
        self.pinned.get(iid)
    }

    pub fn peer_auth_state(&self, iid: &[u8; 8]) -> PeerAuthState {
        match (self.peers.get(iid), self.pinned.get(iid)) {
            (Some(peer), Some(pk)) if *pk == peer.pubkey => PeerAuthState::Authenticated,
            (Some(_), _) => PeerAuthState::Authenticating,
            (None, _) => PeerAuthState::Unknown,
        }
    }

    pub fn add_peer(&mut self, peer: PeerIdentity) {
        self.peers.insert(peer.iid, peer);
    }

    pub fn remove_peer(&mut self, iid: &[u8; 8]) {
        self.peers.remove(iid);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Serialise a signed frame into `out`. Returns bytes written.
    ///
    /// inner_payload is signed; the resulting wire frame contains
    /// `inner_payload || sig(48B)` as its payload field.
    ///
    /// # Panics
    ///
    /// Returns an error if `out` is smaller than the serialised frame size.
    /// Callers must provide a buffer of at least `inner_payload.len() + 48 + 6`
    /// bytes (frame header + signature trailer).
    pub fn build_frame(
        &self,
        epoch: u8,
        seqnum: LinkSeqNum,
        dst_addr: &[u8],
        inner_payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, FrameError> {
        let sig = schnorr::sign_frame(
            epoch,
            seqnum,
            dst_addr,
            inner_payload,
            &self.identity.privkey,
            &self.identity.pubkey,
        );
        let mut signed = Vec::with_capacity(inner_payload.len() + SIGNATURE_LENGTH);
        signed.extend_from_slice(inner_payload);
        signed.extend_from_slice(&sig);

        let frame = LichenFrame {
            epoch,
            seqnum,
            dst_addr,
            payload: &signed,
            mic: &[0u8; 4],
            addr_mode: crate::frame::AddrMode::None,
            mic_length: crate::frame::MicLength::Bits32,
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
        if frame.payload.len() < SIGNATURE_LENGTH {
            return Err(TooShort::new(SIGNATURE_LENGTH, frame.payload.len()).into());
        }

        let inner_len = frame.payload.len() - SIGNATURE_LENGTH;
        let inner_payload = &frame.payload[..inner_len];

        // O(n) scan — try every known peer
        let Some(sender) = self
            .peers
            .values()
            .find(|peer| {
                schnorr::verify_frame(
                    frame.epoch,
                    frame.seqnum,
                    frame.dst_addr,
                    frame.payload,
                    &peer.pubkey,
                )
            })
            .cloned()
        else {
            #[cfg(feature = "log")]
            debug!("link_layer: frame from unknown sender");
            return Err(LinkRxError::UnknownSender);
        };

        // Key pinning: first-contact pins IID→pubkey; subsequent frames must match.
        let old_state = self.peer_auth_state(&sender.iid);
        match self.pinned.get(&sender.iid) {
            Some(pk) if *pk != sender.pubkey => {
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

        self.pinned.entry(sender.iid).or_insert(sender.pubkey);
        let new_state = self.peer_auth_state(&sender.iid);
        if !old_state.can_transition_to(new_state) {
            #[cfg(feature = "log")]
            warn!(
                "link_layer: illegal peer auth state transition {:?}->{:?}",
                old_state, new_state
            );
            return Err(LinkRxError::KeyChange);
        }

        Ok(AuthenticatedFrame {
            payload: inner_payload.to_vec(),
            sender,
        })
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
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer.clone());

        let ll_alice = LinkLayer::new(alice);
        let mut wire1 = [0u8; 256];
        let n1 = ll_alice
            .build_frame(1, seq(1), &[], b"hello", &mut wire1)
            .unwrap();

        // First RX succeeds and pins alice_iid → alice's pubkey.
        ll_bob.receive_frame(&wire1[..n1]).unwrap();
        assert_eq!(
            ll_bob.pinned_pubkey_for(&alice_iid),
            Some(&alice_peer.pubkey)
        );

        // Simulate key change: overwrite pin with a different pubkey.
        let impostor_pk = Identity::from_seed(Seed::new([0x99u8; 32])).pubkey;
        ll_bob.pinned.insert(alice_iid, impostor_pk);

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
        ll_bob.remove_peer(&alice_iid);
        ll_bob.add_peer(new_alice_peer.clone());

        let ll_new = LinkLayer::new(new_alice);
        let mut wire2 = [0u8; 256];
        let n2 = ll_new
            .build_frame(1, seq(1), &[], b"rotated", &mut wire2)
            .unwrap();
        ll_bob.receive_frame(&wire2[..n2]).unwrap();
        assert_eq!(
            ll_bob.pinned_pubkey_for(&new_alice_peer.iid),
            Some(&new_alice_peer.pubkey)
        );
    }
}
