//! LICHEN link layer: signed frame TX/RX with TOFU peer management.

use std::collections::HashMap;
use std::vec::Vec;

use crate::frame::{FrameError, LichenFrame};
use crate::identity::{Identity, PeerIdentity};
use crate::replay::ReplayWindow;
use crate::schnorr::{self, SIGNATURE_LENGTH};

/// Error returned by [`LinkLayer::receive_frame`].
#[derive(Debug, PartialEq, Eq)]
pub enum RxError {
    Frame(FrameError),
    /// Frame has no signature but all LICHEN frames must be signed.
    Unsigned,
    /// No known peer has a valid signature for this frame (TOFU: frame
    /// arrives from a pubkey not yet in the peer table).
    UnknownSender,
    /// Replay-window check failed (duplicate or too-old seqnum).
    Replay,
    /// Payload shorter than the mandatory 48-byte signature trailer.
    TruncatedPayload,
    /// A previously-pinned IID appeared with a different public key.
    KeyChange,
}

impl From<FrameError> for RxError {
    fn from(e: FrameError) -> Self {
        RxError::Frame(e)
    }
}

/// A successfully received and authenticated frame.
#[derive(Debug)]
pub struct RxFrame {
    /// The inner payload (everything before the 48-byte signature trailer).
    pub payload: Vec<u8>,
    /// Identity of the authenticated sender.
    pub sender: PeerIdentity,
}

/// Per-peer replay-window tracker keyed by `(pubkey, epoch)`.
pub struct ReplayProtector {
    windows: HashMap<([u8; 32], u8), ReplayWindow>,
}

impl ReplayProtector {
    pub fn new() -> Self {
        ReplayProtector { windows: HashMap::new() }
    }

    /// Check and advance the window. Returns `true` if the frame is fresh.
    pub fn check_and_update(&mut self, pubkey: &[u8; 32], epoch: u8, seqnum: u16) -> bool {
        self.windows
            .entry((*pubkey, epoch))
            .or_default()
            .accept(seqnum)
    }

    pub fn reset_peer(&mut self, pubkey: &[u8; 32]) {
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
/// pinned pubkey; a mismatch returns `RxError::KeyChange`.
pub struct LinkLayer {
    pub identity: Identity,
    peers: HashMap<[u8; 8], PeerIdentity>,
    replay: ReplayProtector,
    pinned: HashMap<[u8; 8], [u8; 32]>,
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
    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<&[u8; 32]> {
        self.pinned.get(iid)
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
    pub fn build_frame(
        &self,
        epoch: u8,
        seqnum: u16,
        dst_addr: &[u8],
        inner_payload: &[u8],
        out: &mut [u8],
    ) -> usize {
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
            signature_present: true,
            encrypted: false,
        };
        frame.write_to(out).expect("build_frame: buffer too small")
    }

    /// Parse, authenticate, and replay-check an incoming frame.
    pub fn receive_frame(&mut self, wire: &[u8]) -> Result<RxFrame, RxError> {
        let frame = LichenFrame::from_bytes(wire)?;

        if !frame.signature_present {
            return Err(RxError::Unsigned);
        }
        if frame.payload.len() < SIGNATURE_LENGTH {
            return Err(RxError::TruncatedPayload);
        }

        let inner_len = frame.payload.len() - SIGNATURE_LENGTH;
        let inner_payload = &frame.payload[..inner_len];

        // O(n) scan — try every known peer
        let sender = self
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
            .ok_or(RxError::UnknownSender)?;

        // Key pinning: first-contact pins IID→pubkey; subsequent frames must match.
        match self.pinned.get(&sender.iid) {
            Some(pk) if pk != &sender.pubkey => return Err(RxError::KeyChange),
            None => { self.pinned.insert(sender.iid, sender.pubkey); }
            _ => {}
        }

        if !self.replay.check_and_update(&sender.pubkey, frame.epoch, frame.seqnum) {
            return Err(RxError::Replay);
        }

        Ok(RxFrame {
            payload: inner_payload.to_vec(),
            sender,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn make_ll(seed: u8) -> LinkLayer {
        LinkLayer::new(Identity::from_seed([seed; 32]))
    }

    #[test]
    fn tx_rx_basic() {
        let alice = Identity::from_seed([0x01u8; 32]);

        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = LinkLayer::new(Identity::from_seed([0x02u8; 32]));
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice.build_frame(1, 1, &[], b"hello", &mut wire);

        let rx = ll_bob.receive_frame(&wire[..n]).unwrap();
        assert_eq!(rx.payload, b"hello");
    }

    #[test]
    fn replay_rejected() {
        let alice = Identity::from_seed([0x01u8; 32]);
        let bob_seed = [0x02u8; 32];

        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = LinkLayer::new(Identity::from_seed(bob_seed));
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice.build_frame(1, 42, &[], b"data", &mut wire);

        ll_bob.receive_frame(&wire[..n]).unwrap();
        let err = ll_bob.receive_frame(&wire[..n]).unwrap_err();
        assert_eq!(err, RxError::Replay);
    }

    #[test]
    fn unknown_sender_rejected() {
        let alice = Identity::from_seed([0x01u8; 32]);
        let mut ll_bob = make_ll(0x02);
        // Alice is NOT added as a peer

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice.build_frame(1, 1, &[], b"hi", &mut wire);

        assert_eq!(ll_bob.receive_frame(&wire[..n]).unwrap_err(), RxError::UnknownSender);
    }

    #[test]
    fn tampered_payload_rejected() {
        let alice = Identity::from_seed([0x01u8; 32]);
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(alice);
        let mut wire = [0u8; 256];
        let n = ll_alice.build_frame(1, 1, &[], b"hello", &mut wire);

        // Flip a bit in the inner payload region
        wire[6] ^= 0xFF;
        assert_eq!(ll_bob.receive_frame(&wire[..n]).unwrap_err(), RxError::UnknownSender);
    }

    #[test]
    fn peer_count_tracked() {
        let mut ll = make_ll(0x01);
        assert_eq!(ll.peer_count(), 0);
        let peer_a = PeerIdentity::from_pubkey(Identity::from_seed([0x02u8; 32]).pubkey);
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
        let alice = Identity::from_seed([0x01u8; 32]);
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer.clone());

        let ll_alice = LinkLayer::new(alice);
        let mut wire1 = [0u8; 256];
        let n1 = ll_alice.build_frame(1, 1, &[], b"hello", &mut wire1);

        // First RX succeeds and pins alice_iid → alice's pubkey.
        ll_bob.receive_frame(&wire1[..n1]).unwrap();
        assert_eq!(ll_bob.pinned_pubkey_for(&alice_iid), Some(&alice_peer.pubkey));

        // Simulate key change: overwrite pin with a different pubkey.
        let impostor_pk = Identity::from_seed([0x99u8; 32]).pubkey;
        ll_bob.pinned.insert(alice_iid, impostor_pk);

        // Second RX with same alice frame must now fail with KeyChange.
        let ll_alice2 = LinkLayer::new(Identity::from_seed([0x01u8; 32]));
        let mut wire2 = [0u8; 256];
        let n2 = ll_alice2.build_frame(1, 2, &[], b"hi", &mut wire2);
        assert_eq!(ll_bob.receive_frame(&wire2[..n2]).unwrap_err(), RxError::KeyChange);
    }

    #[test]
    fn unpin_allows_key_rotation() {
        let alice = Identity::from_seed([0x01u8; 32]);
        let alice_peer = PeerIdentity::from_pubkey(alice.pubkey);
        let alice_iid = alice_peer.iid;
        let mut ll_bob = make_ll(0x02);
        ll_bob.add_peer(alice_peer);

        let ll_alice = LinkLayer::new(Identity::from_seed([0x01u8; 32]));
        let mut wire = [0u8; 256];
        let n = ll_alice.build_frame(1, 1, &[], b"hello", &mut wire);
        ll_bob.receive_frame(&wire[..n]).unwrap();

        // Admin unpins: allows accepting a new key for this IID.
        ll_bob.unpin_peer(&alice_iid);
        assert_eq!(ll_bob.pinned_pubkey_for(&alice_iid), None);

        // New key accepted and re-pinned.
        let new_alice = Identity::from_seed([0xAAu8; 32]);
        let new_alice_peer = PeerIdentity::from_pubkey(new_alice.pubkey);
        ll_bob.remove_peer(&alice_iid);
        ll_bob.add_peer(new_alice_peer.clone());

        let ll_new = LinkLayer::new(new_alice);
        let mut wire2 = [0u8; 256];
        let n2 = ll_new.build_frame(1, 1, &[], b"rotated", &mut wire2);
        ll_bob.receive_frame(&wire2[..n2]).unwrap();
        assert_eq!(ll_bob.pinned_pubkey_for(&new_alice_peer.iid), Some(&new_alice_peer.pubkey));
    }
}
