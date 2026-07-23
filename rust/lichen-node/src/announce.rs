//! Announce message processor (spec section 9.3).
//!
//! Processes incoming announces: verifies signatures, detects duplicates,
//! updates gradients, decides whether to relay.
//!
//! Why separate from lichen-core/announce.rs: That crate provides the pure codec.
//! Processing involves state (gradient table, seen announces, peer database) and
//! crypto operations. Separation keeps the codec testable without crypto deps.

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::vec::Vec;

use lichen_core::announce::Announce;
use lichen_link::identity::{iid_from_pubkey, PeerIdentity};
use lichen_link::keys::PublicKey;
use lichen_link::schnorr;

use crate::gradient::{
    GeoCoords, GradientEntry, GradientSource, GradientTable, GRADIENT_TIMEOUT_MS,
};

/// Maximum tracked originators (LRU eviction when exceeded).
pub const MAX_TRACKED_ORIGINATORS: usize = 64;

/// Sequence number half-space for RFC 1982 comparison.
const SEQ_HALF: u16 = 1 << 15;

/// RFC 1982 serial number arithmetic: return true if `a` > `b` (wrap-aware).
///
/// Why: 16-bit sequence numbers wrap around. Simple comparison fails when
/// seq_num wraps from 65535 to 0. RFC 1982 defines "greater than" as:
/// a > b iff (a != b) and ((a - b) mod 2^N) < 2^(N-1)
///
/// This means `a` is "ahead" of `b` if the unsigned distance (a - b) is less
/// than half the sequence space. Works correctly across wrap boundaries.
#[inline]
pub fn seq_gt(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < SEQ_HALF
}

/// Why an announce was rejected (for logging/debugging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceRejectReason {
    /// Schnorr48 signature verification failed.
    InvalidSignature,
    /// IID in announce doesn't match SHA-256(pubkey)\[0:8\].
    IidMismatch,
    /// seq_num <= existing (RFC 1982 serial arithmetic).
    StaleSeqNum,
    /// hop_count >= MAX_ANNOUNCE_HOPS.
    HopLimitExceeded,
    /// Announce failed to parse.
    Malformed,
    /// IID known, but pubkey differs from pinned key.
    /// SECURITY: This indicates either hash collision (cryptographically
    /// implausible) or a bug in key derivation. Hard reject.
    KeyChangeDetected,
}

/// Result of processing an announce message.
///
/// Why a result object: Callers need to know what happened for logging,
/// metrics, and deciding whether to relay. A simple bool loses information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceResult {
    /// Whether the announce was accepted and gradient updated.
    pub accepted: bool,
    /// Whether this announce should be broadcast to neighbors.
    ///
    /// Why separate from accepted: We accept (update gradient) but might
    /// not relay (hop limit reached, or duplicate from better path).
    pub should_relay: bool,
    /// Why the announce was rejected, if not accepted.
    pub reject_reason: Option<AnnounceRejectReason>,
    /// The sender's identity if signature verified.
    pub peer: Option<PeerIdentity>,
    /// Queue depth from announce app_data (spec 11.4), or None.
    pub congestion: Option<u8>,
}

impl AnnounceResult {
    fn rejected(reason: AnnounceRejectReason) -> Self {
        Self {
            accepted: false,
            should_relay: false,
            reject_reason: Some(reason),
            peer: None,
            congestion: None,
        }
    }

    fn accepted(should_relay: bool, peer: PeerIdentity, congestion: Option<u8>) -> Self {
        Self {
            accepted: true,
            should_relay,
            reject_reason: None,
            peer: Some(peer),
            congestion,
        }
    }
}

/// LRU entry for tracking seen originators.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct SeenEntry {
    seq_num: u16,
    /// Monotonically increasing counter for LRU ordering.
    last_access: u64,
}

/// LRU entry for key pinning (TOFU).
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct PinnedKeyEntry {
    pubkey: [u8; 32],
    /// Monotonically increasing counter for LRU ordering.
    last_access: u64,
}

/// Processes incoming announce messages (spec 9.3).
///
/// Why a struct: Needs state across invocations:
/// - gradient_table: Where to install/update routes
/// - seen: Per-originator seq_num for duplicate detection
/// - pinned_keys: IID -> pubkey (TOFU trust anchors)
/// - address_builder: How to convert IID to full IPv6 (prefix is context)
#[cfg(feature = "std")]
pub struct AnnounceProcessor {
    /// Unified routing table (spec section 11).
    gradient_table: GradientTable,
    /// IPv6 prefix for building full addresses from IIDs.
    prefix: [u8; 8],
    /// Per-originator highest seq_num seen (LRU-bounded).
    /// IID is the key, SeenEntry contains seq_num and LRU timestamp.
    seen: HashMap<[u8; 8], SeenEntry>,
    /// IID -> pinned pubkey (TOFU trust anchors, LRU-bounded).
    /// SECURITY: Even though IID = hash(pubkey) makes silent substitution
    /// cryptographically infeasible, we maintain an explicit pin table as
    /// defence-in-depth.
    pinned_keys: HashMap<[u8; 8], PinnedKeyEntry>,
    /// Monotonically increasing counter for LRU ordering.
    access_counter: u64,
    /// Maximum tracked originators.
    max_entries: usize,
}

#[cfg(feature = "std")]
impl AnnounceProcessor {
    /// Create a new announce processor.
    ///
    /// # Arguments
    /// * `gradient_table` - The unified gradient table to update.
    /// * `prefix` - The first 8 bytes of the IPv6 address prefix (e.g., ULA or GUA).
    pub fn new(gradient_table: GradientTable, prefix: [u8; 8]) -> Self {
        Self {
            gradient_table,
            prefix,
            seen: HashMap::new(),
            pinned_keys: HashMap::new(),
            access_counter: 0,
            max_entries: MAX_TRACKED_ORIGINATORS,
        }
    }

    /// Process an incoming announce message (spec 9.3 pseudocode).
    ///
    /// # Arguments
    /// * `announce` - The parsed announce message.
    /// * `from_neighbor` - Link-local address of the neighbor who sent this.
    ///   This becomes the next_hop in our gradient (not the originator).
    /// * `now_ms` - Current time in milliseconds.
    ///
    /// # Returns
    /// `AnnounceResult` indicating what happened.
    pub fn process(
        &mut self,
        announce: &Announce<'_>,
        from_neighbor: [u8; 16],
        now_ms: u32,
    ) -> AnnounceResult {
        // Step 1: Verify IID matches pubkey hash.
        // Why first: This is a cheap check before expensive crypto.
        let pubkey = PublicKey::new(*announce.pubkey);
        let expected_iid = iid_from_pubkey(&pubkey);
        if *announce.originator_iid != expected_iid {
            return AnnounceResult::rejected(AnnounceRejectReason::IidMismatch);
        }

        // Step 2: Verify signature.
        // SECURITY: Proves the announce was created by the holder of this pubkey.
        let mut signed_buf = [0u8; 256];
        let signed_len = announce.write_signed_data(&mut signed_buf).unwrap_or(0);
        if signed_len == 0 {
            return AnnounceResult::rejected(AnnounceRejectReason::Malformed);
        }
        if !schnorr::verify(&pubkey, &signed_buf[..signed_len], announce.signature) {
            return AnnounceResult::rejected(AnnounceRejectReason::InvalidSignature);
        }

        let iid = *announce.originator_iid;

        // Step 3: Key pinning - TOFU anchor + change detection.
        // SECURITY: Even though IID = hash(pubkey) makes silent substitution
        // cryptographically infeasible, we maintain an explicit pin table as
        // defence-in-depth. A pin mismatch means either hash collision or a
        // bug in key derivation - both warrant a hard reject.
        if let Some(entry) = self.pinned_keys.get(&iid) {
            if entry.pubkey != *announce.pubkey {
                return AnnounceResult::rejected(AnnounceRejectReason::KeyChangeDetected);
            }
        }

        // Step 4: Check for stale/duplicate (RFC 1982 serial arithmetic).
        // Why: Prevents processing old announces that were delayed in the network.
        if let Some(entry) = self.seen.get(&iid) {
            if !seq_gt(announce.seq_num, entry.seq_num) {
                return AnnounceResult::rejected(AnnounceRejectReason::StaleSeqNum);
            }
        }

        // Accept: pin pubkey (TOFU first-contact), update seen, update gradient.
        self.access_counter += 1;
        let access = self.access_counter;

        // Update or insert pinned key with LRU eviction
        self.pinned_keys.insert(
            iid,
            PinnedKeyEntry {
                pubkey: *announce.pubkey,
                last_access: access,
            },
        );
        self.evict_pinned_if_needed();

        // Update or insert seen entry with LRU eviction
        self.seen.insert(
            iid,
            SeenEntry {
                seq_num: announce.seq_num,
                last_access: access,
            },
        );
        self.evict_seen_if_needed();

        // Step 5: Update gradient table.
        // Build full IPv6 from prefix + IID.
        let mut destination = [0u8; 16];
        destination[..8].copy_from_slice(&self.prefix);
        destination[8..].copy_from_slice(&iid);

        // Parse optional geo coords from app_data.
        let coords = GeoCoords::from_app_data(announce.app_data);

        // Parse optional congestion from app_data (type 0x02).
        let congestion = parse_congestion(announce.app_data);

        let entry = GradientEntry {
            destination,
            next_hop: from_neighbor,
            hop_count: announce.hop_count,
            seq_num: announce.seq_num,
            source: GradientSource::Announce,
            expires_ms: now_ms.wrapping_add(GRADIENT_TIMEOUT_MS),
            coords,
        };
        self.gradient_table.update(entry, now_ms);

        // Step 6: Decide relay.
        // Why: Propagate announces through the mesh, up to hop limit.
        let should_relay = announce.should_relay();

        let peer = PeerIdentity::from_pubkey(pubkey);
        AnnounceResult::accepted(should_relay, peer, congestion)
    }

    /// Forget the seq_num for an originator (e.g., on key rotation).
    ///
    /// Why: If a node rotates keys, their seq_num may reset. Forgetting
    /// allows accepting announces from their new identity.
    pub fn reset_seen(&mut self, iid: &[u8; 8]) {
        self.seen.remove(iid);
    }

    /// Remove the key pin for an IID (use only for intentional key rotation).
    ///
    /// Why: Administrators who rotate a node's key must unpin the old binding
    /// or all future announces from the new key will be rejected as key changes.
    /// This is an intentional administrative action - not automatic.
    pub fn unpin(&mut self, iid: &[u8; 8]) {
        self.pinned_keys.remove(iid);
    }

    /// Return the pinned pubkey for an IID, or None if not yet seen.
    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<&[u8; 32]> {
        self.pinned_keys.get(iid).map(|e| &e.pubkey)
    }

    /// Return IIDs of all originators we've seen announces from.
    ///
    /// Why: For debugging/monitoring. Not for production routing logic.
    pub fn known_originators(&self) -> Vec<[u8; 8]> {
        self.seen.keys().copied().collect()
    }

    /// Get the relay message with incremented hop count.
    ///
    /// Returns None if the announce shouldn't be relayed (hop limit exceeded).
    ///
    /// Why separate method: process() returns a result, not a modified message.
    /// Caller calls this if should_relay is true and needs the incremented data.
    pub fn build_relay_hop_count(&self, announce: &Announce<'_>) -> Option<u8> {
        if announce.should_relay() {
            Some(announce.hop_count + 1)
        } else {
            None
        }
    }

    /// Access the gradient table.
    pub fn gradient_table(&self) -> &GradientTable {
        &self.gradient_table
    }

    /// Access the gradient table mutably.
    pub fn gradient_table_mut(&mut self) -> &mut GradientTable {
        &mut self.gradient_table
    }

    /// Evict oldest pinned key entry if over capacity.
    fn evict_pinned_if_needed(&mut self) {
        while self.pinned_keys.len() > self.max_entries {
            // Find oldest entry (lowest last_access)
            let oldest_iid = self
                .pinned_keys
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                self.pinned_keys.remove(&iid);
            }
        }
    }

    /// Evict oldest seen entry if over capacity.
    fn evict_seen_if_needed(&mut self) {
        while self.seen.len() > self.max_entries {
            // Find oldest entry (lowest last_access)
            let oldest_iid = self
                .seen
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                self.seen.remove(&iid);
            }
        }
    }
}

const CONGESTION_TLV: u8 = 0x02;

fn parse_congestion(app_data: &[u8]) -> Option<u8> {
    let mut pos = 0;
    while pos + 2 <= app_data.len() {
        let typ = app_data[pos];
        let len = app_data[pos + 1] as usize;
        let value_start = pos + 2;
        let value_end = value_start + len;

        if value_end > app_data.len() {
            return None;
        }

        if typ == CONGESTION_TLV && len >= 1 {
            return Some(app_data[value_start]);
        }

        pos = value_end;
    }
    None
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use lichen_core::announce::AnnounceBuilder;
    use lichen_link::identity::Identity;
    use lichen_link::keys::Seed;
    use lichen_link::schnorr::sign;

    fn make_identity(seed_byte: u8) -> Identity {
        Identity::from_seed(Seed::new([seed_byte; 32]))
    }

    fn link_local(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = iid;
        addr
    }

    fn ula_prefix() -> [u8; 8] {
        [0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    /// Create a valid signed announce message (CCP-9 includes rx_channel in signed_data).
    fn make_signed_announce(
        identity: &Identity,
        seq_num: u16,
        hop_count: u8,
        rx_channel: u8,
        app_data: &[u8],
        buf: &mut [u8],
    ) -> usize {
        // First, build the signed data to sign (includes rx_channel per CCP-9 to match core)
        let mut signed_data = [0u8; 256];
        let signed_len = 8 + 32 + 2 + 1 + app_data.len();
        signed_data[..8].copy_from_slice(&identity.iid);
        signed_data[8..40].copy_from_slice(identity.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&seq_num.to_be_bytes());
        signed_data[42] = rx_channel;
        signed_data[43..signed_len].copy_from_slice(app_data);

        let sig = sign(
            &identity.privkey,
            &identity.pubkey,
            &signed_data[..signed_len],
        );

        // Build the announce
        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num,
            hop_count,
            rx_channel,
            signature: &sig,
            app_data,
            flags: 0,
        };
        builder.write_to(buf).unwrap()
    }

    #[test]
    fn seq_gt_normal() {
        assert!(seq_gt(10, 5));
        assert!(!seq_gt(5, 10));
        assert!(!seq_gt(5, 5));
    }

    #[test]
    fn seq_gt_wraparound() {
        // 0 is newer than 65535 (just wrapped)
        assert!(seq_gt(0, 65535));
        assert!(seq_gt(1, 65535));
        assert!(seq_gt(100, 65535));

        // RFC 1982: a > b iff (a - b) mod 2^16 < 32768
        // 65535 - 32768 = 32767 < 32768, so 65535 > 32768
        assert!(seq_gt(65535, 32768));
        // But 32768 - 65535 mod 2^16 = 32769 >= 32768, so 32768 is NOT > 65535
        assert!(!seq_gt(32768, 65535));
    }

    #[test]
    fn accept_valid_announce() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let from_neighbor = link_local(0xAA);
        let result = processor.process(&announce, from_neighbor, 1000);

        assert!(result.accepted);
        assert!(result.should_relay);
        assert_eq!(result.reject_reason, None);
        assert!(result.peer.is_some());
        let peer = result.peer.unwrap();
        assert_eq!(peer.iid, identity.iid);
    }

    #[test]
    fn reject_iid_mismatch() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Build announce with wrong IID
        let wrong_iid = [0xAA; 8];
        let mut signed_data = [0u8; 43];
        signed_data[..8].copy_from_slice(&identity.iid); // sign with correct IID
        signed_data[8..40].copy_from_slice(identity.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&100u16.to_be_bytes());
        signed_data[42] = 0; // rx_channel per CCP-9
        let sig = sign(&identity.privkey, &identity.pubkey, &signed_data[..43]);

        let builder = AnnounceBuilder {
            originator_iid: &wrong_iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
            flags: 0,
            rx_channel: 0,
        };
        let mut buf = [0u8; 256];
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::IidMismatch)
        );
    }

    #[test]
    fn reject_invalid_signature() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Build announce with tampered signature
        let bad_sig = [0xFF; 48];
        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &bad_sig,
            app_data: &[],
            flags: 0,
        };
        let mut buf = [0u8; 256];
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::InvalidSignature)
        );
    }

    #[test]
    fn reject_stale_seqnum() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Accept first announce with seq_num 100
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Reject announce with same seq_num
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // Reject announce with lower seq_num
        let len = make_signed_announce(&identity, 50, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(!result.accepted);
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::StaleSeqNum)
        );

        // Accept announce with higher seq_num
        let len = make_signed_announce(&identity, 200, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 4000);
        assert!(result.accepted);
    }

    #[test]
    fn reject_key_change() {
        let identity1 = make_identity(0x01);
        let identity2 = make_identity(0x02);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Accept first announce from identity1
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity1, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Now try to spoof the same IID with identity2's pubkey
        // (This would require a SHA-256 collision, so we simulate by
        // manually constructing an announce with identity1's IID but identity2's key)
        let mut signed_data = [0u8; 43];
        signed_data[..8].copy_from_slice(&identity1.iid);
        signed_data[8..40].copy_from_slice(identity2.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&200u16.to_be_bytes());
        signed_data[42] = 0; // rx_channel per CCP-9
        let sig = sign(&identity2.privkey, &identity2.pubkey, &signed_data[..43]);

        let builder = AnnounceBuilder {
            originator_iid: &identity1.iid,
            pubkey: identity2.pubkey.as_bytes(),
            seq_num: 200,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
            flags: 0,
        };
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        // This will fail at IID mismatch (identity2's pubkey hashes to different IID)
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
        // It should fail at IidMismatch before KeyChangeDetected
        assert_eq!(
            result.reject_reason,
            Some(AnnounceRejectReason::IidMismatch)
        );
    }

    #[test]
    fn key_pinning_tofu() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // No pinned key yet
        assert!(processor.pinned_pubkey_for(&identity.iid).is_none());

        // Accept announce - pins the key
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        processor.process(&announce, link_local(0xAA), 1000);

        // Key is now pinned
        let pinned = processor.pinned_pubkey_for(&identity.iid);
        assert!(pinned.is_some());
        assert_eq!(pinned.unwrap(), identity.pubkey.as_bytes());
    }

    #[test]
    fn reset_seen_allows_reaccept() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Accept first announce
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Same seq_num rejected
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);

        // Reset seen
        processor.reset_seen(&identity.iid);

        // Now same seq_num is accepted again
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(result.accepted);
    }

    #[test]
    fn gradient_table_updated() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let from_neighbor = link_local(0xAA);
        processor.process(&announce, from_neighbor, 1000);

        // Build expected destination address
        let mut expected_dst = [0u8; 16];
        expected_dst[..8].copy_from_slice(&ula_prefix());
        expected_dst[8..].copy_from_slice(&identity.iid);

        let entry = processor.gradient_table().lookup(&expected_dst, 1000);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.next_hop, from_neighbor);
        assert_eq!(entry.hop_count, 3);
        assert_eq!(entry.seq_num, 100);
        assert_eq!(entry.source, GradientSource::Announce);
    }

    #[test]
    fn hop_limit_prevents_relay() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Announce at max hops (15)
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 15, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        assert!(!result.should_relay); // At max hops, don't relay

        // Announce below max hops should relay
        let len = make_signed_announce(&identity, 101, 14, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(result.accepted);
        assert!(result.should_relay);
    }

    #[test]
    fn congestion_parsing() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // App data with congestion TLV: type=0x02, length=1, value=42
        let app_data = [0x02, 0x01, 42];
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &app_data, &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        assert_eq!(result.congestion, Some(42));
    }

    #[test]
    fn congestion_parsing_skips_unknown_types() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // App data with unknown TLV (type=0xFF, length=2, value=[0xAA, 0xBB])
        // followed by congestion TLV (type=0x02, length=1, value=77)
        let app_data = [0xFF, 0x02, 0xAA, 0xBB, 0x02, 0x01, 77];
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &app_data, &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
        // Parser should skip the unknown type and find congestion
        assert_eq!(result.congestion, Some(77));
    }

    #[test]
    fn lru_eviction() {
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());
        processor.max_entries = 3; // Small capacity for testing

        // Fill with 3 originators
        let mut buf = [0u8; 256];
        for i in 1..=3 {
            let identity = make_identity(i);
            let len = make_signed_announce(&identity, 100, 3, 0, &[], &mut buf);
            let announce = Announce::from_bytes(&buf[..len]).unwrap();
            processor.process(&announce, link_local(0xAA), 1000 + i as u32);
        }
        assert_eq!(processor.known_originators().len(), 3);

        // Add a 4th - should evict the oldest (identity 1)
        let identity4 = make_identity(4);
        let len = make_signed_announce(&identity4, 100, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        processor.process(&announce, link_local(0xAA), 5000);

        assert_eq!(processor.known_originators().len(), 3);
        let identity1 = make_identity(1);
        assert!(!processor.known_originators().contains(&identity1.iid));
        assert!(processor.known_originators().contains(&identity4.iid));
    }

    #[test]
    fn seqnum_wraparound_accepted() {
        let identity = make_identity(0x01);
        let gradient_table = GradientTable::new(64);
        let mut processor = AnnounceProcessor::new(gradient_table, ula_prefix());

        // Start near max seq_num
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 65534, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);

        // Wrapped seq_num (0) is newer than 65534
        let len = make_signed_announce(&identity, 0, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(result.accepted);

        // And 1 is newer than 0
        let len = make_signed_announce(&identity, 1, 3, 0, &[], &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();
        let result = processor.process(&announce, link_local(0xAA), 3000);
        assert!(result.accepted);
    }
}
