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

pub const MAX_TRACKED_ORIGINATORS: usize = 64;
const SEQ_HALF: u16 = 1 << 15;

#[inline]
pub fn seq_gt(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < SEQ_HALF
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnounceRejectReason {
    InvalidSignature,
    IidMismatch,
    StaleSeqNum,
    HopLimitExceeded,
    Malformed,
    KeyChangeDetected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceResult {
    pub accepted: bool,
    pub should_relay: bool,
    pub reject_reason: Option<AnnounceRejectReason>,
    pub peer: Option<PeerIdentity>,
    pub congestion: Option<u8>,
    pub evicted_iid: Option<[u8; 8]>,
}

impl AnnounceResult {
    fn rejected(reason: AnnounceRejectReason) -> Self {
        Self {
            accepted: false,
            should_relay: false,
            reject_reason: Some(reason),
            peer: None,
            congestion: None,
            evicted_iid: None,
        }
    }

    fn accepted(
        should_relay: bool,
        peer: PeerIdentity,
        congestion: Option<u8>,
        evicted_iid: Option<[u8; 8]>,
    ) -> Self {
        Self {
            accepted: true,
            should_relay,
            reject_reason: None,
            peer: Some(peer),
            congestion,
            evicted_iid,
        }
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct SeenEntry {
    seq_num: u16,
    last_access: u64,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct PinnedKeyEntry {
    pubkey: [u8; 32],
    last_access: u64,
}

#[cfg(feature = "std")]
#[derive(Clone)]
pub struct AnnounceProcessor {
    gradient_table: GradientTable,
    prefix: [u8; 8],
    seen: HashMap<[u8; 8], SeenEntry>,
    pinned_keys: HashMap<[u8; 8], PinnedKeyEntry>,
    access_counter: u64,
    max_entries: usize,
}

#[cfg(feature = "std")]
impl AnnounceProcessor {
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
        let pubkey = PublicKey::new(*announce.pubkey);
        let expected_iid = iid_from_pubkey(&pubkey);
        if *announce.originator_iid != expected_iid {
            return AnnounceResult::rejected(AnnounceRejectReason::IidMismatch);
        }

        let mut signed_buf = [0u8; 256];
        let signed_len = announce.write_signed_data(&mut signed_buf).unwrap_or(0);
        if signed_len == 0 {
            return AnnounceResult::rejected(AnnounceRejectReason::Malformed);
        }
        if !schnorr::verify(&pubkey, &signed_buf[..signed_len], announce.signature) {
            return AnnounceResult::rejected(AnnounceRejectReason::InvalidSignature);
        }

        let iid = *announce.originator_iid;

        if let Some(entry) = self.pinned_keys.get(&iid) {
            if entry.pubkey != *announce.pubkey {
                return AnnounceResult::rejected(AnnounceRejectReason::KeyChangeDetected);
            }
        }

        if let Some(entry) = self.seen.get(&iid) {
            if !seq_gt(announce.seq_num, entry.seq_num) {
                return AnnounceResult::rejected(AnnounceRejectReason::StaleSeqNum);
            }
        }

        self.access_counter += 1;
        let access = self.access_counter;

        let mut destination = [0u8; 16];
        destination[..8].copy_from_slice(&self.prefix);
        destination[8..].copy_from_slice(&iid);

        let coords = GeoCoords::from_app_data(announce.app_data);

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

        self.pinned_keys.insert(
            iid,
            PinnedKeyEntry {
                pubkey: *announce.pubkey,
                last_access: access,
            },
        );
        let evicted_iid = self.evict_pinned_if_needed();

        self.seen.insert(
            iid,
            SeenEntry {
                seq_num: announce.seq_num,
                last_access: access,
            },
        );
        self.evict_seen_if_needed();

        let should_relay = announce.should_relay();

        let peer = PeerIdentity::from_pubkey(pubkey);
        AnnounceResult::accepted(should_relay, peer, congestion, evicted_iid)
    }

    pub fn reset_seen(&mut self, iid: &[u8; 8]) {
        self.seen.remove(iid);
    }

    pub fn unpin(&mut self, iid: &[u8; 8]) {
        self.pinned_keys.remove(iid);
    }

    pub fn pinned_pubkey_for(&self, iid: &[u8; 8]) -> Option<PublicKey> {
        self.pinned_keys
            .get(iid)
            .map(|entry| PublicKey::new(entry.pubkey))
    }

    #[cfg(test)]
    pub(crate) fn pin_for_test(&mut self, pubkey: PublicKey) {
        let iid = iid_from_pubkey(&pubkey);
        self.pinned_keys.insert(
            iid,
            PinnedKeyEntry {
                pubkey: *pubkey.as_bytes(),
                last_access: 0,
            },
        );
    }

    pub fn known_originators(&self) -> Vec<[u8; 8]> {
        self.seen.keys().copied().collect()
    }

    pub fn build_relay_hop_count(&self, announce: &Announce<'_>) -> Option<u8> {
        if announce.should_relay() {
            Some(announce.hop_count + 1)
        } else {
            None
        }
    }

    pub fn gradient_table(&self) -> &GradientTable {
        &self.gradient_table
    }

    pub fn gradient_table_mut(&mut self) -> &mut GradientTable {
        &mut self.gradient_table
    }

    fn evict_pinned_if_needed(&mut self) -> Option<[u8; 8]> {
        let mut evicted = None;
        while self.pinned_keys.len() > self.max_entries {
            let oldest_iid = self
                .pinned_keys
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(iid) = oldest_iid {
                self.pinned_keys.remove(&iid);
                evicted = Some(iid);
            }
        }
        evicted
    }

    fn evict_seen_if_needed(&mut self) {
        while self.seen.len() > self.max_entries {
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
    for i in 0..app_data.len().saturating_sub(1) {
        if app_data[i] == CONGESTION_TLV {
            return Some(app_data[i + 1]);
        }
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

    fn make_signed_announce(
        identity: &Identity,
        seq_num: u16,
        hop_count: u8,
        rx_channel: u8,
        app_data: &[u8],
        buf: &mut [u8],
    ) -> usize {
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

        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num,
            hop_count,
            rx_channel,
            signature: &sig,
            app_data,
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

        let wrong_iid = [0xAA; 8];
        let mut signed_data = [0u8; 43];
        signed_data[..8].copy_from_slice(&identity.iid);
        signed_data[8..40].copy_from_slice(identity.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&100u16.to_be_bytes());
        signed_data[42] = 0;
        let sig = sign(&identity.privkey, &identity.pubkey, &signed_data[..43]);

        let builder = AnnounceBuilder {
            originator_iid: &wrong_iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
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

        let bad_sig = [0xFF; 48];
        let builder = AnnounceBuilder {
            originator_iid: &identity.iid,
            pubkey: identity.pubkey.as_bytes(),
            seq_num: 100,
            hop_count: 3,
            rx_channel: 0,
            signature: &bad_sig,
            app_data: &[],
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

        let mut signed_data = [0u8; 43];
        signed_data[..8].copy_from_slice(&identity1.iid);
        signed_data[8..40].copy_from_slice(identity2.pubkey.as_bytes());
        signed_data[40..42].copy_from_slice(&200u16.to_be_bytes());
        signed_data[42] = 0;
        let sig = sign(&identity2.privkey, &identity2.pubkey, &signed_data[..43]);

        let builder = AnnounceBuilder {
            originator_iid: &identity1.iid,
            pubkey: identity2.pubkey.as_bytes(),
            seq_num: 200,
            hop_count: 3,
            rx_channel: 0,
            signature: &sig,
            app_data: &[],
        };
        let len = builder.write_to(&mut buf).unwrap();
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 2000);
        assert!(!result.accepted);
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
        assert_eq!(pinned.unwrap(), identity.pubkey);
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

        let app_data = [0x02, 42];
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

        let app_data = [0xFF, 0xAA, 0xBB, 0x02, 77];
        let mut buf = [0u8; 256];
        let len = make_signed_announce(&identity, 100, 3, 0, &app_data, &mut buf);
        let announce = Announce::from_bytes(&buf[..len]).unwrap();

        let result = processor.process(&announce, link_local(0xAA), 1000);
        assert!(result.accepted);
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
