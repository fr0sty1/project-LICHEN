//! Unified gradient (routing) table (spec section 11).
//!
//! A single table holds next-hop gradients toward destinations, populated by every
//! routing method: Announce (section 9), LOADng RREP (section 10), RPL, and passive
//! learning from forwarded data (section 11.2). Entries carry a source priority so
//! explicitly-advertised routes win over opportunistic ones.

use core::cmp::Ordering;

/// Maximum gradient table entries (spec 11).
pub const MAX_GRADIENT_ENTRIES: usize = 64;

/// Gradient timeout for announce/rrep entries in milliseconds (spec 9.4: 600s).
pub const GRADIENT_TIMEOUT_MS: u32 = 600_000;

/// Data gradient timeout in milliseconds (spec 11.2: 60s, shorter since opportunistic).
pub const DATA_GRADIENT_TIMEOUT_MS: u32 = 60_000;

/// Sequence number half-space for RFC 1982 comparison.
const SEQ_HALF: u16 = 1 << 15;

/// How a gradient entry was learned (spec 11.1/11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradientSource {
    /// From announce message (spec 9).
    Announce,
    /// From LOADng RREP (spec 10).
    Rrep,
    /// From RPL DAO/routing table.
    Rpl,
    /// Passively learned from forwarded data (spec 11.2).
    Data,
}

impl GradientSource {
    /// Priority for route replacement. Higher wins.
    /// Explicitly-advertised routes outrank opportunistic data.
    #[inline]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Announce | Self::Rrep | Self::Rpl => 1,
        }
    }
}

/// Geographic coordinates (lat, lon) in degrees (spec 9.7).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoCoords {
    pub lat: f32,
    pub lon: f32,
}

impl GeoCoords {
    pub fn from_app_data(data: &[u8]) -> Option<Self> {
        for i in 0..data.len().saturating_sub(8) {
            if data[i] == 0x01 {
                let lat_e7 =
                    i32::from_be_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                let lon_e7 =
                    i32::from_be_bytes([data[i + 5], data[i + 6], data[i + 7], data[i + 8]]);
                return Some(Self {
                    lat: lat_e7 as f32 / 1e7,
                    lon: lon_e7 as f32 / 1e7,
                });
            }
        }
        None
    }
}

/// A next-hop gradient toward a destination (spec 11.1).
#[derive(Debug, Clone)]
pub struct GradientEntry {
    /// Destination IID or full IPv6 address (last 8 bytes for IID).
    pub destination: [u8; 16],
    /// Link-local address of next-hop neighbor.
    pub next_hop: [u8; 16],
    /// Distance in hops.
    pub hop_count: u8,
    /// Sequence number for freshness comparison (RFC 1982).
    pub seq_num: u16,
    /// How this entry was learned.
    pub source: GradientSource,
    /// Expiry timestamp in milliseconds.
    pub expires_ms: u32,
    /// Geographic coordinates from announce app_data (spec 9.7).
    pub coords: Option<GeoCoords>,
}

impl GradientEntry {
    /// Compare sequence numbers per RFC 1982 (serial number arithmetic).
    /// Returns Ordering::Greater if `a` is newer than `b`.
    fn seq_cmp(a: u16, b: u16) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        let diff = a.wrapping_sub(b);
        if diff < SEQ_HALF {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    /// Rank for replacement comparison (higher is better).
    /// Priority → seq_num (RFC 1982) → fewer hops.
    fn rank(&self) -> (u8, u16, i16) {
        // seq_num comparison via RFC 1982 handled separately
        (
            self.source.priority(),
            self.seq_num,
            -(self.hop_count as i16),
        )
    }

    /// Returns true if `self` should replace `other`.
    pub fn should_replace(&self, other: &Self) -> bool {
        let (s_pri, s_seq, s_hops) = self.rank();
        let (o_pri, o_seq, o_hops) = other.rank();

        if s_pri != o_pri {
            return s_pri > o_pri;
        }
        match Self::seq_cmp(s_seq, o_seq) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => s_hops > o_hops, // fewer hops = higher value
        }
    }
}

/// Unified gradient table (spec 11).
///
/// Bounded, LRU-evicting table of gradient entries populated by all routing
/// methods (announce, LOADng, RPL, passive learning).
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct GradientTable {
    entries: std::vec::Vec<GradientEntry>,
    max_entries: usize,
}

#[cfg(feature = "std")]
impl GradientTable {
    /// Create a new gradient table with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::vec::Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Lookup gradient for destination. Returns None if absent or expired.
    pub fn lookup(&self, destination: &[u8; 16], now_ms: u32) -> Option<&GradientEntry> {
        self.entries
            .iter()
            .find(|e| e.destination == *destination && !is_expired(e.expires_ms, now_ms))
    }

    /// Lookup gradient for destination by IID (last 8 bytes).
    pub fn lookup_by_iid(&self, iid: &[u8; 8], now_ms: u32) -> Option<&GradientEntry> {
        self.entries
            .iter()
            .find(|e| &e.destination[8..] == iid && !is_expired(e.expires_ms, now_ms))
    }

    /// Insert or update a gradient entry.
    /// Returns true if the table was modified.
    pub fn update(&mut self, entry: GradientEntry, now_ms: u32) -> bool {
        // Find existing entry for this destination
        if let Some(idx) = self
            .entries
            .iter()
            .position(|e| e.destination == entry.destination)
        {
            let existing = &self.entries[idx];
            let expired = is_expired(existing.expires_ms, now_ms);

            if expired || entry.should_replace(existing) {
                self.entries[idx] = entry;
                // Move to end for LRU (most recently used)
                let last = self.entries.len() - 1;
                self.entries.swap(idx, last);
                return true;
            }
            return false;
        }

        // New entry - evict LRU if full
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0); // Remove oldest (LRU)
        }
        self.entries.push(entry);
        true
    }

    /// Remove gradient for destination.
    pub fn remove(&mut self, destination: &[u8; 16]) {
        self.entries.retain(|e| e.destination != *destination);
    }

    /// Remove all gradients routing through a next-hop.
    /// Returns the destinations that were removed.
    pub fn remove_via(&mut self, next_hop: &[u8; 16]) -> std::vec::Vec<[u8; 16]> {
        let mut removed = std::vec::Vec::new();
        self.entries.retain(|e| {
            if e.next_hop == *next_hop {
                removed.push(e.destination);
                false
            } else {
                true
            }
        });
        removed
    }

    /// Drop expired entries. Returns count removed.
    pub fn expire_old(&mut self, now_ms: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !is_expired(e.expires_ms, now_ms));
        before - self.entries.len()
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &GradientEntry> {
        self.entries.iter()
    }
}

#[cfg(feature = "std")]
impl Default for GradientTable {
    fn default() -> Self {
        Self::new(MAX_GRADIENT_ENTRIES)
    }
}

/// Check if a timestamp is expired (handles u32 wraparound).
#[inline]
#[allow(dead_code)]
fn is_expired(expires_ms: u32, now_ms: u32) -> bool {
    let diff = now_ms.wrapping_sub(expires_ms);
    diff != 0 && diff < 0x8000_0000
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn link_local(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = iid;
        addr
    }

    fn make_entry(dst: u8, next: u8, hops: u8, seq: u16, source: GradientSource) -> GradientEntry {
        GradientEntry {
            destination: link_local(dst),
            next_hop: link_local(next),
            hop_count: hops,
            seq_num: seq,
            source,
            expires_ms: 1000 + GRADIENT_TIMEOUT_MS,
            coords: None,
        }
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let table = GradientTable::new(10);
        assert!(table.lookup(&link_local(1), 1000).is_none());
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = GradientTable::new(10);
        let entry = make_entry(1, 2, 3, 100, GradientSource::Announce);
        assert!(table.update(entry, 1000));
        assert_eq!(table.len(), 1);

        let found = table.lookup(&link_local(1), 1000).unwrap();
        assert_eq!(found.hop_count, 3);
        assert_eq!(found.seq_num, 100);
    }

    #[test]
    fn higher_priority_replaces_lower() {
        let mut table = GradientTable::new(10);

        // Insert data-source entry
        let data_entry = make_entry(1, 2, 3, 100, GradientSource::Data);
        table.update(data_entry, 1000);

        // Announce-source entry should replace it
        let ann_entry = make_entry(1, 3, 4, 50, GradientSource::Announce);
        assert!(table.update(ann_entry, 1000));

        let found = table.lookup(&link_local(1), 1000).unwrap();
        assert_eq!(found.next_hop, link_local(3));
        assert_eq!(found.source, GradientSource::Announce);
    }

    #[test]
    fn newer_seq_replaces_older() {
        let mut table = GradientTable::new(10);

        let entry1 = make_entry(1, 2, 3, 100, GradientSource::Announce);
        table.update(entry1, 1000);

        // Higher seq_num should replace
        let entry2 = make_entry(1, 3, 3, 150, GradientSource::Announce);
        assert!(table.update(entry2, 1000));

        let found = table.lookup(&link_local(1), 1000).unwrap();
        assert_eq!(found.next_hop, link_local(3));
        assert_eq!(found.seq_num, 150);
    }

    #[test]
    fn seq_num_wraparound() {
        let mut table = GradientTable::new(10);

        // Start near max seq_num
        let entry1 = make_entry(1, 2, 3, 65534, GradientSource::Announce);
        table.update(entry1, 1000);

        // Wrapped seq_num (0) is newer than 65534
        let entry2 = make_entry(1, 3, 3, 0, GradientSource::Announce);
        assert!(table.update(entry2, 1000));

        let found = table.lookup(&link_local(1), 1000).unwrap();
        assert_eq!(found.seq_num, 0);
    }

    #[test]
    fn fewer_hops_replaces_at_same_priority_and_seq() {
        let mut table = GradientTable::new(10);

        let entry1 = make_entry(1, 2, 5, 100, GradientSource::Announce);
        table.update(entry1, 1000);

        // Same priority and seq, but fewer hops
        let entry2 = make_entry(1, 3, 2, 100, GradientSource::Announce);
        assert!(table.update(entry2, 1000));

        let found = table.lookup(&link_local(1), 1000).unwrap();
        assert_eq!(found.hop_count, 2);
    }

    #[test]
    fn lru_eviction() {
        let mut table = GradientTable::new(3);

        table.update(make_entry(1, 10, 1, 1, GradientSource::Announce), 1000);
        table.update(make_entry(2, 10, 1, 1, GradientSource::Announce), 1000);
        table.update(make_entry(3, 10, 1, 1, GradientSource::Announce), 1000);
        assert_eq!(table.len(), 3);

        // Adding 4th should evict LRU (destination 1)
        table.update(make_entry(4, 10, 1, 1, GradientSource::Announce), 1000);
        assert_eq!(table.len(), 3);
        assert!(table.lookup(&link_local(1), 1000).is_none());
        assert!(table.lookup(&link_local(4), 1000).is_some());
    }

    #[test]
    fn expire_old_removes_stale() {
        let mut table = GradientTable::new(10);

        let mut entry = make_entry(1, 2, 3, 100, GradientSource::Announce);
        entry.expires_ms = 5000;
        table.update(entry, 1000);

        // Not expired yet
        assert!(table.lookup(&link_local(1), 4000).is_some());

        // Expired
        assert!(table.lookup(&link_local(1), 6000).is_none());

        // expire_old removes it
        let removed = table.expire_old(6000);
        assert_eq!(removed, 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn remove_via_clears_next_hop() {
        let mut table = GradientTable::new(10);

        table.update(make_entry(1, 10, 1, 1, GradientSource::Announce), 1000);
        table.update(make_entry(2, 10, 1, 1, GradientSource::Announce), 1000);
        table.update(make_entry(3, 20, 1, 1, GradientSource::Announce), 1000);

        let removed = table.remove_via(&link_local(10));
        assert_eq!(removed.len(), 2);
        assert_eq!(table.len(), 1);
        assert!(table.lookup(&link_local(3), 1000).is_some());
    }

    #[test]
    fn geo_coords_parsing() {
        let lat_e7: i32 = 450_000_000;
        let lon_e7: i32 = -1_220_000_000;
        let mut data = [0u8; 9];
        data[0] = 0x01;
        data[1..5].copy_from_slice(&lat_e7.to_be_bytes());
        data[5..9].copy_from_slice(&lon_e7.to_be_bytes());

        let coords = GeoCoords::from_app_data(&data).unwrap();
        assert!((coords.lat - 45.0).abs() < 0.001);
        assert!((coords.lon - (-122.0)).abs() < 0.001);
    }

    #[test]
    fn geo_coords_parsing_skips_unknown_types() {
        let lat_e7: i32 = 450_000_000;
        let lon_e7: i32 = -1_220_000_000;
        let mut data = [0u8; 13];
        data[0] = 0xFF;
        data[1..4].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        data[4] = 0x01;
        data[5..9].copy_from_slice(&lat_e7.to_be_bytes());
        data[9..13].copy_from_slice(&lon_e7.to_be_bytes());

        let coords = GeoCoords::from_app_data(&data).unwrap();
        assert!((coords.lat - 45.0).abs() < 0.001);
        assert!((coords.lon - (-122.0)).abs() < 0.001);
    }
}
