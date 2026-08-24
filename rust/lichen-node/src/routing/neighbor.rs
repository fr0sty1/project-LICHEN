//! Neighbor tracking and link quality management.

#[cfg(feature = "std")]
use lichen_rpl::trickle::TrickleTimer;

/// Maximum neighbors tracked.
pub const MAX_NEIGHBORS: usize = 16;

/// Link quality estimate (ETX as f32: 1.0 = perfect link).
pub type LinkEtx = f32;

/// Geographic coordinates (latitude, longitude) in decimal degrees.
pub type GeoCoords = (f64, f64);

/// Liveness policy for neighbor pruning.
pub trait TrickleSafeLivenessPolicy {
    fn is_alive(&self, last_seen: u64, now: u64, timeout: u64) -> bool {
        now.saturating_sub(last_seen) <= timeout
    }
}

impl TrickleSafeLivenessPolicy for () {}

/// Trickle-aware neighbor liveness policy.
///
/// Placeholder - implementation needed.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct TrickleAwareNeighborLiveness;

#[cfg(feature = "std")]
impl TrickleSafeLivenessPolicy for TrickleAwareNeighborLiveness {
    fn is_alive(&self, last_seen: u64, now: u64, timeout: u64) -> bool {
        now.saturating_sub(last_seen) <= timeout
    }
}

/// Neighbor entry with link quality tracking and optional coordinates.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub addr: [u8; 16],
    pub etx: LinkEtx,
    /// Last observation on the caller's monotonic millisecond timeline.
    pub last_seen_ms: u64,
    pub rssi: i8,
    /// Geographic coordinates from announce app_data (spec 9.7).
    /// None if neighbor hasn't advertised coords.
    pub coords: Option<GeoCoords>,
}

/// Neighbor table for link quality tracking.
#[derive(Clone, Debug)]
pub struct NeighborTable {
    entries: [Option<Neighbor>; MAX_NEIGHBORS],
    last_now_ms: u64,
}

impl NeighborTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_NEIGHBORS],
            last_now_ms: 0,
        }
    }

    /// Update or insert a neighbor. Returns the slot index.
    ///
    /// `now_ms` must use one nondecreasing monotonic `u64` timeline.
    pub fn update(&mut self, addr: &[u8; 16], etx: LinkEtx, rssi: i8, now_ms: u64) -> usize {
        self.update_with_coords(addr, etx, rssi, now_ms, None)
    }

    /// Update or insert a neighbor with optional coordinates.
    pub fn update_with_coords(
        &mut self,
        addr: &[u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
        coords: Option<GeoCoords>,
    ) -> usize {
        self.update_with_coords_and_eviction(addr, etx, rssi, now_ms, coords, None)
            .0
    }

    pub(crate) fn update_with_coords_and_eviction(
        &mut self,
        addr: &[u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
        coords: Option<GeoCoords>,
        protected: Option<[u8; 16]>,
    ) -> (usize, Option<[u8; 16]>) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        // Find existing or empty slot
        let mut empty_slot = None;
        for (i, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(n) if n.addr == *addr => {
                    n.etx = etx;
                    n.rssi = rssi;
                    n.last_seen_ms = now_ms;
                    if coords.is_some() {
                        n.coords = coords;
                    }
                    return (i, None);
                }
                None if empty_slot.is_none() => empty_slot = Some(i),
                _ => {}
            }
        }
        // Insert new
        if let Some(i) = empty_slot {
            self.entries[i] = Some(Neighbor {
                addr: *addr,
                etx,
                rssi,
                last_seen_ms: now_ms,
                coords,
            });
            return (i, None);
        }
        // Evict oldest neighbor, but never evict the protected address (e.g., preferred parent)
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|n| (i, n)))
            .filter(|(_, n)| protected != Some(n.addr))
            .max_by_key(|(i, n)| (now_ms.wrapping_sub(n.last_seen_ms), MAX_NEIGHBORS - *i))
            .map(|(i, _)| i);
        let Some(oldest) = oldest else {
            // All slots are protected or empty; cannot evict
            return (0, None);
        };
        let evicted = self.entries[oldest].as_ref().map(|neighbor| neighbor.addr);
        self.entries[oldest] = Some(Neighbor {
            addr: *addr,
            etx,
            rssi,
            last_seen_ms: now_ms,
            coords,
        });
        (oldest, evicted)
    }

    /// Get neighbor ETX, or None if unknown.
    pub fn get_etx(&self, addr: &[u8; 16]) -> Option<LinkEtx> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .map(|n| n.etx)
    }

    /// Remove an exact neighbor, returning whether it was present.
    pub fn remove(&mut self, addr: &[u8; 16]) -> bool {
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|neighbor| neighbor.addr == *addr)
            {
                *entry = None;
                return true;
            }
        }
        false
    }

    /// Remove every address alias for one authenticated signer IID.
    #[allow(dead_code)]
    pub(crate) fn remove_with_iid(&mut self, signer_iid: &[u8; 8]) -> bool {
        let mut removed = false;
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|neighbor| neighbor.addr[8..] == *signer_iid)
            {
                *entry = None;
                removed = true;
            }
        }
        removed
    }

    /// Get neighbor coordinates, or None if unknown or not advertised.
    pub fn get_coords(&self, addr: &[u8; 16]) -> Option<GeoCoords> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .and_then(|n| n.coords)
    }

    /// Update coordinates for an existing neighbor. Does nothing if neighbor not found.
    pub fn set_coords(&mut self, addr: &[u8; 16], coords: GeoCoords) {
        for n in self.entries.iter_mut().flatten() {
            if n.addr == *addr {
                n.coords = Some(coords);
                return;
            }
        }
    }

    #[cfg(feature = "std")]
    pub fn prune(&mut self, now_ms: u64, max_age_ms: u64) {
        let policy = TrickleAwareNeighborLiveness;
        self.prune_with_removed(&policy, now_ms, max_age_ms, 0, |_| {});
    }

    #[cfg(feature = "std")]
    pub(crate) fn prune_with_removed<P: TrickleSafeLivenessPolicy>(
        &mut self,
        policy: &P,
        now_ms: u64,
        max_age_ms: u64,
        _heard_consistent: u32,
        mut removed: impl FnMut([u8; 16]),
    ) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        for slot in self.entries.iter_mut() {
            let is_stale = slot.as_ref().is_some_and(|neighbor| {
                !policy.is_alive(neighbor.last_seen_ms, now_ms, max_age_ms)
            });
            if is_stale {
                let neighbor = slot.take().expect("stale slot contains a neighbor");
                removed(neighbor.addr);
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.iter().flatten()
    }

    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_likely_alive<P: TrickleSafeLivenessPolicy>(
        &self,
        policy: &P,
        addr: &[u8; 16],
        now_ms: u64,
        max_age_ms: u64,
        _heard_consistent: u32,
    ) -> bool {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .is_some_and(|n| policy.is_alive(n.last_seen_ms, now_ms, max_age_ms))
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl NeighborTable {
    /// Trickle-aware liveness policy per RFC 6206 and RPL neighbor timeout.
    ///
    /// Factors in TrickleTimer::counter (from heard_consistent) to avoid
    /// premature eviction of suppressed neighbors in dense networks (when
    /// counter >= k, transmissions suppressed). Scales effective timeout
    /// up to 3x under full suppression. Design doc as specified in
    /// project-LICHEN-2auf.44.11.7.1.1.
    pub fn is_trickle_aware_live(
        &self,
        addr: &[u8; 16],
        trickle: &TrickleTimer,
        now_ms: u64,
        max_age_ms: u64,
    ) -> bool {
        let Some(neighbor) = self.entries.iter().flatten().find(|n| n.addr == *addr) else {
            return false;
        };
        let age = now_ms.saturating_sub(neighbor.last_seen_ms);
        if age <= max_age_ms {
            return true;
        }
        let k = u64::from(trickle.k);
        if k == 0 {
            return false;
        }
        let c = u64::from(trickle.counter.min(trickle.k));
        let scale = 1 + (2 * c / k);
        age <= max_age_ms * scale
    }

    pub fn prune_trickle_safe(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
        trickle: &TrickleTimer,
        mut removed: impl FnMut([u8; 16]),
    ) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        // Inline the trickle-aware liveness check to avoid borrow conflict
        let k = u64::from(trickle.k);
        let c = u64::from(trickle.counter.min(trickle.k));
        for slot in self.entries.iter_mut() {
            let is_stale = slot.as_ref().is_some_and(|neighbor| {
                let age = now_ms.saturating_sub(neighbor.last_seen_ms);
                if age <= max_age_ms {
                    return false;
                }
                if k == 0 {
                    return true;
                }
                let scale = 1 + (2 * c / k);
                age > max_age_ms * scale
            });
            if is_stale {
                let neighbor = slot.take().expect("stale slot contains a neighbor");
                removed(neighbor.addr);
            }
        }
    }
}
