//! Routing table.
//!
//! Root-side routing table mapping targets to hop paths.

#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use crate::srh::MAX_ROUTE_HOPS;

/// Maximum installed routes. New state is rejected when this limit is reached.
pub const MAX_ROUTES: usize = 256;

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteEntryState {
    Fresh,
    Stale,
    Expired,
}

#[cfg(feature = "std")]
impl RouteEntryState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Fresh, Self::Fresh)
                | (Self::Fresh, Self::Stale)
                | (Self::Fresh, Self::Expired)
                | (Self::Stale, Self::Fresh)
                | (Self::Stale, Self::Stale)
                | (Self::Stale, Self::Expired)
                | (Self::Expired, Self::Expired)
        )
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRouteEntryTransition {
    pub from: RouteEntryState,
    pub to: RouteEntryState,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub path: Vec<[u8; 16]>,
    pub state: RouteEntryState,
}

/// Canonical IPv6 route prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteTarget {
    prefix: [u8; 16],
    prefix_len: u8,
}

impl RouteTarget {
    /// Construct a prefix key, clearing every bit after `prefix_len`.
    ///
    /// This representation is allocation-free and available in `no_std`
    /// builds. Prefix lengths greater than 128 fail closed.
    pub fn new(mut prefix: [u8; 16], prefix_len: u8) -> Option<Self> {
        if prefix_len > 128 {
            return None;
        }
        let whole_bytes = usize::from(prefix_len / 8);
        let remaining_bits = prefix_len % 8;
        let used_bytes = whole_bytes + usize::from(remaining_bits != 0);
        if remaining_bits != 0 {
            prefix[whole_bytes] &= u8::MAX << (8 - remaining_bits);
        }
        prefix[used_bytes..].fill(0);
        Some(Self { prefix, prefix_len })
    }

    pub const fn host(address: [u8; 16]) -> Self {
        Self {
            prefix: address,
            prefix_len: 128,
        }
    }

    pub const fn prefix(&self) -> &[u8; 16] {
        &self.prefix
    }

    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, address: &[u8; 16]) -> bool {
        let whole_bytes = usize::from(self.prefix_len / 8);
        if self.prefix[..whole_bytes] != address[..whole_bytes] {
            return false;
        }
        let remaining_bits = self.prefix_len % 8;
        remaining_bits == 0
            || (self.prefix[whole_bytes] ^ address[whole_bytes]) & (u8::MAX << (8 - remaining_bits))
                == 0
    }
}

#[cfg(feature = "std")]
impl RouteEntry {
    pub fn fresh(path: &[[u8; 16]]) -> Self {
        Self {
            path: path.to_vec(),
            state: RouteEntryState::Fresh,
        }
    }

    fn transition_to(&mut self, next: RouteEntryState) -> Result<(), InvalidRouteEntryTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidRouteEntryTransition {
                from: self.state,
                to: next,
            })
        }
    }

    pub fn mark_stale(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Stale)
    }

    pub fn mark_expired(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Expired)
    }

    pub fn refresh(&mut self, path: &[[u8; 16]]) -> Result<(), InvalidRouteEntryTransition> {
        if self.state == RouteEntryState::Expired {
            return Err(InvalidRouteEntryTransition {
                from: self.state,
                to: RouteEntryState::Fresh,
            });
        }
        self.path = path.to_vec();
        self.transition_to(RouteEntryState::Fresh)
    }

    pub fn is_usable(&self) -> bool {
        self.state != RouteEntryState::Expired
    }
}

/// Root-side map from route target to an ordered root-to-egress hop list.
///
/// Host routes use `/128` targets and keep the existing `[h1, ..., target]`
/// path shape. Prefix routes store a path to their egress, never to the
/// canonical prefix address.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    pub(crate) routes: HashMap<RouteTarget, RouteEntry>,
    pub(crate) prefix_route_count: usize,
    pub(crate) rpl_managed_hosts: HashSet<[u8; 16]>,
    pub(crate) rpl_managed_prefixes: HashMap<RouteTarget, [u8; 16]>,
    pub(crate) unavailable_managed_prefixes: HashSet<RouteTarget>,
}

#[cfg(feature = "std")]
impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a route, returning `false` if a new entry would exceed capacity.
    pub fn add_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) -> bool {
        self.add_target_route(RouteTarget::host(target), path)
    }

    /// Add a non-host prefix route to its egress path.
    pub fn add_prefix_route(
        &mut self,
        target: RouteTarget,
        egress: [u8; 16],
        path: &[[u8; 16]],
    ) -> bool {
        if target.prefix_len == 128
            || path.last() != Some(&egress)
            || path.iter().any(|hop| hop == target.prefix())
        {
            return false;
        }
        let was_managed = self.rpl_managed_prefixes.get(&target) == Some(&egress);
        let is_managed = was_managed || self.rpl_managed_hosts.contains(&egress);
        if !self.add_target_route(target, path) {
            return false;
        }
        if is_managed {
            self.rpl_managed_prefixes.insert(target, egress);
        } else {
            self.rpl_managed_prefixes.remove(&target);
        }
        self.unavailable_managed_prefixes.remove(&target);
        true
    }

    fn add_target_route(&mut self, target: RouteTarget, path: &[[u8; 16]]) -> bool {
        if path.len() > MAX_ROUTE_HOPS {
            return false;
        }
        let is_new = !self.routes.contains_key(&target);
        if is_new && self.routes.len() == MAX_ROUTES {
            return false;
        }
        match self.routes.get_mut(&target) {
            Some(entry) if entry.state != RouteEntryState::Expired => {
                entry
                    .refresh(path)
                    .expect("fresh or stale route entry can refresh");
            }
            _ => {
                self.routes.insert(target, RouteEntry::fresh(path));
            }
        }
        if is_new && target.prefix_len < 128 {
            self.prefix_route_count += 1;
        }
        true
    }

    pub fn remove_route(&mut self, target: &[u8; 16]) {
        self.routes.remove(&RouteTarget::host(*target));
    }

    pub fn remove_prefix_route(&mut self, target: RouteTarget) {
        if target.prefix_len < 128 && self.routes.remove(&target).is_some() {
            self.prefix_route_count -= 1;
            self.rpl_managed_prefixes.remove(&target);
            self.unavailable_managed_prefixes.remove(&target);
        }
    }

    pub fn mark_stale(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes
            .get_mut(&RouteTarget::host(*target))
            .map(RouteEntry::mark_stale)
    }

    pub fn mark_expired(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes
            .get_mut(&RouteTarget::host(*target))
            .map(RouteEntry::mark_expired)
    }

    pub fn entry_state(&self, target: &[u8; 16]) -> Option<RouteEntryState> {
        self.routes
            .get(&RouteTarget::host(*target))
            .map(|entry| entry.state)
    }

    pub fn mark_prefix_expired(
        &mut self,
        target: RouteTarget,
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        (target.prefix_len < 128)
            .then(|| self.routes.get_mut(&target).map(RouteEntry::mark_expired))
            .flatten()
    }

    /// Return the longest-prefix path for `target`, or `None` if no route is known.
    pub fn lookup(&self, target: &[u8; 16]) -> Option<&[[u8; 16]]> {
        if self.prefix_route_count == 0 {
            return self
                .routes
                .get(&RouteTarget::host(*target))
                .filter(|entry| entry.is_usable())
                .map(|entry| entry.path.as_slice());
        }
        self.routes
            .iter()
            .filter(|(route_target, entry)| route_target.contains(target) && entry.is_usable())
            .max_by_key(|(route_target, _)| route_target.prefix_len)
            .map(|(_, entry)| entry.path.as_slice())
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}
