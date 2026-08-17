//! RPL Multi-Instance Coordination for Gateway Cooperation (GCP-5, RFC 6550 Section 5).
//!
//! This module provides the Rust implementation for multi-gateway DODAG
//! coordination as specified in spec/08-gateway-coordination.md GCP-5:
//!
//! - All cooperating gateways use the same RPLInstanceID
//! - Each gateway acts as DODAG root for that instance
//! - Nodes see a unified DODAG with multiple possible parents
//! - DAO messages propagate across backbone as needed for route aggregation
//!
//! The coordination model uses a federated approach where each gateway maintains
//! its own DODAG root but shares routing information with peer gateways over the
//! backbone network. This enables:
//!
//! 1. Load balancing across gateways
//! 2. Fault tolerance when a gateway fails
//! 3. Optimal path selection for nodes
//! 4. Seamless handoff between gateways
//!
//! # Test Vectors
//!
//! See `test/vectors/rpl_multi_instance.json` for canonical test vectors.

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::sync::Mutex;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::cmp::Ordering;

#[cfg(feature = "std")]
use crate::dodag::DodagState;
use crate::dodag::ROOT_RANK;
use crate::message::Dio;

/// Maximum RPLInstanceID value per RFC 6550.
pub const MAX_RPL_INSTANCE_ID: u8 = 255;

/// Default RPLInstanceID for LICHEN deployments.
pub const DEFAULT_RPL_INSTANCE_ID: u8 = 0;

/// Initial DODAG version (lollipop counter starts at 128).
pub const INITIAL_DODAG_VERSION: u8 = 128;

/// Maximum number of peer gateways to prevent memory exhaustion DoS.
/// SECURITY: Unbounded collections allow resource exhaustion attacks.
pub const MAX_PEERS: usize = 64;

/// Maximum number of root candidates per beacon window to prevent memory exhaustion DoS.
/// SECURITY: Unbounded collections allow resource exhaustion attacks.
pub const MAX_CANDIDATES: usize = 32;

/// Maximum number of peer gateways with received routes to prevent memory exhaustion DoS.
/// SECURITY: Unbounded collections allow resource exhaustion attacks.
pub const MAX_RECEIVED_ROUTE_PEERS: usize = 64;

/// Maximum number of pending propagation messages to prevent memory exhaustion DoS.
/// SECURITY: Unbounded collections allow resource exhaustion attacks.
pub const MAX_PENDING_PROPAGATIONS: usize = 128;

/// Maximum age of a DAO backbone message timestamp before it is considered stale.
/// SECURITY: Timestamps older than this threshold are rejected to prevent replay attacks.
pub const DAO_TIMESTAMP_FRESHNESS_SECONDS: f64 = 300.0;

/// Maximum number of route targets or transits in a single DAO backbone message.
/// SECURITY: Without this limit, a malicious peer can send millions of routes
/// in a single message to exhaust memory during route reconstruction.
pub const MAX_ROUTES_PER_MESSAGE: usize = 256;

/// Role of a gateway in the federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GatewayRole {
    /// Elected time master (lowest IID).
    Primary,
    /// Non-primary gateway in federation.
    Secondary,
    /// Not part of a federation (single gateway).
    Standalone,
}

impl GatewayRole {
    /// Returns the string representation of the role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Standalone => "standalone",
        }
    }
}

/// Information about a cooperating gateway.
///
/// Per GCP-4.1, gateway info includes IID, capabilities, slot map,
/// superframe time, and supported federation modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayInfo {
    /// Interface Identifier (last 8 bytes of link-local IPv6).
    pub iid: [u8; 16],
    /// Maximum slots per superframe.
    pub max_slots: u16,
    /// GPS time sync available.
    pub gps_sync: bool,
    /// Superframe duration in seconds.
    pub superframe_duration_s: u32,
    /// Number of routes learned by this gateway.
    pub routes_learned: u32,
}

impl GatewayInfo {
    /// Create a new gateway info.
    pub fn new(iid: [u8; 16]) -> Self {
        Self {
            iid,
            max_slots: 60,
            gps_sync: false,
            superframe_duration_s: 60,
            routes_learned: 0,
        }
    }

    /// Create gateway info with GPS sync capability.
    pub fn with_gps(mut self, has_gps: bool) -> Self {
        self.gps_sync = has_gps;
        self
    }

    /// Set the number of routes learned.
    pub fn with_routes_learned(mut self, count: u32) -> Self {
        self.routes_learned = count;
        self
    }
}

/// Error type for RPL multi-instance operations.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MultiInstanceError {
    /// RPLInstanceID out of valid range (0-255).
    InvalidInstanceId(i32),
    /// DIO RPLInstanceID doesn't match federation.
    InstanceIdMismatch { expected: u8, got: u8 },
    /// Peer gateway DIO has non-root rank.
    NonRootRank { expected: u16, got: u16 },
    /// Local gateway not configured.
    NoLocalGateway,
    /// DAO backbone message claims self as origin.
    /// SECURITY: A peer cannot claim our own IID as origin.
    SelfOrigin,
    /// DAO backbone message has stale timestamp.
    /// SECURITY: Reject old messages to prevent replay attacks.
    StaleTimestamp { message_time: f64, current_time: f64 },
    /// DAO backbone message origin does not match OSCORE-authenticated sender.
    /// SECURITY: The transport-authenticated identity must match the claimed origin.
    OriginAuthMismatch { claimed: [u8; 16], authenticated: [u8; 16] },
    /// DAO backbone message contains too many routes.
    /// SECURITY: Prevents memory exhaustion from malicious messages.
    TooManyRoutes { targets: usize, transit: usize, limit: usize },
}

impl core::fmt::Display for MultiInstanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInstanceId(id) => {
                write!(f, "RPLInstanceID must be 0-255, got {}", id)
            }
            Self::InstanceIdMismatch { expected, got } => {
                write!(
                    f,
                    "RPLInstanceID mismatch: expected {}, got {}",
                    expected, got
                )
            }
            Self::NonRootRank { expected, got } => {
                write!(
                    f,
                    "Peer gateway DIO must have root rank {}, got {}",
                    expected, got
                )
            }
            Self::NoLocalGateway => write!(f, "local_gateway must be set"),
            Self::SelfOrigin => write!(f, "DAO message claims self as origin"),
            Self::StaleTimestamp {
                message_time,
                current_time,
            } => {
                write!(
                    f,
                    "DAO timestamp stale: message_time={:.1}s, current_time={:.1}s",
                    message_time, current_time
                )
            }
            Self::OriginAuthMismatch { .. } => {
                write!(f, "DAO origin does not match OSCORE-authenticated sender")
            }
            Self::TooManyRoutes { targets, transit, limit } => {
                write!(
                    f,
                    "DAO message exceeds route limit: {} targets, {} transits (max {})",
                    targets, transit, limit
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MultiInstanceError {}

/// Result of DIO validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DioValidationResult {
    /// Whether the DIO is valid.
    pub is_valid: bool,
    /// Reason string (for diagnostics).
    pub reason: &'static str,
}

/// DAO message for backbone propagation between gateways.
///
/// Per GCP-5, DAO messages propagate across backbone as needed for
/// route aggregation. This carries the essential routing information.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq)]
pub struct DaoBackboneMessage {
    /// IID of originating gateway.
    pub origin_gateway: [u8; 16],
    /// RPL instance ID.
    pub rpl_instance_id: u8,
    /// DAO sequence number.
    pub dao_sequence: u8,
    /// Route targets.
    pub targets: Vec<DaoTarget>,
    /// Transit information.
    pub transit: Vec<DaoTransit>,
    /// Timestamp (monotonic).
    pub timestamp: f64,
}

/// A route target in a DAO backbone message.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaoTarget {
    /// Target prefix (IPv6 address).
    pub target: [u8; 16],
    /// Prefix length.
    pub prefix_length: u8,
}

/// Transit information in a DAO backbone message.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaoTransit {
    /// Path sequence number.
    pub path_sequence: u8,
    /// Path lifetime.
    pub path_lifetime: u8,
    /// Path control field.
    pub path_control: u8,
    /// Parent address (optional).
    pub parent: Option<[u8; 16]>,
}

/// Coordinates multiple DODAG roots in the same RPL instance.
///
/// Per GCP-5, all cooperating gateways use the same RPLInstanceID and each
/// acts as a DODAG root. This coordinator manages:
///
/// 1. Shared RPLInstanceID across all gateways
/// 2. DODAG version synchronization
/// 3. Gateway discovery and membership
/// 4. Time master election (lowest IID per GCP-6.1)
///
/// MUST requirements from GCP-5:
/// - All cooperating gateways use the same RPLInstanceID
/// - Each gateway acts as DODAG root for that instance
/// - Nodes see a unified DODAG with multiple possible parents
#[cfg(feature = "std")]
pub struct MultiRootCoordinator {
    /// RPL instance ID (0-255).
    rpl_instance_id: u8,
    /// Local gateway info.
    local_gateway: Option<GatewayInfo>,
    /// Known peer gateways.
    peers: Mutex<HashMap<[u8; 16], GatewayInfo>>,
    /// Current DODAG version (lollipop counter).
    dodag_version: Mutex<u8>,
}

#[cfg(feature = "std")]
impl MultiRootCoordinator {
    /// Create a new coordinator with the given RPL instance ID.
    ///
    /// # Errors
    ///
    /// Returns error if `rpl_instance_id` is not in range 0-255
    /// (which is impossible with u8, but kept for API consistency).
    pub fn new(rpl_instance_id: u8) -> Self {
        Self {
            rpl_instance_id,
            local_gateway: None,
            peers: Mutex::new(HashMap::new()),
            dodag_version: Mutex::new(INITIAL_DODAG_VERSION),
        }
    }

    /// Create a new coordinator with default RPL instance ID (0).
    pub fn default_instance() -> Self {
        Self::new(DEFAULT_RPL_INSTANCE_ID)
    }

    /// Set the local gateway info.
    pub fn set_local_gateway(&mut self, gateway: GatewayInfo) {
        self.local_gateway = Some(gateway);
    }

    /// Create a coordinator with local gateway already set.
    pub fn with_local_gateway(mut self, gateway: GatewayInfo) -> Self {
        self.local_gateway = Some(gateway);
        self
    }

    /// Get the RPL instance ID.
    pub fn rpl_instance_id(&self) -> u8 {
        self.rpl_instance_id
    }

    /// Get the local gateway info.
    pub fn local_gateway(&self) -> Option<&GatewayInfo> {
        self.local_gateway.as_ref()
    }

    /// Add a discovered peer gateway to the federation.
    ///
    /// Per GCP-4.1, gateways discover each other via backbone multicast
    /// or LoRa fallback. This method registers a discovered peer.
    ///
    /// SECURITY: Enforces MAX_PEERS limit to prevent memory exhaustion DoS.
    /// Returns `true` if the peer was added, `false` if the limit was reached
    /// (unless updating an existing peer).
    pub fn add_peer(&self, gateway: GatewayInfo) -> bool {
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        // Allow updates to existing peers even at capacity
        if peers.len() >= MAX_PEERS && !peers.contains_key(&gateway.iid) {
            return false;
        }
        peers.insert(gateway.iid, gateway);
        true
    }

    /// Remove a peer gateway from the federation.
    ///
    /// Returns `true` if the peer was removed, `false` if not found.
    pub fn remove_peer(&self, iid: &[u8; 16]) -> bool {
        let mut peers = self.peers.lock().expect("peers mutex poisoned");
        peers.remove(iid).is_some()
    }

    /// Return list of all known peer gateways.
    pub fn get_peers(&self) -> Vec<GatewayInfo> {
        let peers = self.peers.lock().expect("peers mutex poisoned");
        peers.values().cloned().collect()
    }

    /// Get a specific peer gateway by IID.
    pub fn get_peer(&self, iid: &[u8; 16]) -> Option<GatewayInfo> {
        let peers = self.peers.lock().expect("peers mutex poisoned");
        peers.get(iid).cloned()
    }

    /// Get the number of peer gateways.
    pub fn peer_count(&self) -> usize {
        let peers = self.peers.lock().expect("peers mutex poisoned");
        peers.len()
    }

    /// Elect time master by lowest IID (per GCP-6.1).
    ///
    /// Per GCP-6.1: Non-GPS gateways elect time master; lowest IID wins.
    /// GPS-equipped gateways use GPS epoch directly.
    ///
    /// Returns the elected time master, or None if no gateways known.
    pub fn elect_time_master(&self) -> Option<GatewayInfo> {
        let peers = self.peers.lock().expect("peers mutex poisoned");

        let mut candidates: Vec<&GatewayInfo> = peers.values().collect();
        if let Some(ref local) = self.local_gateway {
            candidates.push(local);
        }

        if candidates.is_empty() {
            return None;
        }

        // Lowest IID wins - compare by packed bytes
        candidates
            .into_iter()
            .min_by(|a, b| iid_compare(&a.iid, &b.iid))
            .cloned()
    }

    /// Determine this gateway's role in the federation.
    ///
    /// This method holds the peers lock for the entire role determination
    /// to avoid a TOCTOU race between checking peer count and electing time master.
    pub fn get_role(&self) -> GatewayRole {
        let Some(ref local) = self.local_gateway else {
            return GatewayRole::Standalone;
        };

        // Hold lock for entire role determination to avoid TOCTOU race
        let peers = self.peers.lock().expect("peers mutex poisoned");

        if peers.is_empty() {
            return GatewayRole::Standalone;
        }

        // Elect time master from same locked snapshot of peers
        let mut candidates: Vec<&GatewayInfo> = peers.values().collect();
        candidates.push(local);

        // Lowest IID wins - compare by packed bytes
        let master = candidates
            .into_iter()
            .min_by(|a, b| iid_compare(&a.iid, &b.iid));

        match master {
            Some(m) if m.iid == local.iid => GatewayRole::Primary,
            _ => GatewayRole::Secondary,
        }
    }

    /// Return current DODAG version (lollipop counter).
    pub fn get_dodag_version(&self) -> u8 {
        let version = self.dodag_version.lock().expect("version mutex poisoned");
        *version
    }

    /// Increment DODAG version (lollipop semantics per RFC 6550 Section 7.2).
    ///
    /// The counter wraps from 255 to 0, entering the linear region.
    /// Returns the new version.
    pub fn increment_dodag_version(&self) -> u8 {
        let mut version = self.dodag_version.lock().expect("version mutex poisoned");
        *version = (*version).wrapping_add(1);
        *version
    }

    /// Set DODAG version explicitly (for synchronization).
    pub fn set_dodag_version(&self, new_version: u8) {
        let mut version = self.dodag_version.lock().expect("version mutex poisoned");
        *version = new_version;
    }

    /// Create a DODAG state for a root gateway.
    ///
    /// Per GCP-5, each gateway acts as DODAG root for the shared instance.
    /// This creates the root state with the shared RPLInstanceID.
    pub fn create_dodag_state(&self, dodag_id: [u8; 16]) -> DodagState {
        let version = self.get_dodag_version();
        DodagState::as_root(self.rpl_instance_id, dodag_id, version)
    }

    /// Validate a DIO from a peer gateway.
    ///
    /// Per GCP-5, all cooperating gateways use the same RPLInstanceID.
    /// This validates that an incoming DIO conforms to federation rules.
    pub fn validate_dio(&self, dio: &Dio) -> DioValidationResult {
        // MUST: Same RPLInstanceID
        if dio.rpl_instance_id != self.rpl_instance_id {
            return DioValidationResult {
                is_valid: false,
                reason: "RPLInstanceID mismatch",
            };
        }

        // Root DIOs have rank = ROOT_RANK (256)
        if dio.rank != ROOT_RANK {
            return DioValidationResult {
                is_valid: false,
                reason: "Peer gateway DIO must have root rank",
            };
        }

        DioValidationResult {
            is_valid: true,
            reason: "valid",
        }
    }

    /// Validate a DIO with detailed error.
    pub fn validate_dio_detailed(&self, dio: &Dio) -> Result<(), MultiInstanceError> {
        if dio.rpl_instance_id != self.rpl_instance_id {
            return Err(MultiInstanceError::InstanceIdMismatch {
                expected: self.rpl_instance_id,
                got: dio.rpl_instance_id,
            });
        }

        if dio.rank != ROOT_RANK {
            return Err(MultiInstanceError::NonRootRank {
                expected: ROOT_RANK,
                got: dio.rank,
            });
        }

        Ok(())
    }

    /// Get total routes learned across all gateways in federation.
    pub fn total_aggregated_routes(&self) -> u32 {
        let peers = self.peers.lock().expect("peers mutex poisoned");
        let mut total = peers
            .values()
            .fold(0u32, |acc, g| acc.saturating_add(g.routes_learned));
        if let Some(ref local) = self.local_gateway {
            total = total.saturating_add(local.routes_learned);
        }
        total
    }
}

#[cfg(feature = "std")]
impl Default for MultiRootCoordinator {
    fn default() -> Self {
        Self::default_instance()
    }
}

/// Bridge for propagating DAO messages between gateways over backbone.
///
/// Per GCP-5, DAO messages propagate across backbone as needed for route
/// aggregation. This bridge handles:
///
/// 1. Converting local DAOs to backbone messages
/// 2. Receiving DAOs from peer gateways
/// 3. Merging routing information from multiple sources
/// 4. Maintaining consistency across the federation
///
/// The backbone uses CoAP for transport (per GCP-6.4), with OSCORE protection
/// in either PSK or Ed25519 mode (per GCP-3).
#[cfg(feature = "std")]
pub struct DaoBackboneBridge {
    /// Local gateway IID.
    local_gateway_iid: Option<[u8; 16]>,
    /// RPL instance ID.
    rpl_instance_id: u8,
    /// Pending messages for propagation.
    pending: Mutex<Vec<DaoBackboneMessage>>,
    /// Routes received from peer gateways.
    received_routes: Mutex<HashMap<[u8; 16], Vec<(DaoTarget, DaoTransit)>>>,
}

#[cfg(feature = "std")]
impl DaoBackboneBridge {
    /// Create a new DAO backbone bridge.
    pub fn new(rpl_instance_id: u8) -> Self {
        Self {
            local_gateway_iid: None,
            rpl_instance_id,
            pending: Mutex::new(Vec::new()),
            received_routes: Mutex::new(HashMap::new()),
        }
    }

    /// Set the local gateway IID.
    pub fn set_local_gateway_iid(&mut self, iid: [u8; 16]) {
        self.local_gateway_iid = Some(iid);
    }

    /// Create a bridge with local gateway IID already set.
    pub fn with_local_gateway_iid(mut self, iid: [u8; 16]) -> Self {
        self.local_gateway_iid = Some(iid);
        self
    }

    /// Get the local gateway IID.
    pub fn local_gateway_iid(&self) -> Option<[u8; 16]> {
        self.local_gateway_iid
    }

    /// Create a DAO backbone message from targets and transit info.
    pub fn create_backbone_message(
        &self,
        dao_sequence: u8,
        targets: Vec<DaoTarget>,
        transit: Vec<DaoTransit>,
        timestamp: f64,
    ) -> Result<DaoBackboneMessage, MultiInstanceError> {
        let origin_gateway = self
            .local_gateway_iid
            .ok_or(MultiInstanceError::NoLocalGateway)?;

        Ok(DaoBackboneMessage {
            origin_gateway,
            rpl_instance_id: self.rpl_instance_id,
            dao_sequence,
            targets,
            transit,
            timestamp,
        })
    }

    /// Queue a DAO backbone message for propagation to peers.
    ///
    /// SECURITY: Enforces MAX_PENDING_PROPAGATIONS limit to prevent memory exhaustion DoS.
    /// Returns `true` if the message was queued, `false` if the limit was reached.
    pub fn queue_for_propagation(&self, message: DaoBackboneMessage) -> bool {
        let mut pending = self.pending.lock().expect("pending mutex poisoned");
        if pending.len() >= MAX_PENDING_PROPAGATIONS {
            return false;
        }
        pending.push(message);
        true
    }

    /// Get and clear pending propagation messages.
    pub fn get_pending_propagations(&self) -> Vec<DaoBackboneMessage> {
        let mut pending = self.pending.lock().expect("pending mutex poisoned");
        std::mem::take(&mut *pending)
    }

    /// Process a DAO backbone message received from a peer gateway.
    ///
    /// This merges the routing information into the local routing table,
    /// enabling route aggregation across the federation.
    ///
    /// # Arguments
    ///
    /// * `message` - The DAO backbone message to process
    /// * `authenticated_sender` - The OSCORE-authenticated sender IID from transport layer
    /// * `current_time` - Current monotonic time for freshness validation
    ///
    /// # Security
    ///
    /// This function validates:
    /// - RPL instance ID matches our federation
    /// - Origin gateway is not ourselves (prevents self-loop attacks)
    /// - Timestamp is within acceptable freshness window (prevents replay attacks)
    /// - Origin gateway matches OSCORE-authenticated sender (prevents spoofing)
    /// - Enforces MAX_ROUTES_PER_MESSAGE limit per message (prevents memory exhaustion DoS)
    /// - Enforces MAX_RECEIVED_ROUTE_PEERS limit (prevents memory exhaustion DoS)
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the routes were stored
    /// - `Ok(false)` if the peer limit was reached (DoS protection)
    /// - `Err(...)` if validation failed
    pub fn receive_from_peer(
        &self,
        message: DaoBackboneMessage,
        authenticated_sender: [u8; 16],
        current_time: f64,
    ) -> Result<bool, MultiInstanceError> {
        let origin = message.origin_gateway;

        // SECURITY: Validate RPL instance ID matches our federation
        if message.rpl_instance_id != self.rpl_instance_id {
            return Err(MultiInstanceError::InstanceIdMismatch {
                expected: self.rpl_instance_id,
                got: message.rpl_instance_id,
            });
        }

        // SECURITY: Reject messages claiming to be from ourselves
        if let Some(local_iid) = self.local_gateway_iid {
            if origin == local_iid {
                return Err(MultiInstanceError::SelfOrigin);
            }
        }

        // SECURITY: Validate timestamp freshness to prevent replay attacks
        // NaN check required: NaN comparisons return false, bypassing both > and < guards
        let age = current_time - message.timestamp;
        if age.is_nan() || age > DAO_TIMESTAMP_FRESHNESS_SECONDS || age < 0.0 {
            return Err(MultiInstanceError::StaleTimestamp {
                message_time: message.timestamp,
                current_time,
            });
        }

        // SECURITY: Validate origin matches OSCORE-authenticated sender
        if origin != authenticated_sender {
            return Err(MultiInstanceError::OriginAuthMismatch {
                claimed: origin,
                authenticated: authenticated_sender,
            });
        }

        // SECURITY: Validate route count to prevent memory exhaustion
        let targets_len = message.targets.len();
        let transit_len = message.transit.len();
        if targets_len > MAX_ROUTES_PER_MESSAGE || transit_len > MAX_ROUTES_PER_MESSAGE {
            return Err(MultiInstanceError::TooManyRoutes {
                targets: targets_len,
                transit: transit_len,
                limit: MAX_ROUTES_PER_MESSAGE,
            });
        }

        // Reconstruct routes from message by pairing targets with transits by index.
        // If transit[i] exists, use it; otherwise fall back to default transit.
        let default_transit = DaoTransit {
            path_sequence: message.dao_sequence,
            path_lifetime: 60,
            path_control: 0,
            parent: None,
        };
        let routes: Vec<(DaoTarget, DaoTransit)> = message
            .targets
            .into_iter()
            .enumerate()
            .map(|(i, target)| {
                let transit = message
                    .transit
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| default_transit.clone());
                (target, transit)
            })
            .collect();

        let mut received = self.received_routes.lock().expect("routes mutex poisoned");
        // Allow updates to existing peers even at capacity
        if received.len() >= MAX_RECEIVED_ROUTE_PEERS && !received.contains_key(&origin) {
            return Ok(false);
        }
        received.insert(origin, routes);
        Ok(true)
    }

    /// Get all routes aggregated from peer gateways.
    ///
    /// Returns a map from peer gateway IID to the routes learned from it.
    pub fn get_aggregated_routes(&self) -> HashMap<[u8; 16], Vec<(DaoTarget, DaoTransit)>> {
        let received = self.received_routes.lock().expect("routes mutex poisoned");
        received.clone()
    }

    /// Get total number of routes received from all peers.
    pub fn total_received_routes(&self) -> usize {
        let received = self.received_routes.lock().expect("routes mutex poisoned");
        received.values().map(|v| v.len()).sum()
    }

    /// Clear all received routes.
    pub fn clear_received_routes(&self) {
        let mut received = self.received_routes.lock().expect("routes mutex poisoned");
        received.clear();
    }
}

// ─── Helper Functions ───────────────────────────────────────────────────────

/// Compare two gateway IIDs for conflict resolution.
///
/// Per GCP-6.3, conflicts are resolved by lowest IID.
/// IIDs are compared as packed byte representation (lexicographic).
///
/// Returns `Ordering` indicating relative order of `a` vs `b`.
pub fn iid_compare(a: &[u8; 16], b: &[u8; 16]) -> Ordering {
    a.cmp(b)
}

/// Compare two gateway IIDs and return comparison result.
///
/// Returns:
/// - `-1` if a < b
/// - `0` if a == b
/// - `1` if a > b
pub fn iid_compare_int(a: &[u8; 16], b: &[u8; 16]) -> i32 {
    match iid_compare(a, b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Resolve slot conflict between two gateways.
///
/// Per GCP-6.3: If two gateways claim overlapping slot, lowest IID MUST win.
/// Returns the winning gateway's IID.
pub fn resolve_slot_conflict(claimant_a: &[u8; 16], claimant_b: &[u8; 16]) -> [u8; 16] {
    if iid_compare(claimant_a, claimant_b) != Ordering::Greater {
        *claimant_a
    } else {
        *claimant_b
    }
}

/// Validate that an RPLInstanceID is in valid range.
///
/// Per RFC 6550, RPLInstanceID must be 0-255.
pub fn validate_rpl_instance_id(id: i32) -> Result<u8, MultiInstanceError> {
    if (0..=255).contains(&id) {
        Ok(id as u8)
    } else {
        Err(MultiInstanceError::InvalidInstanceId(id))
    }
}

/// Increment DODAG version with lollipop semantics.
///
/// Per RFC 6550 Section 7.2, the version counter wraps from 255 to 0.
pub fn increment_lollipop_version(current: u8) -> u8 {
    current.wrapping_add(1)
}

// ─── Multi-Root Conflict Resolution (2a.5.4) ────────────────────────────────

/// Holdoff period for root transition (spec 2a.5.3).
pub const HOLDOFF_SUPERFRAMES: u8 = 3;

/// Outcome of an RPL version change during multi-root conflict.
///
/// Per spec 02a-coordinated-capacity.md section 2a.5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionChangeOutcome {
    /// Version accepted, SFN reset, continue with current root.
    Accepted,
    /// Version accepted during holdoff, holdoff counter reset.
    HoldoffReset,
    /// Signature verification failed on new version, root discarded.
    SigFailedDiscard,
    /// No version change (same version or not in conflict state).
    NoChange,
}

/// Result of processing an RPL version change during multi-root conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionChangeResult {
    /// Outcome of the version change.
    pub outcome: VersionChangeOutcome,
    /// New version number.
    pub new_version: u8,
    /// Whether SFN should be reset relative to new epoch.
    pub sfn_reset: bool,
    /// Whether holdoff counter was reset.
    pub holdoff_reset: bool,
    /// Whether remaining candidates should be evaluated.
    pub evaluate_candidates: bool,
}

/// Root candidate for multi-root conflict resolution.
///
/// Per spec 02a-coordinated-capacity.md section 2a.5.2.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq)]
pub struct RootCandidate {
    /// Root's EUI-64 (8 bytes).
    pub eui64: [u8; 8],
    /// RPL DODAG Preference (higher = more preferred).
    pub dodag_preference: u8,
    /// Time-provider stratum (lower = better).
    pub stratum: u8,
    /// EMA-smoothed RSSI in dBm.
    pub rssi_ema: f32,
    /// EMA-smoothed SNR in dB.
    pub snr_ema: f32,
    /// Whether Schnorr48 signature verified.
    pub signature_valid: bool,
}

#[cfg(feature = "std")]
impl RootCandidate {
    /// Create a new root candidate.
    ///
    /// SECURITY: signature_valid defaults to false (fail-closed). Callers
    /// MUST call `.with_signature_valid(true)` only AFTER successful
    /// Schnorr48 signature verification.
    pub fn new(eui64: [u8; 8]) -> Self {
        Self {
            eui64,
            dodag_preference: 0,
            stratum: 255,
            rssi_ema: -120.0,
            snr_ema: -20.0,
            signature_valid: false,
        }
    }

    /// Set DODAG preference.
    pub fn with_dodag_preference(mut self, pref: u8) -> Self {
        self.dodag_preference = pref;
        self
    }

    /// Set stratum.
    pub fn with_stratum(mut self, stratum: u8) -> Self {
        self.stratum = stratum;
        self
    }

    /// Set RF metrics.
    ///
    /// NaN values are replaced with worst-case defaults (-120.0 dBm RSSI,
    /// -20.0 dB SNR) to maintain Eq reflexivity (NaN != NaN would break it).
    pub fn with_rf_metrics(mut self, rssi_ema: f32, snr_ema: f32) -> Self {
        // Sanitize NaN to default (worst) values to maintain Eq invariant
        self.rssi_ema = if rssi_ema.is_nan() { -120.0 } else { rssi_ema };
        self.snr_ema = if snr_ema.is_nan() { -20.0 } else { snr_ema };
        self
    }

    /// Set RSSI EMA.
    pub fn with_rssi_ema(mut self, rssi_ema: f32) -> Self {
        self.rssi_ema = if rssi_ema.is_nan() { -120.0 } else { rssi_ema };
        self
    }

    /// Set SNR EMA.
    pub fn with_snr_ema(mut self, snr_ema: f32) -> Self {
        self.snr_ema = if snr_ema.is_nan() { -20.0 } else { snr_ema };
        self
    }

    /// Set signature validity.
    pub fn with_signature_valid(mut self, valid: bool) -> Self {
        self.signature_valid = valid;
        self
    }

    /// Combined RSSI+SNR score (RSSI weighted 2:1 over SNR).
    pub fn combined_score(&self) -> f32 {
        2.0 * self.rssi_ema + self.snr_ema
    }

    /// IID as unsigned big-endian integer for comparison.
    pub fn iid(&self) -> u64 {
        u64::from_be_bytes(self.eui64)
    }
}

#[cfg(feature = "std")]
impl Ord for RootCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Per 2a.5.2, ordered by:
        // 1. DODAG Preference (higher wins, so reverse order)
        // 2. Stratum (lower wins)
        // 3. RSSI+SNR (higher wins, so reverse order)
        // 4. IID (lower wins)
        other
            .dodag_preference
            .cmp(&self.dodag_preference)
            .then_with(|| self.stratum.cmp(&other.stratum))
            .then_with(|| {
                // Higher combined score is better; use total_cmp for Ord compliance
                other.combined_score().total_cmp(&self.combined_score())
            })
            .then_with(|| self.iid().cmp(&other.iid()))
    }
}

#[cfg(feature = "std")]
impl PartialOrd for RootCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "std")]
impl Eq for RootCandidate {}

/// Select the best root from candidates per spec 2a.5.
///
/// Returns None if no valid candidates (all have invalid signatures).
#[cfg(feature = "std")]
pub fn select_root(candidates: &[RootCandidate]) -> Option<&RootCandidate> {
    // Filter to valid signatures only (2a.5.1)
    candidates
        .iter()
        .filter(|c| c.signature_valid)
        .min_by(|a, b| a.cmp(b))
}

/// Select the best root and return its index.
///
/// Returns None if no valid candidates (all have invalid signatures).
/// This is used when we need to mutate state then return a reference.
#[cfg(feature = "std")]
fn select_root_index(candidates: &[RootCandidate]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.signature_valid)
        .min_by(|(_, a), (_, b)| a.cmp(b))
        .map(|(idx, _)| idx)
}

/// State machine for multi-root beacon conflict resolution.
///
/// Per spec 02a-coordinated-capacity.md section 2a.5:
/// - 2a.5.1: Signature verification gate
/// - 2a.5.2: Root selection criteria
/// - 2a.5.3: Overlap resolution with holdoff
/// - 2a.5.4: RPL version change during multi-root conflict
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct MultiRootState {
    /// Current root (None if not synced).
    pub current_root: Option<RootCandidate>,
    /// Current RPL DODAG version.
    pub current_version: u8,
    /// Candidates received in current beacon window.
    candidates: Vec<RootCandidate>,
    /// Selected root during holdoff transition.
    holdoff_selected: Option<RootCandidate>,
    /// Holdoff counter (0 = not in holdoff, 1-3 = superframes remaining).
    holdoff_counter: u8,
    /// Desync state that depends on prior version.
    desync_state_version: Option<u8>,
}

#[cfg(feature = "std")]
impl MultiRootState {
    /// Create a new multi-root state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate root from a received beacon.
    ///
    /// Per 2a.5.1: Only candidates with valid signatures are retained.
    ///
    /// SECURITY: Enforces MAX_CANDIDATES limit to prevent memory exhaustion DoS.
    /// Returns `true` if the candidate was added, `false` if the limit was reached
    /// or the signature was invalid.
    pub fn add_candidate(&mut self, candidate: RootCandidate) -> bool {
        if !candidate.signature_valid {
            return false;
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            return false;
        }
        self.candidates.push(candidate);
        true
    }

    /// Clear candidate list after beacon window processing.
    pub fn clear_candidates(&mut self) {
        self.candidates.clear();
    }

    /// Return True if in holdoff transition period.
    pub fn is_in_holdoff(&self) -> bool {
        self.holdoff_counter > 0
    }

    /// Process overlapping beacons per 2a.5.3.
    ///
    /// Returns the selected root, or None if no valid candidates.
    /// Initiates holdoff if selected root differs from current root.
    pub fn process_beacon_window(&mut self) -> Option<&RootCandidate> {
        // Use index-based selection to avoid returning a different candidate
        // with the same eui64 when duplicates exist in the candidates list.
        let selected_idx = select_root_index(&self.candidates)?;
        let selected = &self.candidates[selected_idx];
        let selected_eui64 = selected.eui64;

        // Check if selected root differs from current root
        if let Some(ref current) = self.current_root {
            if selected_eui64 != current.eui64 && !self.is_in_holdoff() {
                // Per 2a.5.3: defer transition for 3 superframes
                self.holdoff_selected = Some(self.candidates[selected_idx].clone());
                self.holdoff_counter = HOLDOFF_SUPERFRAMES;
            }
        } else if !self.is_in_holdoff() {
            // First sync - no holdoff needed
            self.current_root = Some(self.candidates[selected_idx].clone());
        }

        // Return reference to the exact candidate that was selected
        self.candidates.get(selected_idx)
    }

    /// Advance holdoff counter by one superframe.
    ///
    /// Returns true if holdoff completed and transition should occur.
    pub fn advance_holdoff(&mut self) -> bool {
        if !self.is_in_holdoff() {
            return false;
        }

        self.holdoff_counter -= 1;
        if self.holdoff_counter == 0 {
            // Holdoff complete - transition to new root
            if let Some(selected) = self.holdoff_selected.take() {
                self.current_root = Some(selected);
            }
            return true;
        }
        false
    }

    /// Handle RPL DODAG version change per spec 2a.5.4.
    pub fn on_version_change(
        &mut self,
        new_version: u8,
        signature_valid: bool,
    ) -> VersionChangeResult {
        // No change if same version
        if new_version == self.current_version {
            return VersionChangeResult {
                outcome: VersionChangeOutcome::NoChange,
                new_version,
                sfn_reset: false,
                holdoff_reset: false,
                evaluate_candidates: false,
            };
        }

        // Per 2a.5.4: Re-verify signature upon first beacon with new version
        if !signature_valid {
            // Signature verification failed for new version
            if self.is_in_holdoff() {
                self.holdoff_counter = 0;
                self.holdoff_selected = None;
            }
            self.current_root = None;
            return VersionChangeResult {
                outcome: VersionChangeOutcome::SigFailedDiscard,
                new_version,
                sfn_reset: false,
                holdoff_reset: false,
                evaluate_candidates: true,
            };
        }

        // Per 2a.5.4 step 1: Accept the new DODAG Version
        let old_version = self.current_version;
        self.current_version = new_version;

        // Per 2a.5.4 step 2: Reset desync state that depended on prior version
        if self.desync_state_version == Some(old_version) {
            self.desync_state_version = None;
        }

        // Per 2a.5.4: During holdoff, version change resets holdoff counter
        if self.is_in_holdoff() {
            self.holdoff_counter = HOLDOFF_SUPERFRAMES;
            return VersionChangeResult {
                outcome: VersionChangeOutcome::HoldoffReset,
                new_version,
                sfn_reset: true,
                holdoff_reset: true,
                evaluate_candidates: false,
            };
        }

        // Not in holdoff: standard version change handling
        VersionChangeResult {
            outcome: VersionChangeOutcome::Accepted,
            new_version,
            sfn_reset: true,
            holdoff_reset: false,
            evaluate_candidates: false,
        }
    }

    /// Cancel holdoff transition.
    pub fn cancel_holdoff(&mut self) {
        self.holdoff_counter = 0;
        self.holdoff_selected = None;
    }

    /// Mark that desync state depends on the given version.
    pub fn set_desync_state_version(&mut self, version: u8) {
        self.desync_state_version = Some(version);
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.current_root = None;
        self.current_version = 0;
        self.candidates.clear();
        self.holdoff_selected = None;
        self.holdoff_counter = 0;
        self.desync_state_version = None;
    }
}

/// Parse a link-local IPv6 address string to byte array.
///
/// Supports format like "fe80::1234:5678:9abc:def0".
#[cfg(feature = "std")]
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    Ipv6Addr::from_str(s).ok().map(|addr| addr.octets())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::vec;

    /// Parse IPv6 address for tests.
    fn ipv6(s: &str) -> [u8; 16] {
        parse_ipv6(s).expect("valid IPv6")
    }

    // ─── Test Vectors from rpl_multi_instance.json ──────────────────────────

    #[test]
    fn multi_root_basic_time_master_election() {
        // Vector: multi_root_basic
        // Two gateways in same RPL instance, lowest IID elected as time master
        let coord = MultiRootCoordinator::new(0);

        let gw1 = GatewayInfo::new(ipv6("fe80::1234:5678:9abc:def0")).with_gps(false);
        let gw2 = GatewayInfo::new(ipv6("fe80::abcd:ef01:2345:6789")).with_gps(false);

        coord.add_peer(gw1.clone());
        coord.add_peer(gw2);

        let master = coord.elect_time_master();
        assert!(master.is_some());
        // Lowest IID wins: fe80::1234... < fe80::abcd...
        assert_eq!(master.unwrap().iid, ipv6("fe80::1234:5678:9abc:def0"));
    }

    #[test]
    fn slot_conflict_iid_resolution() {
        // Vector: slot_conflict_iid_resolution
        // Slot conflict resolved by lowest IID per GCP-6.3
        let claimant_a = ipv6("fe80::1234:5678:9abc:def0");
        let claimant_b = ipv6("fe80::abcd:ef01:2345:6789");

        let winner = resolve_slot_conflict(&claimant_a, &claimant_b);
        assert_eq!(winner, claimant_a);

        // Order shouldn't matter
        let winner2 = resolve_slot_conflict(&claimant_b, &claimant_a);
        assert_eq!(winner2, claimant_a);
    }

    #[test]
    fn dio_validation_same_instance() {
        // Vector: dio_validation_same_instance
        // Peer gateway DIO with matching RPLInstanceID accepted
        let coord = MultiRootCoordinator::new(0);

        let dio = Dio {
            rpl_instance_id: 0,
            version: 1,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: ipv6("fe80::1234:5678:9abc:def0"),
        };

        let result = coord.validate_dio(&dio);
        assert!(result.is_valid);
        assert_eq!(result.reason, "valid");
    }

    #[test]
    fn dio_validation_different_instance_rejected() {
        // Vector: dio_validation_different_instance
        // Peer gateway DIO with different RPLInstanceID rejected per GCP-5
        let coord = MultiRootCoordinator::new(0);

        let dio = Dio {
            rpl_instance_id: 1, // Different instance
            version: 1,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: ipv6("fe80::1234:5678:9abc:def0"),
        };

        let result = coord.validate_dio(&dio);
        assert!(!result.is_valid);
        assert!(result.reason.contains("mismatch"));
    }

    #[test]
    fn dodag_version_lollipop() {
        // Vector: dodag_version_lollipop
        // DODAG version increments using lollipop semantics
        let coord = MultiRootCoordinator::new(0);
        coord.set_dodag_version(254);

        let v1 = coord.increment_dodag_version();
        assert_eq!(v1, 255);

        let v2 = coord.increment_dodag_version();
        assert_eq!(v2, 0); // Wrap around

        let v3 = coord.increment_dodag_version();
        assert_eq!(v3, 1);
    }

    #[test]
    fn three_gateway_federation() {
        // Vector: three_gateway_federation
        // Three gateways sharing RPL instance with route aggregation
        let coord = MultiRootCoordinator::new(0);

        let gw1 = GatewayInfo::new(ipv6("fe80::aaaa:1111:2222:3333")).with_routes_learned(5);
        let gw2 = GatewayInfo::new(ipv6("fe80::bbbb:4444:5555:6666")).with_routes_learned(3);
        let gw3 = GatewayInfo::new(ipv6("fe80::cccc:7777:8888:9999")).with_routes_learned(7);

        coord.add_peer(gw1);
        coord.add_peer(gw2);
        coord.add_peer(gw3);

        // Lowest IID is fe80::aaaa...
        let master = coord.elect_time_master().unwrap();
        assert_eq!(master.iid, ipv6("fe80::aaaa:1111:2222:3333"));

        // Total routes = 5 + 3 + 7 = 15
        assert_eq!(coord.total_aggregated_routes(), 15);
    }

    #[test]
    fn gateway_role_determination() {
        // Vector: gateway_role_determination

        // Scenario: standalone (no peers)
        let mut coord = MultiRootCoordinator::new(0);
        let local = GatewayInfo::new(ipv6("fe80::1234:5678:9abc:def0"));
        coord.set_local_gateway(local);
        assert_eq!(coord.get_role(), GatewayRole::Standalone);

        // Scenario: primary (lowest IID)
        let mut coord = MultiRootCoordinator::new(0);
        let local = GatewayInfo::new(ipv6("fe80::0001:0002:0003:0004"));
        coord.set_local_gateway(local);
        let peer = GatewayInfo::new(ipv6("fe80::ffff:ffff:ffff:ffff"));
        coord.add_peer(peer);
        assert_eq!(coord.get_role(), GatewayRole::Primary);

        // Scenario: secondary (higher IID)
        let mut coord = MultiRootCoordinator::new(0);
        let local = GatewayInfo::new(ipv6("fe80::ffff:ffff:ffff:ffff"));
        coord.set_local_gateway(local);
        let peer = GatewayInfo::new(ipv6("fe80::0001:0002:0003:0004"));
        coord.add_peer(peer);
        assert_eq!(coord.get_role(), GatewayRole::Secondary);
    }

    #[test]
    fn rpl_instance_id_validation() {
        // Vector: rpl_instance_id_validation
        // RPLInstanceID must be 0-255 per RFC 6550

        // Valid IDs
        for id in [0, 1, 127, 128, 255] {
            assert!(validate_rpl_instance_id(id).is_ok());
        }

        // Invalid IDs
        for id in [-1, 256, 1000] {
            assert!(validate_rpl_instance_id(id).is_err());
        }
    }

    #[test]
    fn iid_comparison_bytes() {
        // Vector: iid_comparison_bytes
        // IID comparison uses packed byte representation for ordering

        // fe80::0001:0002:0003:0004 < fe80::ffff:ffff:ffff:ffff
        let a = ipv6("fe80::0001:0002:0003:0004");
        let b = ipv6("fe80::ffff:ffff:ffff:ffff");
        assert_eq!(iid_compare_int(&a, &b), -1);
        assert_eq!(resolve_slot_conflict(&a, &b), a);

        // fe80::1234:5678:9abc:def0 < fe80::abcd:ef01:2345:6789
        let a = ipv6("fe80::1234:5678:9abc:def0");
        let b = ipv6("fe80::abcd:ef01:2345:6789");
        assert_eq!(iid_compare_int(&a, &b), -1);

        // Same IID
        let a = ipv6("fe80::1234:5678:9abc:def0");
        let b = ipv6("fe80::1234:5678:9abc:def0");
        assert_eq!(iid_compare_int(&a, &b), 0);
    }

    #[test]
    fn dao_backbone_propagation() {
        // Vector: dao_backbone_propagation
        // DAO propagated from gateway A to gateway B over backbone
        let mut bridge = DaoBackboneBridge::new(0);
        bridge.set_local_gateway_iid(ipv6("fe80::1234:5678:9abc:def0"));

        let targets = vec![DaoTarget {
            target: ipv6("0200:1234:5678:9abc::"),
            prefix_length: 64,
        }];

        let transit = vec![DaoTransit {
            path_sequence: 42,
            path_lifetime: 60,
            path_control: 0,
            parent: Some(ipv6("fe80::1111:2222:3333:4444")),
        }];

        let message = bridge
            .create_backbone_message(42, targets, transit, 1234567890.0)
            .expect("should create message");

        assert_eq!(
            message.origin_gateway,
            ipv6("fe80::1234:5678:9abc:def0")
        );
        assert_eq!(message.dao_sequence, 42);
        assert_eq!(message.targets.len(), 1);
        assert_eq!(message.targets[0].prefix_length, 64);
    }

    #[test]
    fn dao_target_aggregation() {
        // Vector: dao_target_aggregation
        // Multiple targets from single DAO aggregated in backbone message
        let mut bridge = DaoBackboneBridge::new(0);
        bridge.set_local_gateway_iid(ipv6("fe80::1234:5678:9abc:def0"));

        let targets = vec![
            DaoTarget {
                target: ipv6("0200:aaaa::"),
                prefix_length: 64,
            },
            DaoTarget {
                target: ipv6("0200:bbbb::"),
                prefix_length: 64,
            },
            DaoTarget {
                target: ipv6("0200:cccc::"),
                prefix_length: 64,
            },
        ];

        let message = bridge
            .create_backbone_message(100, targets, vec![], 0.0)
            .expect("should create message");

        assert_eq!(message.targets.len(), 3);
    }

    #[test]
    fn bridge_queue_and_receive() {
        let bridge = DaoBackboneBridge::new(0);

        // Queue a message
        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::1234:5678:9abc:def0"),
            rpl_instance_id: 0,
            dao_sequence: 42,
            targets: vec![DaoTarget {
                target: ipv6("0200:5678::"),
                prefix_length: 64,
            }],
            transit: vec![DaoTransit {
                path_sequence: 42,
                path_lifetime: 60,
                path_control: 0,
                parent: None,
            }],
            timestamp: 0.0,
        };

        assert!(bridge.queue_for_propagation(message.clone()));

        // Get pending
        let pending = bridge.get_pending_propagations();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].dao_sequence, 42);

        // Queue should be cleared
        assert_eq!(bridge.get_pending_propagations().len(), 0);

        // Receive from peer (with valid authentication)
        let authenticated_sender = ipv6("fe80::1234:5678:9abc:def0");
        let current_time = 0.0; // message.timestamp is 0.0
        bridge
            .receive_from_peer(message, authenticated_sender, current_time)
            .expect("should accept valid message");

        let aggregated = bridge.get_aggregated_routes();
        assert!(aggregated.contains_key(&ipv6("fe80::1234:5678:9abc:def0")));

        let routes = &aggregated[&ipv6("fe80::1234:5678:9abc:def0")];
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0.prefix_length, 64);
    }

    #[test]
    fn bridge_queue_respects_max_pending_limit() {
        let bridge = DaoBackboneBridge::new(0);

        // Queue up to MAX_PENDING_PROPAGATIONS messages
        for i in 0..MAX_PENDING_PROPAGATIONS {
            let message = DaoBackboneMessage {
                origin_gateway: ipv6("fe80::1234:5678:9abc:def0"),
                rpl_instance_id: 0,
                dao_sequence: i as u8,
                targets: vec![],
                transit: vec![],
                timestamp: 0.0,
            };
            assert!(
                bridge.queue_for_propagation(message),
                "message {} should be queued",
                i
            );
        }

        // Next message should be rejected
        let overflow_message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::1234:5678:9abc:def0"),
            rpl_instance_id: 0,
            dao_sequence: 255,
            targets: vec![],
            transit: vec![],
            timestamp: 0.0,
        };
        assert!(
            !bridge.queue_for_propagation(overflow_message),
            "message beyond limit should be rejected"
        );

        // Drain queue, then should accept again
        let _pending = bridge.get_pending_propagations();
        let new_message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::1234:5678:9abc:def0"),
            rpl_instance_id: 0,
            dao_sequence: 0,
            targets: vec![],
            transit: vec![],
            timestamp: 0.0,
        };
        assert!(
            bridge.queue_for_propagation(new_message),
            "after drain, should accept new messages"
        );
    }

    #[test]
    fn bridge_receive_pairs_targets_with_transits_by_index() {
        let bridge = DaoBackboneBridge::new(0);

        // Create message with 3 targets and 3 distinct transits
        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 0,
            dao_sequence: 50,
            targets: vec![
                DaoTarget {
                    target: ipv6("0200:1111::"),
                    prefix_length: 64,
                },
                DaoTarget {
                    target: ipv6("0200:2222::"),
                    prefix_length: 64,
                },
                DaoTarget {
                    target: ipv6("0200:3333::"),
                    prefix_length: 64,
                },
            ],
            transit: vec![
                DaoTransit {
                    path_sequence: 10,
                    path_lifetime: 30,
                    path_control: 0,
                    parent: None,
                },
                DaoTransit {
                    path_sequence: 20,
                    path_lifetime: 60,
                    path_control: 0,
                    parent: None,
                },
                DaoTransit {
                    path_sequence: 30,
                    path_lifetime: 90,
                    path_control: 0,
                    parent: None,
                },
            ],
            timestamp: 0.0,
        };

        let authenticated_sender = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let current_time = 0.0;
        bridge
            .receive_from_peer(message, authenticated_sender, current_time)
            .expect("should accept valid message");

        let aggregated = bridge.get_aggregated_routes();
        let routes = &aggregated[&ipv6("fe80::aaaa:bbbb:cccc:dddd")];
        assert_eq!(routes.len(), 3);

        // Verify each target is paired with its corresponding transit by index
        assert_eq!(routes[0].1.path_sequence, 10);
        assert_eq!(routes[0].1.path_lifetime, 30);
        assert_eq!(routes[1].1.path_sequence, 20);
        assert_eq!(routes[1].1.path_lifetime, 60);
        assert_eq!(routes[2].1.path_sequence, 30);
        assert_eq!(routes[2].1.path_lifetime, 90);
    }

    #[test]
    fn bridge_rejects_wrong_rpl_instance_id() {
        // SECURITY: Messages with wrong RPL instance ID must be rejected
        let bridge = DaoBackboneBridge::new(0);

        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 42, // Wrong instance ID
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 100.0,
        };

        let authenticated_sender = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let current_time = 100.0;
        let result = bridge.receive_from_peer(message, authenticated_sender, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::InstanceIdMismatch { expected: 0, got: 42 })
        ));
    }

    #[test]
    fn bridge_rejects_self_origin() {
        // SECURITY: Messages claiming our own IID as origin must be rejected
        let mut bridge = DaoBackboneBridge::new(0);
        let local_iid = ipv6("fe80::1234:5678:9abc:def0");
        bridge.set_local_gateway_iid(local_iid);

        let message = DaoBackboneMessage {
            origin_gateway: local_iid, // Same as our local IID
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 100.0,
        };

        let authenticated_sender = local_iid;
        let current_time = 100.0;
        let result = bridge.receive_from_peer(message, authenticated_sender, current_time);

        assert!(matches!(result, Err(MultiInstanceError::SelfOrigin)));
    }

    #[test]
    fn bridge_rejects_stale_timestamp() {
        // SECURITY: Messages with stale timestamps must be rejected
        let bridge = DaoBackboneBridge::new(0);

        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 0.0, // Old timestamp
        };

        let authenticated_sender = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let current_time = 1000.0; // Much later than message timestamp
        let result = bridge.receive_from_peer(message, authenticated_sender, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn bridge_rejects_future_timestamp() {
        // SECURITY: Messages with future timestamps must be rejected (negative age)
        let bridge = DaoBackboneBridge::new(0);

        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 2000.0, // Future timestamp
        };

        let authenticated_sender = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let current_time = 100.0; // Earlier than message timestamp
        let result = bridge.receive_from_peer(message, authenticated_sender, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn bridge_rejects_nan_timestamp() {
        // SECURITY: NaN timestamp must be rejected (NaN comparisons return false, bypassing guards)
        let bridge = DaoBackboneBridge::new(0);

        let message = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: f64::NAN,
        };

        let authenticated_sender = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let current_time = 100.0;
        let result = bridge.receive_from_peer(message.clone(), authenticated_sender, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::StaleTimestamp { .. })
        ));

        // Also test NaN current_time
        let message2 = DaoBackboneMessage {
            origin_gateway: ipv6("fe80::aaaa:bbbb:cccc:dddd"),
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 100.0,
        };
        let result2 = bridge.receive_from_peer(message2, authenticated_sender, f64::NAN);

        assert!(matches!(
            result2,
            Err(MultiInstanceError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn bridge_rejects_origin_auth_mismatch() {
        // SECURITY: Messages where claimed origin doesn't match OSCORE sender must be rejected
        let bridge = DaoBackboneBridge::new(0);

        let claimed_origin = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let actual_sender = ipv6("fe80::1111:2222:3333:4444"); // Different from origin

        let message = DaoBackboneMessage {
            origin_gateway: claimed_origin,
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: vec![],
            timestamp: 100.0,
        };

        let current_time = 100.0;
        let result = bridge.receive_from_peer(message, actual_sender, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::OriginAuthMismatch { .. })
        ));
    }

    #[test]
    fn bridge_rejects_too_many_routes() {
        // SECURITY: Messages with too many routes must be rejected to prevent memory exhaustion
        let bridge = DaoBackboneBridge::new(0);

        let origin = ipv6("fe80::aaaa:bbbb:cccc:dddd");

        // Create a message with more than MAX_ROUTES_PER_MESSAGE targets
        let too_many_targets: Vec<DaoTarget> = (0..=MAX_ROUTES_PER_MESSAGE)
            .map(|i| {
                let mut target = [0u8; 16];
                target[0] = 0x02;
                target[2] = (i >> 8) as u8;
                target[3] = i as u8;
                DaoTarget {
                    target,
                    prefix_length: 64,
                }
            })
            .collect();

        let message = DaoBackboneMessage {
            origin_gateway: origin,
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: too_many_targets,
            transit: vec![],
            timestamp: 100.0,
        };

        let current_time = 100.0;
        let result = bridge.receive_from_peer(message, origin, current_time);

        assert!(matches!(
            result,
            Err(MultiInstanceError::TooManyRoutes { targets, transit: 0, limit: MAX_ROUTES_PER_MESSAGE })
            if targets > MAX_ROUTES_PER_MESSAGE
        ));

        // Also test too many transits
        let too_many_transits: Vec<DaoTransit> = (0..=MAX_ROUTES_PER_MESSAGE)
            .map(|_| DaoTransit {
                path_sequence: 1,
                path_lifetime: 60,
                path_control: 0,
                parent: None,
            })
            .collect();

        let message2 = DaoBackboneMessage {
            origin_gateway: origin,
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![],
            transit: too_many_transits,
            timestamp: 100.0,
        };

        let result2 = bridge.receive_from_peer(message2, origin, current_time);

        assert!(matches!(
            result2,
            Err(MultiInstanceError::TooManyRoutes { targets: 0, transit, limit: MAX_ROUTES_PER_MESSAGE })
            if transit > MAX_ROUTES_PER_MESSAGE
        ));
    }

    #[test]
    fn bridge_accepts_valid_message() {
        // Valid message should be accepted and return Ok(true)
        let bridge = DaoBackboneBridge::new(0);

        let origin = ipv6("fe80::aaaa:bbbb:cccc:dddd");
        let message = DaoBackboneMessage {
            origin_gateway: origin,
            rpl_instance_id: 0,
            dao_sequence: 1,
            targets: vec![DaoTarget {
                target: ipv6("0200:1111::"),
                prefix_length: 64,
            }],
            transit: vec![],
            timestamp: 100.0,
        };

        let authenticated_sender = origin;
        let current_time = 100.0;
        let result = bridge.receive_from_peer(message, authenticated_sender, current_time);

        assert!(matches!(result, Ok(true)));
        assert_eq!(bridge.total_received_routes(), 1);
    }

    #[test]
    fn coordinator_remove_peer() {
        let coord = MultiRootCoordinator::new(0);
        let gw = GatewayInfo::new(ipv6("fe80::1111:2222:3333:4444"));

        coord.add_peer(gw.clone());
        assert_eq!(coord.peer_count(), 1);

        let removed = coord.remove_peer(&gw.iid);
        assert!(removed);
        assert_eq!(coord.peer_count(), 0);

        // Remove non-existent returns false
        let removed = coord.remove_peer(&ipv6("fe80::dead:beef:cafe:babe"));
        assert!(!removed);
    }

    #[test]
    fn coordinator_default_instance() {
        let coord = MultiRootCoordinator::default_instance();
        assert_eq!(coord.rpl_instance_id(), DEFAULT_RPL_INSTANCE_ID);
        assert_eq!(coord.get_dodag_version(), INITIAL_DODAG_VERSION);
    }

    #[test]
    fn coordinator_create_dodag_state() {
        let coord = MultiRootCoordinator::new(0);
        let dodag_id = ipv6("fe80::1234:5678:9abc:def0");

        let state = coord.create_dodag_state(dodag_id);
        assert!(state.is_root());
        assert_eq!(state.rpl_instance_id, 0);
        assert_eq!(state.version, INITIAL_DODAG_VERSION);
    }

    #[test]
    fn validate_dio_detailed_errors() {
        let coord = MultiRootCoordinator::new(0);

        // Instance ID mismatch
        let dio = Dio {
            rpl_instance_id: 1,
            version: 1,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: ipv6("fe80::1234:5678:9abc:def0"),
        };
        let err = coord.validate_dio_detailed(&dio).unwrap_err();
        assert!(matches!(err, MultiInstanceError::InstanceIdMismatch { .. }));

        // Non-root rank
        let dio = Dio {
            rpl_instance_id: 0,
            version: 1,
            rank: 512, // Not root rank
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: ipv6("fe80::1234:5678:9abc:def0"),
        };
        let err = coord.validate_dio_detailed(&dio).unwrap_err();
        assert!(matches!(err, MultiInstanceError::NonRootRank { .. }));
    }

    #[test]
    fn increment_lollipop() {
        assert_eq!(increment_lollipop_version(0), 1);
        assert_eq!(increment_lollipop_version(127), 128);
        assert_eq!(increment_lollipop_version(254), 255);
        assert_eq!(increment_lollipop_version(255), 0); // Wrap
    }

    // ─── MultiRootState Tests (Spec 02a.5.4) ────────────────────────────────

    fn eui64(val: u8) -> [u8; 8] {
        [val, val, val, val, val, val, val, val]
    }

    #[test]
    fn multi_root_state_initial() {
        let state = MultiRootState::new();
        assert!(state.current_root.is_none());
        assert_eq!(state.current_version, 0);
        assert!(!state.is_in_holdoff());
    }

    #[test]
    fn multi_root_state_add_candidate_filters_invalid_sig() {
        // Per 2a.5.1: Only candidates with valid signatures are retained
        let mut state = MultiRootState::new();
        let valid = RootCandidate::new(eui64(1)).with_signature_valid(true);
        let invalid = RootCandidate::new(eui64(2)).with_signature_valid(false);

        state.add_candidate(valid);
        state.add_candidate(invalid);

        assert_eq!(state.candidates.len(), 1);
        assert_eq!(state.candidates[0].eui64, eui64(1));
    }

    #[test]
    fn multi_root_state_process_beacon_window_selects_best() {
        let mut state = MultiRootState::new();
        let best = RootCandidate::new(eui64(1)).with_dodag_preference(200).with_signature_valid(true);
        let worse = RootCandidate::new(eui64(2)).with_dodag_preference(100).with_signature_valid(true);

        state.add_candidate(worse);
        state.add_candidate(best.clone());
        let selected = state.process_beacon_window();

        assert!(selected.is_some());
        assert_eq!(selected.unwrap().eui64, eui64(1));
        assert_eq!(state.current_root.as_ref().unwrap().eui64, eui64(1));
    }

    #[test]
    fn multi_root_state_holdoff_initiated_on_root_change() {
        // Per 2a.5.3: Defer transition for 3 superframes
        let mut state = MultiRootState::new();
        let first = RootCandidate::new(eui64(1)).with_dodag_preference(100).with_signature_valid(true);
        state.add_candidate(first);
        state.process_beacon_window();
        state.clear_candidates();

        // Now a better root appears
        let second = RootCandidate::new(eui64(2)).with_dodag_preference(200).with_signature_valid(true);
        state.add_candidate(second);
        state.process_beacon_window();

        assert!(state.is_in_holdoff());
        assert_eq!(state.holdoff_counter, HOLDOFF_SUPERFRAMES);
        // Current root unchanged until holdoff completes
        assert_eq!(state.current_root.as_ref().unwrap().eui64, eui64(1));
    }

    #[test]
    fn multi_root_state_holdoff_completes_after_3_superframes() {
        // Per 2a.5.3: Transition after 3-superframe holdoff
        let mut state = MultiRootState::new();
        let first = RootCandidate::new(eui64(1)).with_dodag_preference(100).with_signature_valid(true);
        state.add_candidate(first);
        state.process_beacon_window();
        state.clear_candidates();

        let second = RootCandidate::new(eui64(2)).with_dodag_preference(200).with_signature_valid(true);
        state.add_candidate(second);
        state.process_beacon_window();
        state.clear_candidates();

        // Advance through holdoff
        assert!(!state.advance_holdoff()); // 2 remaining
        assert!(!state.advance_holdoff()); // 1 remaining
        assert!(state.advance_holdoff());  // Complete

        assert!(!state.is_in_holdoff());
        assert_eq!(state.current_root.as_ref().unwrap().eui64, eui64(2));
    }

    #[test]
    fn multi_root_state_version_change_resets_sfn() {
        // Per 2a.5.4: Reset SFN relative to current root's new epoch
        let mut state = MultiRootState::new();
        let root = RootCandidate::new(eui64(1)).with_signature_valid(true);
        state.add_candidate(root);
        state.process_beacon_window();
        state.current_version = 1;

        let result = state.on_version_change(2, true);

        assert_eq!(result.outcome, VersionChangeOutcome::Accepted);
        assert!(result.sfn_reset);
        assert_eq!(state.current_version, 2);
    }

    #[test]
    fn multi_root_state_version_change_no_change_same_version() {
        let mut state = MultiRootState::new();
        state.current_version = 5;

        let result = state.on_version_change(5, true);

        assert_eq!(result.outcome, VersionChangeOutcome::NoChange);
        assert!(!result.sfn_reset);
    }

    #[test]
    fn multi_root_state_version_change_during_holdoff_resets_counter() {
        // Per 2a.5.4: Version change resets holdoff counter to zero and restarts
        let mut state = MultiRootState::new();
        let first = RootCandidate::new(eui64(1)).with_dodag_preference(100).with_signature_valid(true);
        state.add_candidate(first);
        state.process_beacon_window();
        state.clear_candidates();

        let second = RootCandidate::new(eui64(2)).with_dodag_preference(200).with_signature_valid(true);
        state.add_candidate(second);
        state.process_beacon_window();
        state.current_version = 1;

        // Advance holdoff partway
        state.advance_holdoff(); // 2 remaining
        assert_eq!(state.holdoff_counter, 2);

        // Version change should reset holdoff
        let result = state.on_version_change(2, true);

        assert_eq!(result.outcome, VersionChangeOutcome::HoldoffReset);
        assert!(result.holdoff_reset);
        assert!(result.sfn_reset);
        assert_eq!(state.holdoff_counter, HOLDOFF_SUPERFRAMES);
    }

    #[test]
    fn multi_root_state_version_change_sig_fail_discards_root() {
        // Per 2a.5.4: If signature verification fails, discard current root
        let mut state = MultiRootState::new();
        let root = RootCandidate::new(eui64(1)).with_signature_valid(true);
        state.add_candidate(root);
        state.process_beacon_window();
        state.current_version = 1;

        let result = state.on_version_change(2, false);

        assert_eq!(result.outcome, VersionChangeOutcome::SigFailedDiscard);
        assert!(result.evaluate_candidates);
        assert!(state.current_root.is_none());
    }

    #[test]
    fn multi_root_state_version_change_sig_fail_during_holdoff_cancels() {
        // Per 2a.5.4: Sig fail during holdoff -> immediately evaluate candidates
        let mut state = MultiRootState::new();
        let first = RootCandidate::new(eui64(1)).with_dodag_preference(100).with_signature_valid(true);
        state.add_candidate(first);
        state.process_beacon_window();
        state.clear_candidates();

        let second = RootCandidate::new(eui64(2)).with_dodag_preference(200).with_signature_valid(true);
        state.add_candidate(second);
        state.process_beacon_window();
        state.current_version = 1;

        // Now version change with sig failure
        let result = state.on_version_change(2, false);

        assert_eq!(result.outcome, VersionChangeOutcome::SigFailedDiscard);
        assert!(result.evaluate_candidates);
        assert!(!state.is_in_holdoff());
        assert!(state.holdoff_selected.is_none());
    }

    #[test]
    fn multi_root_state_version_change_resets_desync_state() {
        // Per 2a.5.4 step 2: Reset desync state that depended on prior version
        let mut state = MultiRootState::new();
        let root = RootCandidate::new(eui64(1)).with_signature_valid(true);
        state.add_candidate(root);
        state.process_beacon_window();
        state.current_version = 1;
        state.set_desync_state_version(1);

        let result = state.on_version_change(2, true);

        assert_eq!(result.outcome, VersionChangeOutcome::Accepted);
        assert!(state.desync_state_version.is_none());
    }

    #[test]
    fn multi_root_state_cancel_holdoff() {
        let mut state = MultiRootState::new();
        let first = RootCandidate::new(eui64(1)).with_dodag_preference(100).with_signature_valid(true);
        state.add_candidate(first);
        state.process_beacon_window();
        state.clear_candidates();

        let second = RootCandidate::new(eui64(2)).with_dodag_preference(200).with_signature_valid(true);
        state.add_candidate(second);
        state.process_beacon_window();

        assert!(state.is_in_holdoff());
        state.cancel_holdoff();

        assert!(!state.is_in_holdoff());
        assert!(state.holdoff_selected.is_none());
    }

    #[test]
    fn multi_root_state_reset() {
        let mut state = MultiRootState::new();
        let root = RootCandidate::new(eui64(1)).with_signature_valid(true);
        state.add_candidate(root);
        state.process_beacon_window();
        state.current_version = 5;
        state.set_desync_state_version(5);

        state.reset();

        assert!(state.current_root.is_none());
        assert_eq!(state.current_version, 0);
        assert!(state.candidates.is_empty());
        assert_eq!(state.holdoff_counter, 0);
        assert!(state.desync_state_version.is_none());
    }

    #[test]
    fn root_candidate_ordering() {
        // Test RootCandidate ordering per spec 2a.5.2

        // Higher DODAG preference wins
        let high_pref = RootCandidate::new(eui64(0xff)).with_dodag_preference(200);
        let low_pref = RootCandidate::new(eui64(0x00)).with_dodag_preference(100);
        assert!(high_pref < low_pref);

        // Same preference, lower stratum wins
        let gnss = RootCandidate::new(eui64(0xff)).with_dodag_preference(128).with_stratum(0);
        let ntp = RootCandidate::new(eui64(0x00)).with_dodag_preference(128).with_stratum(1);
        assert!(gnss < ntp);

        // Same preference and stratum, higher RSSI+SNR wins
        let strong = RootCandidate::new(eui64(0xff))
            .with_dodag_preference(128)
            .with_stratum(1)
            .with_rf_metrics(-70.0, 15.0);
        let weak = RootCandidate::new(eui64(0x00))
            .with_dodag_preference(128)
            .with_stratum(1)
            .with_rf_metrics(-100.0, 5.0);
        assert!(strong < weak);

        // All else equal, lower IID wins
        let low_iid = RootCandidate::new([0, 0, 0, 0, 0, 0, 0, 1])
            .with_dodag_preference(128)
            .with_stratum(1)
            .with_rf_metrics(-80.0, 10.0);
        let high_iid = RootCandidate::new([0, 0, 0, 0, 0, 0, 0, 2])
            .with_dodag_preference(128)
            .with_stratum(1)
            .with_rf_metrics(-80.0, 10.0);
        assert!(low_iid < high_iid);
    }

    #[test]
    fn root_candidate_nan_rf_metrics_sanitized() {
        // NaN RF metrics must be sanitized to defaults to maintain Eq reflexivity
        // (NaN != NaN would break the Eq invariant)
        let nan_rssi = RootCandidate::new(eui64(1)).with_rf_metrics(f32::NAN, 10.0);
        let nan_snr = RootCandidate::new(eui64(1)).with_rf_metrics(-80.0, f32::NAN);
        let both_nan = RootCandidate::new(eui64(1)).with_rf_metrics(f32::NAN, f32::NAN);

        // Check that NaN values are replaced with defaults
        assert_eq!(nan_rssi.rssi_ema, -120.0);
        assert_eq!(nan_rssi.snr_ema, 10.0);
        assert_eq!(nan_snr.rssi_ema, -80.0);
        assert_eq!(nan_snr.snr_ema, -20.0);
        assert_eq!(both_nan.rssi_ema, -120.0);
        assert_eq!(both_nan.snr_ema, -20.0);

        // Verify Eq reflexivity holds (this would fail with NaN)
        assert_eq!(nan_rssi, nan_rssi);
        assert_eq!(nan_snr, nan_snr);
        assert_eq!(both_nan, both_nan);

        // NaN metrics should sort as worst (default values)
        let good_rf = RootCandidate::new(eui64(2))
            .with_dodag_preference(100)
            .with_rf_metrics(-70.0, 15.0);
        let nan_rf = RootCandidate::new(eui64(1))
            .with_dodag_preference(100)
            .with_rf_metrics(f32::NAN, f32::NAN);
        // Good RF should be preferred (sort first)
        assert!(good_rf < nan_rf);
    }

    #[test]
    fn select_root_filters_invalid_signatures() {
        // Per 2a.5.1: Only candidates with valid signatures considered
        let valid = RootCandidate::new(eui64(0xff)).with_dodag_preference(100).with_signature_valid(true);
        let invalid = RootCandidate::new(eui64(0x00))
            .with_dodag_preference(200)
            .with_signature_valid(false);

        let candidates = vec![invalid, valid.clone()];
        let selected = select_root(&candidates);

        assert!(selected.is_some());
        assert_eq!(selected.unwrap().eui64, eui64(0xff));
    }

    #[test]
    fn select_root_empty_returns_none() {
        let candidates: Vec<RootCandidate> = vec![];
        assert!(select_root(&candidates).is_none());
    }

    #[test]
    fn select_root_all_invalid_returns_none() {
        let invalid1 = RootCandidate::new(eui64(1)).with_signature_valid(false);
        let invalid2 = RootCandidate::new(eui64(2)).with_signature_valid(false);

        let candidates = vec![invalid1, invalid2];
        assert!(select_root(&candidates).is_none());
    }

    #[test]
    fn process_beacon_window_returns_correct_candidate_on_duplicate_eui64() {
        // Regression test: when multiple candidates with same eui64 exist
        // (e.g., from multiple beacon receptions), process_beacon_window must
        // return the exact candidate that select_root chose, not a different
        // one with the same eui64 but worse RF metrics.
        let mut state = MultiRootState::new();

        // Two candidates with same eui64 but different RF metrics
        // We bypass add_candidate (which dedupes) by accessing candidates directly
        let worse = RootCandidate::new(eui64(1))
            .with_rssi_ema(-110.0)  // Worse RSSI
            .with_snr_ema(-15.0)
            .with_signature_valid(true);
        let better = RootCandidate::new(eui64(1))
            .with_rssi_ema(-70.0)  // Better RSSI
            .with_snr_ema(10.0)
            .with_signature_valid(true);

        // Insert in order: worse first, then better
        // select_root will pick 'better' due to higher RSSI/SNR
        state.candidates.push(worse.clone());
        state.candidates.push(better.clone());

        let selected = state.process_beacon_window();
        assert!(selected.is_some());

        // The returned reference must have the BETTER metrics,
        // not the WORSE metrics of the first candidate with same eui64
        let result = selected.unwrap();
        assert_eq!(result.rssi_ema, better.rssi_ema);
        assert_eq!(result.snr_ema, better.snr_ema);

        // Also verify current_root has the correct metrics
        let current = state.current_root.as_ref().unwrap();
        assert_eq!(current.rssi_ema, better.rssi_ema);
        assert_eq!(current.snr_ema, better.snr_ema);
    }
}
