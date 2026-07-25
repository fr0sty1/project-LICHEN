//! Routing integration: wraps lichen-rpl with neighbor tracking and node-level API.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. The `Router`
//! type owns DODAG state, trickle timer, and neighbor table, providing a
//! unified interface for the node's receive/transmit paths.
//!
//! Also provides GPSR geographic forwarding fallback (spec 9.7) when gradient
//! routes are unavailable and LOADng discovery times out.
//!
//! Requires `std` feature for full RPL integration.

mod neighbor;
#[cfg(feature = "std")]
mod router;
#[cfg(feature = "std")]
mod gpsr;
#[cfg(feature = "std")]
mod dtn;
#[cfg(all(test, feature = "std"))]
mod tests;

// Re-exports from neighbor module
pub use neighbor::{
    GeoCoords, LinkEtx, Neighbor, NeighborTable, TrickleSafeLivenessPolicy,
    MAX_NEIGHBORS,
};
#[cfg(feature = "std")]
pub use neighbor::TrickleAwareNeighborLiveness;

// Re-exports from router module
#[cfg(feature = "std")]
pub use router::{
    DioProcessOutcome, RplMaintenanceOutcome, Router,
};

// Re-exports from dtn module
#[cfg(feature = "std")]
pub use dtn::{DtnBuffer, DtnMessage, DTN_BUFFER_MAX_BYTES};

// Re-exports from lichen-rpl
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::{DodagRole, DodagState, ParentCandidate, ROOT_RANK};
#[cfg(feature = "std")]
pub use lichen_rpl::message::{
    Dao, DaoOriginSignature, Dio, DodagConfig, OptionIter, RplError, RplTarget, SignedDaoEnvelope,
    TransitInfo, DAO_ORIGIN_SIGNATURE_LEN, OPT_DODAG_CONFIG, OPT_RPL_TARGET, OPT_TRANSIT_INFO,
};
#[cfg(feature = "std")]
pub use lichen_rpl::routing::{
    DaoPersistentOpenError, DaoProvisionError, DaoRxState, RouteTarget, RoutingTable,
    SourceRoutingHeader,
};
#[cfg(feature = "std")]
pub use lichen_rpl::trickle::{TrickleEvent, TrickleTimer};

// Internal re-exports for router module
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::{
    dao_origin_digest, DaoManager, DaoProcessError, DaoProcessOutcome, DaoProcessTiming,
    DaoTxError, DaoTxState, DaoVerifyError,
};
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::SignatureVerifiedDao;
