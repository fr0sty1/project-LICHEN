//! Routing stubs: RPL (RFC 6550), Announce, and LOADng fallback.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. Announce
//! messages (spec §05-routing) provide peer discovery. LOADng is a fallback
//! for multi-hop paths that do not have a border router.

use lichen_core::constants::{RPL_INSTANCE_ID, RPL_MODE_OF_OPERATION};

/// Routing protocol selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoutingMode {
    Rpl,
    Announce,
    Loadng,
}

/// Minimal RPL instance state stub.
pub struct RplInstance {
    pub instance_id: u8,
    pub mode_of_operation: u8,
    pub rank: u16,
}

impl RplInstance {
    pub const fn default_instance() -> Self {
        Self {
            instance_id: RPL_INSTANCE_ID,
            mode_of_operation: RPL_MODE_OF_OPERATION,
            rank: u16::MAX, // Infinity until DODAG join
        }
    }
}
