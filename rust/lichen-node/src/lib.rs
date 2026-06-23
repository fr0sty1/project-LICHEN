//! LICHEN node integration crate.
//!
//! Combines the link layer, SCHC compression, CoAP stack, and routing stubs
//! into a single surface for embedded node firmware. The `Node` type is the
//! main entry point; it owns the per-layer state and dispatches received
//! frames down the receive path and up the transmit path.

#![no_std]

pub mod node;
pub mod routing;

pub use node::Node;

#[cfg(feature = "std")]
extern crate std;
