//! LICHEN node integration crate.
//!
//! Combines the link layer, SCHC compression, CoAP stack, and RPL routing
//! into a single surface for embedded node firmware. The `Node` type is the
//! main entry point; it owns the per-layer state and dispatches received
//! frames down the receive path and up the transmit path.
//!
//! # Stack Types
//!
//! For CoAP communication, use [`SecureStack`] (the default). Per spec section 8.7,
//! **all CoAP traffic MUST use OSCORE end-to-end encryption**.
//!
//! - **[`SecureStack`]** — OSCORE-protected CoAP. Use this for all application traffic.
//! # Integration Testing
//!
//! This crate has integration tests that exercise the full protocol path without mocking:
//!
//! - **`stack::tests::stack_ping_pong`** — Two `Stack` instances connected via `LoopbackRadio`.
//!   Alice sends ICMPv6 Echo Request → Radio TX → L2 sign → SCHC compress → wire →
//!   Radio RX → L2 verify → SCHC decompress → IPv6 → ICMPv6 → Echo Reply back.
//!   Real crypto, real compression, real packet handling.
//!
//! - **`secure::tests::secure_stack_oscore_roundtrip`** — OSCORE-protected CoAP GET
//!   over the full stack with end-to-end encryption.
//!
//! - **`node::tests::echo_request_to_self_yields_reply`** — SCHC-compressed Echo Request
//!   processed through the node's `handle_frame` path with reply verification.
//!
//! These tests catch integration bugs that unit tests miss: compression/decompression
//! round-trip issues, L2 signature verification across peers, message ID threading, etc.
//!
//! Run with: `cargo test --features std`

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod announce;
pub mod dispatch;
#[cfg(feature = "std")]
pub mod forward_buffer;
pub mod gradient;
pub mod hybrid;
pub mod node;
pub mod port_dispatch;
pub mod routing;
#[cfg(feature = "std")]
pub mod rpl_stack;
#[cfg(feature = "std")]
pub mod runtime;
#[cfg(feature = "std")]
pub mod scheduler;
#[cfg(feature = "std")]
pub mod secure;
#[cfg(feature = "std")]
pub mod stack;
#[cfg(feature = "std")]
pub mod tdma_scheduler;

#[cfg(feature = "std")]
pub use announce::{
    seq_gt, AnnounceProcessor, AnnounceRejectReason, AnnounceResult, MAX_TRACKED_ORIGINATORS,
};
pub use dispatch::{Dispatcher, Request, Resource, Response};
#[cfg(feature = "std")]
pub use gradient::GradientTable;
pub use gradient::{
    GeoCoords, GradientEntry, GradientSource, DATA_GRADIENT_TIMEOUT_MS, GRADIENT_TIMEOUT_MS,
};
pub use hybrid::{AddressClass, RouteDecision, RouteResult};
#[cfg(feature = "std")]
pub use hybrid::{HybridRouter, MeshPrefix, PendingPacket};
#[cfg(feature = "std")]
pub use node::RplNode;
pub use node::{Node, RplEvent};
pub use port_dispatch::{
    dispatch_by_port, AppProtocol, DispatchError, Dispatched, UdpDispatchError,
};
#[cfg(feature = "std")]
pub use routing::{DtnBuffer, DtnMessage, RouteTarget, Router, DTN_BUFFER_MAX_BYTES};
pub use routing::{Neighbor, NeighborTable, TrickleAwareNeighborLiveness, TrickleSafeLivenessPolicy};
// SECURITY: SecureStack is the primary export for CoAP traffic per spec section 8.7.
// Use Stack (PlaintextStack) only for ICMPv6, diagnostics, or testing.
#[cfg(feature = "std")]
pub use secure::{SecureError, SecureStack};
#[cfg(feature = "std")]
pub use stack::{ReceivedIpv6, RxError, Stack, TxError};
/// Type alias for `Stack` — use only for ICMPv6, diagnostics, or testing.
/// For CoAP traffic, use [`SecureStack`] instead (per spec section 8.7).
#[cfg(feature = "std")]
pub type PlaintextStack<R> = Stack<R>;
#[cfg(feature = "std")]
pub use forward_buffer::{
    ForwardBuffer, ForwardEntry, ForwardError, ForwardStats, MAX_FORWARDING_SOURCES,
    MAX_PACKETS_PER_SOURCE,
};
#[cfg(feature = "std")]
pub use lichen_link::link_layer::LinkRxError;
#[cfg(feature = "std")]
pub use scheduler::{AnnounceScheduler, AnnounceTransmitter, SchedulerConfig, SchedulerError};
#[cfg(feature = "std")]
pub use tdma_scheduler::TdmaScheduler;

#[cfg(feature = "std")]
extern crate std;
