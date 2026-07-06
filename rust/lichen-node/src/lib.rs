//! LICHEN node integration crate.
//!
//! Combines the link layer, SCHC compression, CoAP stack, and RPL routing
//! into a single surface for embedded node firmware. The `Node` type is the
//! main entry point; it owns the per-layer state and dispatches received
//! frames down the receive path and up the transmit path.
//!
//! The `Stack` type (std only) provides the full TX/RX path over a radio.
//!
//! # Integration Testing
//!
//! This crate has integration tests that exercise the full protocol path without mocking:
//!
//! - **`stack::tests::stack_ping_pong`** — Two `Stack` instances connected via `LoopbackRadio`.
//!   Alice sends ICMPv6 Echo Request → Radio TX → L2 sign → SCHC compress → wire →
//!   Radio RX → L2 verify → SCHC decompress → IPv6 → ICMPv6 → Echo Reply back.
//!   Real crypto, real compression, real packet handling.
//!
//! - **`stack::tests::stack_send_get_loopback`** — CoAP GET request over the full stack.
//!   Exercises CoAP → IPv6/UDP → SCHC → L2 → Radio path.
//!
//! - **`node::tests::echo_request_to_self_yields_reply`** — SCHC-compressed Echo Request
//!   processed through the node's `handle_frame` path with reply verification.
//!
//! These tests catch integration bugs that unit tests miss: compression/decompression
//! round-trip issues, L2 signature verification across peers, message ID threading, etc.
//!
//! Run with: `cargo test --features std`

#![no_std]

pub mod dispatch;
pub mod node;
pub mod port_dispatch;
pub mod routing;
#[cfg(feature = "std")]
pub mod stack;
#[cfg(feature = "std")]
pub mod secure;

pub use dispatch::{Dispatcher, Resource, Request, Response};
pub use node::{Node, RplEvent};
pub use port_dispatch::{dispatch_by_port, AppProtocol, DispatchError, Dispatched, UdpDispatchError};
#[cfg(feature = "std")]
pub use node::RplNode;
pub use routing::{NeighborTable, Neighbor};
#[cfg(feature = "std")]
pub use routing::Router;
#[cfg(feature = "std")]
pub use stack::{Stack, TxError, RxError, ReceivedIpv6};
#[cfg(feature = "std")]
pub use lichen_link::link_layer::LinkRxError;
#[cfg(feature = "std")]
pub use secure::{SecureStack, SecureError};

#[cfg(feature = "std")]
extern crate std;
