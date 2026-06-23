//! Shared application utilities for LICHEN CLI tools.
//!
//! Provides common CLI argument parsing stubs and logging setup used by
//! the gateway and simulator binaries. Requires std.

pub mod cli;

pub use cli::CommonArgs;
