//! CLI argument parsing stubs.

/// Arguments common to all LICHEN CLI tools.
///
/// Stub — will be populated with actual argument parsing (likely via `clap`)
/// once the toolchain and dependencies are wired up.
#[derive(Debug)]
pub struct CommonArgs {
    /// Simulator TCP address (e.g. `127.0.0.1:4444`).
    pub sim_addr: String,
    /// API/management TCP port.
    pub api_port: u16,
    /// Verbosity level (0 = quiet, 1 = info, 2 = debug).
    pub verbosity: u8,
}

impl Default for CommonArgs {
    fn default() -> Self {
        Self {
            sim_addr: "127.0.0.1:4444".to_string(),
            api_port: 4445,
            verbosity: 1,
        }
    }
}
