//! lichend configuration (TOML).

use serde::Deserialize;
use std::{fs, io, path::Path};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub mesh: MeshConfig,
    pub ipv6: Ipv6Config,
    pub rpl: RplConfig,
}

#[derive(Debug, Deserialize)]
pub struct MeshConfig {
    /// Serial device connected to the LoRa puck, e.g. `/dev/ttyACM0`.
    pub interface: String,
    /// Baud rate for the SLIP serial link (typically unused for USB CDC, kept for hardware UART).
    #[serde(default = "default_baud")]
    pub baud: u32,
    /// TCP address of the lichen-sim server (used when `interface = "sim"`).
    #[serde(default)]
    pub sim_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Ipv6Config {
    /// ULA or GUA prefix delegated to the mesh, e.g. `"fd00:lichen:1::/48"`.
    pub prefix: String,
    /// Upstream interface for internet connectivity, e.g. `"eth0"`.
    pub upstream: String,
}

#[derive(Debug, Deserialize)]
pub struct RplConfig {
    #[serde(default = "default_instance_id")]
    pub instance_id: u8,
    /// `"non-storing"` (MOP 1) or `"storing"` (MOP 2).
    #[serde(default = "default_mop")]
    pub mode: String,
}

fn default_baud() -> u32 { 115_200 }
fn default_instance_id() -> u8 { 1 }
fn default_mop() -> String { "non-storing".to_string() }

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&text)?;
        Ok(config)
    }

    /// Return a minimal default config suitable for `--sim` mode.
    pub fn default_sim() -> Self {
        Config {
            mesh: MeshConfig {
                interface: "sim".to_string(),
                baud: 115_200,
                sim_addr: Some("127.0.0.1:4444".to_string()),
            },
            ipv6: Ipv6Config {
                prefix: "fd00:1::/48".to_string(),
                upstream: "lo".to_string(),
            },
            rpl: RplConfig {
                instance_id: 1,
                mode: "non-storing".to_string(),
            },
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error reading config: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self { ConfigError::Io(e) }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self { ConfigError::Parse(e) }
}
