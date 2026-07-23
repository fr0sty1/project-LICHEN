//! lichend configuration (TOML).

use serde::Deserialize;
use std::{fs, io, path::Path};

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub mesh: MeshConfig,
    pub ipv6: Ipv6Config,
    pub rpl: RplConfig,
    #[serde(default)]
    pub yggdrasil: YggdrasilConfig,
    #[serde(default)]
    pub backhaul: BackhaulConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct MeshConfig {
    /// Serial device connected to the LoRa puck, e.g. `/dev/ttyACM0`.
    #[serde(default = "default_mesh_interface")]
    pub interface: String,
    /// Baud rate for the SLIP serial link (typically unused for USB CDC, kept for hardware UART).
    #[serde(default = "default_baud")]
    pub baud: u32,
    /// TCP address of the lichen-sim server (used when `interface = "sim"`).
    #[serde(default)]
    pub sim_addr: Option<String>,
    /// HAT type for RAK2287/SX1302 concentrator (e.g. "rak2287" enables direct multi-channel RX/TX).
    #[serde(default)]
    pub hat: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Ipv6Config {
    /// 02xx::/7 from LICHEN Ed25519 (gateway: external yggdrasil daemon on RPi/Linux w/ TUN, yggdrasil.conf peering+privkey+systemd+subnet-advertise-mesh-02xx; embedded: lite/proxy).
    #[serde(default = "default_ipv6_prefix")]
    pub prefix: String,
    /// Upstream interface for internet connectivity, e.g. `"eth0"`.
    #[serde(default = "default_upstream")]
    pub upstream: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct RplConfig {
    #[serde(default = "default_instance_id")]
    pub instance_id: u8,
    #[serde(default = "default_mop")]
    pub mode: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct BackhaulConfig {
    #[serde(default = "default_backhaul_kind")]
    pub kind: String,
    #[serde(default = "default_backhaul_interface")]
    pub interface: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct AutoPeerConfig {
    /// Peer with public Yggdrasil network (baseline connectivity).
    #[serde(default = "default_true")]
    pub public_network: bool,
    /// Register with LICHEN peer registry for direct peering.
    #[serde(default = "default_true")]
    pub lichen_registry: bool,
    /// Enable local mDNS discovery for same-LAN gateways.
    #[serde(default = "default_true")]
    pub local_discovery: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct YggdrasilConfig {
    /// Layered auto-peering (public, registry, local mDNS) per project-LICHEN-zt3c.4.
    #[serde(default)]
    pub auto_peer: AutoPeerConfig,
    /// Manual peers (optional).
    #[serde(default)]
    pub peers: Vec<String>,
    /// Path to yggdrasil binary (default: /usr/bin/yggdrasil).
    #[serde(default = "default_ygg_binary")]
    pub binary: String,
}

fn default_baud() -> u32 {
    115_200
}
fn default_mesh_interface() -> String {
    "sim".to_string()
}
fn default_instance_id() -> u8 {
    1
}
fn default_mop() -> String {
    "non-storing".to_string()
}
fn default_true() -> bool {
    true
}
fn default_ygg_binary() -> String {
    "/usr/bin/yggdrasil".to_string()
}
fn default_backhaul_kind() -> String {
    "tun".to_string()
}
fn default_backhaul_interface() -> String {
    "lichen0".to_string()
}

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
                hat: None,
            },
            ipv6: Ipv6Config {
                prefix: "0202::/16".to_string(),
                upstream: "lo".to_string(),
            },
            rpl: RplConfig {
                instance_id: 1,
                mode: "non-storing".to_string(),
            },
            yggdrasil: YggdrasilConfig::default(),
            backhaul: BackhaulConfig::default(),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
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

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Parse(e) => Some(e),
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::Parse(e)
    }
}
