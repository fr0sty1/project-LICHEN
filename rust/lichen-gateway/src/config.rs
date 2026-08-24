//! lichend configuration (TOML).

use serde::Deserialize;
use std::{fmt, fs, io, io::Read, path::Path};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub ipv6: Ipv6Config,
    #[serde(default)]
    pub rpl: RplConfig,
    #[serde(default)]
    pub yggdrasil: YggdrasilConfig,
    #[serde(default)]
    pub backhaul: BackhaulConfig,
    #[serde(default)]
    pub gateway_coordination: GatewayCoordinationConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Paths for rollback-resistant gateway security authorities.
#[derive(Debug, Deserialize, Default)]
pub struct SecurityConfig {
    /// Owner-only directory on a rollback domain independent from the gateway
    /// state filesystem (for example a TPM-backed or separately snapshotted
    /// monotonic store). Persistent deployments fail closed when absent.
    #[serde(default)]
    pub rollback_floor_root: Option<std::path::PathBuf>,
}

/// Standalone daemon federation enrollment for GCP-3.
#[derive(Deserialize, Default)]
pub struct GatewayCoordinationConfig {
    /// `disabled`, `psk`, or `open`. Open mode uses the runtime PoP/context
    /// enrollment API and is never silently downgraded to plaintext.
    #[serde(default)]
    pub mode: GatewayFederationMode,
    /// Closed-federation PSK as hexadecimal (minimum 16 decoded bytes).
    #[serde(default)]
    pub psk_hex: Option<SecretString>,
    /// Optional OSCORE master salt as hexadecimal.
    #[serde(default)]
    pub master_salt_hex: Option<SecretString>,
    /// Optional OSCORE ID Context as hexadecimal (maximum 8 decoded bytes).
    #[serde(default)]
    pub id_context_hex: Option<SecretString>,
    /// Ed25519 public keys of configured federation peers, as 32-byte hex.
    #[serde(default)]
    pub peer_public_keys: Vec<String>,
}

/// Heap-backed secret text that is wiped when it leaves scope and is never
/// exposed by formatting implementations.
#[derive(Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Debug for GatewayCoordinationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayCoordinationConfig")
            .field("mode", &self.mode)
            .field("psk_hex", &self.psk_hex.as_ref().map(|_| "[REDACTED]"))
            .field(
                "master_salt_hex",
                &self.master_salt_hex.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "id_context_hex",
                &self.id_context_hex.as_ref().map(|_| "[REDACTED]"),
            )
            .field("peer_public_keys", &self.peer_public_keys)
            .finish()
    }
}

impl GatewayCoordinationConfig {
    fn contains_secret_material(&self) -> bool {
        self.psk_hex.is_some() || self.master_salt_hex.is_some() || self.id_context_hex.is_some()
    }
}

/// Config-selected GCP-3 federation mode.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayFederationMode {
    /// Single-gateway operation; no GCP contexts are installed.
    #[default]
    Disabled,
    /// GCP-3.1 closed federation using a shared PSK and configured peers.
    Psk,
    /// GCP-3.2 open federation using explicit PoP/context enrollment.
    Open,
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

#[derive(Debug, Deserialize)]
pub struct Ipv6Config {
    /// Exact 0200::/8 native address space derived from LICHEN Ed25519 keys
    /// (gateway: external Yggdrasil daemon on Linux; embedded: lite/proxy).
    #[serde(default = "default_ipv6_prefix")]
    pub prefix: String,
    /// Upstream interface for internet connectivity, e.g. `"eth0"`.
    #[serde(default = "default_upstream")]
    pub upstream: String,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            prefix: default_ipv6_prefix(),
            upstream: default_upstream(),
        }
    }
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
fn default_ipv6_prefix() -> String {
    "0200::/8".to_string()
}
fn default_upstream() -> String {
    "eth0".to_string()
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configuration path is not a regular file",
            )
            .into());
        }
        verify_config_metadata(&metadata, false)?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "configuration exceeds the one MiB size limit",
            )
            .into());
        }
        #[cfg(unix)]
        {
            let path_metadata = fs::symlink_metadata(path)?;
            if path_metadata.file_type().is_symlink()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "configuration path changed or is a symbolic link",
                )
                .into());
            }
        }

        let mut text = Zeroizing::new(Vec::new());
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "configuration exceeds the one MiB size limit",
            )
            .into());
        }
        let utf8 = std::str::from_utf8(&text).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "configuration is not UTF-8")
        })?;
        let config: Config = toml::from_str(utf8)?;
        verify_config_metadata(
            &metadata,
            config.gateway_coordination.contains_secret_material(),
        )?;
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
                prefix: "0200::/8".to_string(),
                upstream: "lo".to_string(),
            },
            rpl: RplConfig {
                instance_id: 1,
                mode: "non-storing".to_string(),
            },
            yggdrasil: YggdrasilConfig::default(),
            backhaul: BackhaulConfig::default(),
            gateway_coordination: GatewayCoordinationConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

#[cfg(unix)]
fn verify_config_metadata(metadata: &fs::Metadata, contains_secrets: bool) -> io::Result<()> {
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configuration must not be writable by group or other users",
        ));
    }
    if contains_secrets && metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret-bearing configuration must not be accessible by group or other users",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let effective_uid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration is not owned by the effective user",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_config_metadata(_metadata: &fs::Metadata, _contains_secrets: bool) -> io::Result<()> {
    Ok(())
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    Io(io::Error),
    Parse,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error reading config: {e}"),
            ConfigError::Parse => write!(f, "configuration syntax is invalid (details redacted)"),
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Parse => None,
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(_error: toml::de::Error) -> Self {
        ConfigError::Parse
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH: AtomicU64 = AtomicU64::new(1);

    fn config_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lichen-config-{label}-{}-{}",
            std::process::id(),
            TEST_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn closed_federation_config_is_explicit_and_bounded_by_types() {
        let parsed: Config = toml::from_str(
            r#"
                [gateway_coordination]
                mode = "psk"
                psk_hex = "00112233445566778899aabbccddeeff"
                master_salt_hex = "01020304"
                id_context_hex = "4c494348454e"
                peer_public_keys = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            "#,
        )
        .unwrap();
        assert_eq!(parsed.gateway_coordination.mode, GatewayFederationMode::Psk);
        assert_eq!(parsed.gateway_coordination.peer_public_keys.len(), 1);
    }

    #[test]
    fn default_native_route_covers_complete_0200_prefix() {
        assert_eq!(Config::default_sim().ipv6.prefix, "0200::/8");
        let parsed: Config = toml::from_str("").unwrap();
        assert_eq!(parsed.ipv6.prefix, "0200::/8");
    }

    #[test]
    fn unknown_federation_mode_is_rejected() {
        assert!(toml::from_str::<Config>(
            r#"
                [gateway_coordination]
                mode = "plaintext"
            "#
        )
        .is_err());
    }

    #[test]
    fn secret_configuration_debug_is_redacted() {
        let parsed: Config = toml::from_str(
            r#"
                [gateway_coordination]
                mode = "psk"
                psk_hex = "00112233445566778899aabbccddeeff"
                master_salt_hex = "01020304"
                id_context_hex = "4c494348454e"
            "#,
        )
        .unwrap();
        let debug = format!("{parsed:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("00112233445566778899aabbccddeeff"));
        assert!(!debug.contains("01020304"));
        assert!(!debug.contains("4c494348454e"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_bearing_file_requires_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = config_path("permissions");
        let text =
            "[gateway_coordination]\nmode='psk'\npsk_hex='00112233445566778899aabbccddeeff'\n";
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::from_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::from_file(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nonsecret_configuration_must_not_be_attacker_writable() {
        use std::os::unix::fs::PermissionsExt;

        let path = config_path("integrity-permissions");
        fs::write(&path, "[gateway_coordination]\nmode='disabled'\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Config::from_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::from_file(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn configuration_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let target = config_path("target");
        let link = config_path("link");
        fs::write(&target, "[gateway_coordination]\nmode='disabled'\n").unwrap();
        symlink(&target, &link).unwrap();
        assert!(Config::from_file(&link).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn parse_error_never_echoes_secret_source_text() {
        use std::os::unix::fs::PermissionsExt;

        let path = config_path("parse-redaction");
        let secret = "00112233445566778899aabbccddeeff";
        fs::write(
            &path,
            format!("[gateway_coordination]\nmode='psk'\npsk_hex='{secret}'\ninvalid = [\n"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = Config::from_file(&path).unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn oversized_configuration_is_rejected_before_parsing() {
        use std::os::unix::fs::PermissionsExt;

        let path = config_path("oversized");
        fs::write(&path, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = Config::from_file(&path).unwrap_err();
        assert!(error.to_string().contains("size limit"));
        fs::remove_file(path).unwrap();
    }
}
