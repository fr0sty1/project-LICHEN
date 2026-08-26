// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Client and wire model for the read-only `GET /config` resource.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::Error;

/// A node's `GET /config` document.
///
/// The named fields are the portable LCI fields from §17.5.2. [`raw`](Self::raw)
/// retains implementation-specific configuration values so callers do not lose
/// data exposed by a node with a larger configuration surface.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeConfig {
    /// Complete string-keyed CBOR map returned by the node.
    pub raw: BTreeMap<String, Value>,
    /// Human-readable node name, when configured.
    pub name: Option<String>,
    /// Node role (`leaf`, `router`, or `border-router`), when reported.
    pub role: Option<String>,
    /// Link to the radio configuration resource.
    pub radio_path: Option<String>,
    /// Link to the read-only identity resource.
    pub identity_path: Option<String>,
}

impl NodeConfig {
    /// Decode a string-keyed CBOR map returned by `GET /config`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = std::io::Cursor::new(bytes);
        let raw: BTreeMap<String, Value> =
            ciborium::from_reader(&mut reader).map_err(|error| Error::Decode(error.to_string()))?;
        if reader.position() != bytes.len() as u64 {
            return Err(Error::Decode(
                "trailing bytes after configuration map".into(),
            ));
        }

        Ok(Self {
            name: text_field(&raw, "name"),
            role: text_field(&raw, "role"),
            radio_path: text_field(&raw, "radio"),
            identity_path: text_field(&raw, "identity"),
            raw,
        })
    }
}

fn text_field(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(Value::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

const MAX_UPDATE_BYTES: usize = 4096;
const MAX_MAP_ENTRIES: usize = 64;
const MAX_ARRAY_ENTRIES: usize = 256;
const MAX_ITEMS: usize = 1024;
const MAX_DEPTH: usize = 16;

/// A role accepted by the portable `PUT /config` schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// End device that does not forward mesh traffic.
    Leaf,
    /// Mesh router.
    Router,
    /// Router connecting the mesh to another network.
    BorderRouter,
}

impl NodeRole {
    /// Wire spelling defined by LCI §17.5.2.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Router => "router",
            Self::BorderRouter => "border-router",
        }
    }

    fn is_wire_value(value: &str) -> bool {
        matches!(value, "leaf" | "router" | "border-router")
    }
}

impl core::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A partial, atomic `PUT /config` update.
///
/// `name` and `role` are validated against the portable schema. Other keys are
/// retained as extension values so a client can update implementation-specific
/// settings advertised by the node. The read-only `radio` and `identity` links
/// cannot be included in a mutation.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConfigUpdate {
    values: BTreeMap<String, Value>,
}

impl ConfigUpdate {
    /// Create an empty partial update.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the portable node-name field.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.values.insert("name".into(), Value::Text(name.into()));
        self
    }

    /// Set the portable role field.
    pub fn with_role(mut self, role: NodeRole) -> Self {
        self.values
            .insert("role".into(), Value::Text(role.as_str().into()));
        self
    }

    /// Construct an update from a string-keyed extension-preserving map.
    pub fn try_from_values(values: BTreeMap<String, Value>) -> Result<Self, ConfigUpdateError> {
        validate_update(&values)?;
        Ok(Self { values })
    }

    /// Insert one portable or implementation-specific update value.
    ///
    /// The complete candidate is validated before mutation, so an error leaves
    /// this update unchanged.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Option<Value>, ConfigUpdateError> {
        let key = key.into();
        let mut candidate = self.values.clone();
        candidate.insert(key.clone(), value);
        validate_update(&candidate)?;
        let value = candidate.remove(&key).unwrap();
        Ok(self.values.insert(key, value))
    }

    /// Borrow every value that will be sent to the node.
    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.values
    }

    /// Encode the validated update as one bounded CBOR map.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ConfigUpdateError> {
        validate_config_fields(&self.values)?;
        encode_mutation_map(&self.values)
    }
}

/// Client-side validation or encoding failure for a configuration mutation.
#[derive(Debug)]
pub enum ConfigUpdateError {
    /// A portable field has the wrong type or value.
    InvalidField {
        /// Rejected field name.
        field: String,
        /// Required schema constraint.
        expected: &'static str,
    },
    /// A read-only link was included in a mutation.
    ReadOnlyField(String),
    /// The update exceeds the server's bounded mutation schema.
    Limit(&'static str),
    /// A CBOR tag occurred anywhere in the update.
    TaggedValue,
    /// CBOR encoding failed.
    Encode(Error),
}

impl core::fmt::Display for ConfigUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidField { field, expected } => {
                write!(f, "invalid config field {field:?}: expected {expected}")
            }
            Self::ReadOnlyField(field) => write!(f, "config field {field:?} is read-only"),
            Self::Limit(message) => f.write_str(message),
            Self::TaggedValue => f.write_str("CBOR tags are not allowed in config updates"),
            Self::Encode(error) => write!(f, "encode error: {error}"),
        }
    }
}

impl std::error::Error for ConfigUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_update(values: &BTreeMap<String, Value>) -> Result<(), ConfigUpdateError> {
    validate_config_fields(values)?;
    validate_mutation_map(values)
}

fn validate_config_fields(values: &BTreeMap<String, Value>) -> Result<(), ConfigUpdateError> {
    for (key, value) in values {
        if key.is_empty() {
            return Err(ConfigUpdateError::InvalidField {
                field: key.clone(),
                expected: "a non-empty text key",
            });
        }
        match (key.as_str(), value) {
            ("name", Value::Text(_)) => {}
            ("name", _) => {
                return Err(ConfigUpdateError::InvalidField {
                    field: key.clone(),
                    expected: "a text string",
                });
            }
            ("role", Value::Text(role)) if NodeRole::is_wire_value(role) => {}
            ("role", _) => {
                return Err(ConfigUpdateError::InvalidField {
                    field: key.clone(),
                    expected: "leaf, router, or border-router",
                });
            }
            ("radio" | "identity", _) => {
                return Err(ConfigUpdateError::ReadOnlyField(key.clone()));
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn encode_mutation_map(
    values: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, ConfigUpdateError> {
    validate_mutation_map(values)?;
    let mut encoded = Vec::new();
    ciborium::into_writer(values, &mut encoded)
        .map_err(|error| ConfigUpdateError::Encode(Error::Encode(error.to_string())))?;
    if encoded.len() > MAX_UPDATE_BYTES {
        return Err(ConfigUpdateError::Limit(
            "encoded update exceeds 4096 bytes",
        ));
    }
    Ok(encoded)
}

pub(crate) fn validate_mutation_map(
    values: &BTreeMap<String, Value>,
) -> Result<(), ConfigUpdateError> {
    if values.len() > MAX_MAP_ENTRIES {
        return Err(ConfigUpdateError::Limit("config update exceeds 64 fields"));
    }

    // Match the server's scanner budget: the root map and each top-level key
    // are CBOR items in addition to the values traversed below.
    let mut items = 1 + values.len();
    if items > MAX_ITEMS {
        return Err(ConfigUpdateError::Limit(
            "config update exceeds 1024 CBOR items",
        ));
    }
    for value in values.values() {
        validate_value(value, 1, &mut items)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize, items: &mut usize) -> Result<(), ConfigUpdateError> {
    if depth > MAX_DEPTH {
        return Err(ConfigUpdateError::Limit(
            "config update exceeds CBOR nesting depth 16",
        ));
    }
    *items += 1;
    if *items > MAX_ITEMS {
        return Err(ConfigUpdateError::Limit(
            "config update exceeds 1024 CBOR items",
        ));
    }

    match value {
        Value::Tag(_, _) => Err(ConfigUpdateError::TaggedValue),
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ENTRIES {
                return Err(ConfigUpdateError::Limit(
                    "config update array exceeds 256 entries",
                ));
            }
            for value in values {
                validate_value(value, depth + 1, items)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            if entries.len() > MAX_MAP_ENTRIES {
                return Err(ConfigUpdateError::Limit(
                    "config update map exceeds 64 entries",
                ));
            }
            for (index, (key, value)) in entries.iter().enumerate() {
                if entries[..index].iter().any(|(previous, _)| previous == key) {
                    return Err(ConfigUpdateError::Limit(
                        "config update contains duplicate map keys",
                    ));
                }
                validate_value(key, depth + 1, items)?;
                validate_value(value, depth + 1, items)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Error returned by [`ConfigClient`] operations.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum ConfigClientError {
    /// CoAP transport failed.
    Transport(lichen_coap::client::ClientError),
    /// The node returned a non-success CoAP response.
    CoapResponse {
        /// CoAP response code, such as `4.04`.
        code: String,
    },
    /// The response payload was not a valid configuration document.
    Decode(Error),
    /// The requested update was invalid or could not be encoded.
    InvalidUpdate(ConfigUpdateError),
}

#[cfg(feature = "tokio")]
impl core::fmt::Display for ConfigClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::CoapResponse { code } => write!(f, "config request failed: CoAP {code}"),
            Self::Decode(error) => write!(f, "decode error: {error}"),
            Self::InvalidUpdate(error) => write!(f, "invalid config update: {error}"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for ConfigClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::CoapResponse { .. } => None,
            Self::Decode(error) => Some(error),
            Self::InvalidUpdate(error) => Some(error),
        }
    }
}

#[cfg(feature = "tokio")]
impl From<lichen_coap::client::ClientError> for ConfigClientError {
    fn from(error: lichen_coap::client::ClientError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(feature = "tokio")]
impl From<Error> for ConfigClientError {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[cfg(feature = "tokio")]
impl From<ConfigUpdateError> for ConfigClientError {
    fn from(error: ConfigUpdateError) -> Self {
        Self::InvalidUpdate(error)
    }
}

/// High-level client for the read-only `GET /config` resource.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct ConfigClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl ConfigClient {
    /// Create a client with no active peer backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch and decode a node's configuration document.
    pub async fn get(
        &mut self,
        node: std::net::SocketAddr,
    ) -> Result<NodeConfig, ConfigClientError> {
        let response = self.coap.get(node, crate::paths::CONFIG).await?;
        if !response.is_success() {
            return Err(ConfigClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(NodeConfig::from_cbor(&response.payload)?)
    }

    /// Validate, encode, and atomically apply a partial node-config update.
    pub async fn put(
        &mut self,
        node: std::net::SocketAddr,
        update: &ConfigUpdate,
    ) -> Result<(), ConfigClientError> {
        let payload = update.to_cbor()?;
        let response = self.coap.put(node, crate::paths::CONFIG, &payload).await?;
        if response.code != lichen_coap::MessageCode::CHANGED.0 {
            return Err(ConfigClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(())
    }

    /// Clear all remembered 5.03 backoff state.
    pub fn clear_all_backoffs(&mut self) {
        self.coap.clear_all_backoffs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(value: &str) -> Value {
        Value::Text(value.into())
    }

    fn encode(value: &Value) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::into_writer(value, &mut encoded).unwrap();
        encoded
    }

    #[test]
    fn decodes_spec_fields_and_preserves_extension_values() {
        let encoded = encode(&Value::Map(vec![
            (txt("name"), txt("my-node")),
            (txt("role"), txt("router")),
            (txt("radio"), txt("/config/radio")),
            (txt("identity"), txt("/config/identity")),
            (txt("tx_power_dbm"), Value::Integer(14.into())),
        ]));

        let config = NodeConfig::from_cbor(&encoded).unwrap();
        assert_eq!(config.name.as_deref(), Some("my-node"));
        assert_eq!(config.role.as_deref(), Some("router"));
        assert_eq!(config.radio_path.as_deref(), Some("/config/radio"));
        assert_eq!(config.identity_path.as_deref(), Some("/config/identity"));
        assert_eq!(
            config.raw.get("tx_power_dbm"),
            Some(&Value::Integer(14.into()))
        );
    }

    #[test]
    fn accepts_empty_and_partially_typed_configuration_maps() {
        let empty = NodeConfig::from_cbor(&encode(&Value::Map(Vec::new()))).unwrap();
        assert!(empty.raw.is_empty());
        assert_eq!(empty.name, None);

        let encoded = encode(&Value::Map(vec![
            (txt("name"), Value::Integer(7.into())),
            (txt("role"), txt("leaf")),
        ]));
        let config = NodeConfig::from_cbor(&encoded).unwrap();
        assert_eq!(config.name, None);
        assert_eq!(config.role.as_deref(), Some("leaf"));
        assert_eq!(config.raw.get("name"), Some(&Value::Integer(7.into())));
    }

    #[test]
    fn rejects_non_map_and_non_text_key_payloads() {
        assert!(NodeConfig::from_cbor(&encode(&Value::Array(vec![txt("config")]))).is_err());
        assert!(NodeConfig::from_cbor(&encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            txt("value")
        ),])))
        .is_err());
    }

    #[test]
    fn rejects_truncated_and_trailing_payloads() {
        let valid = encode(&Value::Map(vec![(txt("name"), txt("node"))]));
        assert!(NodeConfig::from_cbor(&valid[..valid.len() - 1]).is_err());

        let mut trailing = valid;
        trailing.push(0);
        assert!(NodeConfig::from_cbor(&trailing).is_err());
    }

    #[test]
    fn put_updates_match_shared_canonical_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/lci_config.json"
        );
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read lci_config.json"))
                .expect("parse lci_config.json");

        for vector in document["vectors"]
            .as_array()
            .expect("vectors must be an array")
            .iter()
            .filter(|vector| vector["op"] == "put" && vector["input"].is_object())
        {
            let values = vector["input"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), json_value(value)))
                .collect();
            let update = ConfigUpdate::try_from_values(values)
                .unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
            let expected = hex::decode(vector["encoded_hex"].as_str().unwrap()).unwrap();
            assert_eq!(update.to_cbor().unwrap(), expected, "{}", vector["name"]);
        }
    }

    fn json_value(value: &serde_json::Value) -> Value {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(value) => Value::Bool(*value),
            serde_json::Value::Number(value) => {
                Value::Integer(value.as_i64().expect("integer vector value").into())
            }
            serde_json::Value::String(value) => Value::Text(value.clone()),
            _ => panic!("unsupported config vector value: {value}"),
        }
    }

    #[test]
    fn update_validates_portable_fields_and_read_only_links_atomically() {
        let mut update = ConfigUpdate::new().with_name("node");
        assert!(update.insert("role", txt("invalid-role")).is_err());
        assert!(!update.values().contains_key("role"));
        assert!(update.insert("radio", txt("/elsewhere")).is_err());
        assert!(!update.values().contains_key("radio"));
        assert!(update.insert("name", Value::Integer(1.into())).is_err());
        assert_eq!(update.values().get("name"), Some(&txt("node")));
    }

    #[test]
    fn update_preserves_extensions_and_rejects_server_forbidden_cbor() {
        let mut update = ConfigUpdate::new().with_role(NodeRole::Router);
        update
            .insert("receive_timeout_ms", Value::Integer(250.into()))
            .unwrap();
        assert_eq!(
            update.values().get("receive_timeout_ms"),
            Some(&Value::Integer(250.into()))
        );
        assert!(update
            .insert("tagged", Value::Tag(29, Box::new(txt("shared"))))
            .is_err());

        let oversized = ConfigUpdate::try_from_values(BTreeMap::from([(
            "extension".into(),
            Value::Bytes(vec![0; MAX_UPDATE_BYTES]),
        )]))
        .unwrap();
        assert!(oversized.to_cbor().is_err());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_fetches_configuration_from_config_path() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let payload = encode(&Value::Map(vec![
            (txt("name"), txt("field-node")),
            (txt("role"), txt("router")),
        ]));
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::GET);
            assert!(request.payload().is_empty());

            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["config"]);

            let mut response_bytes = [0u8; 256];
            let mut response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CONTENT,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            response.payload(&payload).unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        let config = ConfigClient::new().get(address).await.unwrap();
        assert_eq!(config.name.as_deref(), Some("field-node"));
        assert_eq!(config.role.as_deref(), Some("router"));
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_rejects_non_success_response_before_decoding() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            let mut response_bytes = [0u8; 64];
            let response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::NOT_FOUND,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        let error = ConfigClient::new().get(address).await.unwrap_err();
        assert!(matches!(
            error,
            ConfigClientError::CoapResponse { ref code } if code == "4.04"
        ));
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_puts_canonical_update_to_config_path() {
        use lichen_coap::{
            option::content_format, CoapBuilder, CoapPacket, MessageCode, MessageType,
        };
        use tokio::net::UdpSocket;

        let update = ConfigUpdate::new()
            .with_name("relay-1")
            .with_role(NodeRole::BorderRouter);
        let expected =
            hex::decode("a2646e616d656772656c61792d3164726f6c656d626f726465722d726f75746572")
                .unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::PUT);
            assert_eq!(request.payload(), expected);

            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["config"]);
            let format = request
                .options()
                .map(|option| option.unwrap())
                .find(|option| option.is_content_format())
                .unwrap();
            assert_eq!(format.as_uint().unwrap(), content_format::CBOR as u32);

            let mut response_bytes = [0u8; 64];
            let response = CoapBuilder::new(
                &mut response_bytes,
                MessageType::Acknowledgement,
                MessageCode::CHANGED,
                request.message_id(),
                request.token(),
            )
            .unwrap();
            let response_length = response.finish();
            server
                .send_to(&response_bytes[..response_length], peer)
                .await
                .unwrap();
        });

        ConfigClient::new().put(address, &update).await.unwrap();
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_put_rejects_unauthorized_and_unexpected_success_codes() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        for response_code in [MessageCode::UNAUTHORIZED, MessageCode::CONTENT] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let mut request_bytes = [0u8; 1280];
                let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
                let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
                let mut response_bytes = [0u8; 64];
                let response = CoapBuilder::new(
                    &mut response_bytes,
                    MessageType::Acknowledgement,
                    response_code,
                    request.message_id(),
                    request.token(),
                )
                .unwrap();
                let response_length = response.finish();
                server
                    .send_to(&response_bytes[..response_length], peer)
                    .await
                    .unwrap();
            });

            let error = ConfigClient::new()
                .put(address, &ConfigUpdate::new().with_name("renamed"))
                .await
                .unwrap_err();
            assert!(matches!(error, ConfigClientError::CoapResponse { .. }));
            server_task.await.unwrap();
        }
    }
}
