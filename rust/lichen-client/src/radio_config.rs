// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Client and wire model for the read-only `GET /config/radio` operation.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::config::{encode_mutation_map, validate_mutation_map, ConfigUpdateError};
use crate::Error;

/// A node's `GET /config/radio` document.
///
/// Known LCI fields are exposed with their wire types. [`raw`](Self::raw)
/// retains every implementation-specific field returned by the node.
#[derive(Debug, Clone, PartialEq)]
pub struct RadioConfig {
    /// Complete string-keyed CBOR map returned by the node.
    pub raw: BTreeMap<String, Value>,
    /// Center frequency in MHz.
    pub freq_mhz: Option<f64>,
    /// LoRa bandwidth in kHz.
    pub bw_khz: Option<i64>,
    /// LoRa spreading factor.
    pub sf: Option<i64>,
    /// Coding rate, such as `4/5`.
    pub cr: Option<String>,
    /// Transmit power in dBm.
    pub tx_power_dbm: Option<i64>,
    /// LoRa sync word rendered as hexadecimal text.
    pub sync_word: Option<String>,
}

impl RadioConfig {
    /// Decode exactly one string-keyed CBOR map from `GET /config/radio`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = std::io::Cursor::new(bytes);
        let raw: BTreeMap<String, Value> =
            ciborium::from_reader(&mut reader).map_err(|error| Error::Decode(error.to_string()))?;
        if reader.position() != bytes.len() as u64 {
            return Err(Error::Decode(
                "trailing bytes after radio configuration map".into(),
            ));
        }

        Ok(Self {
            freq_mhz: number_field(&raw, "freq_mhz"),
            bw_khz: integer_field(&raw, "bw_khz"),
            sf: integer_field(&raw, "sf"),
            cr: text_field(&raw, "cr"),
            tx_power_dbm: integer_field(&raw, "tx_power_dbm"),
            sync_word: text_field(&raw, "sync_word"),
            raw,
        })
    }
}

fn number_field(map: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    match map.get(key) {
        Some(Value::Float(value)) => Some(*value),
        Some(Value::Integer(value)) => i64::try_from(*value).ok().map(|value| value as f64),
        _ => None,
    }
}

fn integer_field(map: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    match map.get(key) {
        Some(Value::Integer(value)) => i64::try_from(*value).ok(),
        _ => None,
    }
}

fn text_field(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(Value::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

/// A partial, atomic `PUT /config/radio` update.
///
/// Standard radio fields are strictly typed and range-checked. Other fields
/// remain available for node-specific radio extensions.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RadioConfigUpdate {
    values: BTreeMap<String, Value>,
}

impl RadioConfigUpdate {
    /// Create an empty partial update.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an update from a string-keyed extension-preserving map.
    pub fn try_from_values(values: BTreeMap<String, Value>) -> Result<Self, ConfigUpdateError> {
        validate_radio_update(&values)?;
        Ok(Self { values })
    }

    /// Insert one standard or implementation-specific radio setting.
    ///
    /// The complete candidate is validated before mutation, so errors are
    /// atomic and leave this update unchanged.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: Value,
    ) -> Result<Option<Value>, ConfigUpdateError> {
        let key = key.into();
        let mut candidate = self.values.clone();
        candidate.insert(key.clone(), value);
        validate_radio_update(&candidate)?;
        let value = candidate.remove(&key).unwrap();
        Ok(self.values.insert(key, value))
    }

    /// Set the center frequency in MHz.
    pub fn set_freq_mhz(&mut self, value: f64) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("freq_mhz", Value::Float(value))
    }

    /// Set the LoRa bandwidth in kHz.
    pub fn set_bw_khz(&mut self, value: i64) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("bw_khz", Value::Integer(value.into()))
    }

    /// Set the LoRa spreading factor (7 through 12).
    pub fn set_sf(&mut self, value: i64) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("sf", Value::Integer(value.into()))
    }

    /// Set the LoRa coding rate (`4/5` through `4/8`).
    pub fn set_cr(&mut self, value: impl Into<String>) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("cr", Value::Text(value.into()))
    }

    /// Set transmit power in dBm.
    pub fn set_tx_power_dbm(&mut self, value: i64) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("tx_power_dbm", Value::Integer(value.into()))
    }

    /// Set the one-byte LoRa sync word rendered as `0xNN`.
    pub fn set_sync_word(
        &mut self,
        value: impl Into<String>,
    ) -> Result<Option<Value>, ConfigUpdateError> {
        self.insert("sync_word", Value::Text(value.into()))
    }

    /// Borrow every value that will be sent to the node.
    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.values
    }

    /// Encode the validated update as one bounded CBOR map.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ConfigUpdateError> {
        validate_radio_fields(&self.values)?;
        encode_mutation_map(&self.values)
    }
}

fn validate_radio_update(values: &BTreeMap<String, Value>) -> Result<(), ConfigUpdateError> {
    validate_radio_fields(values)?;
    validate_mutation_map(values)
}

fn validate_radio_fields(values: &BTreeMap<String, Value>) -> Result<(), ConfigUpdateError> {
    for (key, value) in values {
        if key.is_empty() {
            return Err(invalid_field(key, "a non-empty text key"));
        }
        match (key.as_str(), value) {
            ("freq_mhz", Value::Float(frequency)) if frequency.is_finite() && *frequency > 0.0 => {}
            ("freq_mhz", Value::Integer(frequency))
                if i64::try_from(*frequency).is_ok_and(|frequency| frequency > 0) => {}
            ("freq_mhz", _) => return Err(invalid_field(key, "a finite positive number")),
            ("bw_khz", Value::Integer(bandwidth))
                if i64::try_from(*bandwidth).is_ok_and(|bandwidth| bandwidth > 0) => {}
            ("bw_khz", _) => return Err(invalid_field(key, "a positive integer")),
            ("sf", Value::Integer(sf))
                if i64::try_from(*sf).is_ok_and(|sf| (7..=12).contains(&sf)) => {}
            ("sf", _) => return Err(invalid_field(key, "an integer from 7 through 12")),
            ("cr", Value::Text(rate)) if matches!(rate.as_str(), "4/5" | "4/6" | "4/7" | "4/8") => {
            }
            ("cr", _) => return Err(invalid_field(key, "4/5, 4/6, 4/7, or 4/8")),
            ("tx_power_dbm", Value::Integer(power)) if i64::try_from(*power).is_ok() => {}
            ("tx_power_dbm", _) => return Err(invalid_field(key, "an integer dBm value")),
            ("sync_word", Value::Text(word)) if valid_sync_word(word) => {}
            ("sync_word", _) => return Err(invalid_field(key, "a one-byte 0xNN hex string")),
            _ => {}
        }
    }
    Ok(())
}

fn invalid_field(field: &str, expected: &'static str) -> ConfigUpdateError {
    ConfigUpdateError::InvalidField {
        field: field.into(),
        expected,
    }
}

fn valid_sync_word(value: &str) -> bool {
    value.len() == 4
        && value.starts_with("0x")
        && value.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

/// Error returned by [`RadioConfigClient`] operations.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum RadioConfigClientError {
    /// CoAP transport failed.
    Transport(lichen_coap::client::ClientError),
    /// The node returned a non-success CoAP response.
    CoapResponse {
        /// CoAP response code, such as `4.04`.
        code: String,
    },
    /// The response payload was not a valid radio-config document.
    Decode(Error),
    /// The requested update was invalid or could not be encoded.
    InvalidUpdate(ConfigUpdateError),
}

#[cfg(feature = "tokio")]
impl core::fmt::Display for RadioConfigClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::CoapResponse { code } => {
                write!(f, "radio config request failed: CoAP {code}")
            }
            Self::Decode(error) => write!(f, "decode error: {error}"),
            Self::InvalidUpdate(error) => write!(f, "invalid radio config update: {error}"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for RadioConfigClientError {
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
impl From<lichen_coap::client::ClientError> for RadioConfigClientError {
    fn from(error: lichen_coap::client::ClientError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(feature = "tokio")]
impl From<Error> for RadioConfigClientError {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[cfg(feature = "tokio")]
impl From<ConfigUpdateError> for RadioConfigClientError {
    fn from(error: ConfigUpdateError) -> Self {
        Self::InvalidUpdate(error)
    }
}

/// High-level client for `GET /config/radio`.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct RadioConfigClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl RadioConfigClient {
    /// Create a client with no active peer backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch and decode a node's radio configuration.
    pub async fn get(
        &mut self,
        node: std::net::SocketAddr,
    ) -> Result<RadioConfig, RadioConfigClientError> {
        let response = self.coap.get(node, crate::paths::CONFIG_RADIO).await?;
        if !response.is_success() {
            return Err(RadioConfigClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(RadioConfig::from_cbor(&response.payload)?)
    }

    /// Validate, encode, and atomically apply a partial radio-config update.
    pub async fn put(
        &mut self,
        node: std::net::SocketAddr,
        update: &RadioConfigUpdate,
    ) -> Result<(), RadioConfigClientError> {
        let payload = update.to_cbor()?;
        let response = self
            .coap
            .put(node, crate::paths::CONFIG_RADIO, &payload)
            .await?;
        if response.code != lichen_coap::MessageCode::CHANGED.0 {
            return Err(RadioConfigClientError::CoapResponse {
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
    fn decodes_shared_get_vectors_and_preserves_extensions() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/lci_radio_config.json"
        );
        let document: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read lci_radio_config.json"),
        )
        .expect("parse lci_radio_config.json");

        for vector in document["vectors"]
            .as_array()
            .expect("vectors must be an array")
            .iter()
            .filter(|vector| vector["op"] == "get")
        {
            let encoded = hex::decode(vector["encoded_hex"].as_str().unwrap()).unwrap();
            let config = RadioConfig::from_cbor(&encoded)
                .unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
            let input = vector["input"].as_object().unwrap();

            assert_eq!(
                config.freq_mhz,
                input.get("freq_mhz").and_then(serde_json::Value::as_f64),
                "{}",
                vector["name"]
            );
            assert_eq!(
                config.bw_khz,
                input.get("bw_khz").and_then(serde_json::Value::as_i64),
                "{}",
                vector["name"]
            );
            assert_eq!(
                config.sf,
                input.get("sf").and_then(serde_json::Value::as_i64),
                "{}",
                vector["name"]
            );
            assert_eq!(
                config.cr.as_deref(),
                input.get("cr").and_then(serde_json::Value::as_str),
                "{}",
                vector["name"]
            );
            assert_eq!(
                config.tx_power_dbm,
                input
                    .get("tx_power_dbm")
                    .and_then(serde_json::Value::as_i64),
                "{}",
                vector["name"]
            );
            assert_eq!(
                config.sync_word.as_deref(),
                input.get("sync_word").and_then(serde_json::Value::as_str),
                "{}",
                vector["name"]
            );
            assert_eq!(config.raw.len(), input.len(), "{}", vector["name"]);
            for key in input.keys() {
                assert!(config.raw.contains_key(key), "{}: {key}", vector["name"]);
            }
        }
    }

    #[test]
    fn known_fields_require_their_wire_types_without_losing_raw_values() {
        let encoded = encode(&Value::Map(vec![
            (txt("freq_mhz"), Value::Integer(915.into())),
            (txt("sf"), Value::Float(9.5)),
            (txt("cr"), Value::Integer(45.into())),
            (txt("vendor_mode"), Value::Bool(true)),
        ]));
        let config = RadioConfig::from_cbor(&encoded).unwrap();

        assert_eq!(config.freq_mhz, Some(915.0));
        assert_eq!(config.sf, None);
        assert_eq!(config.cr, None);
        assert_eq!(config.raw.get("sf"), Some(&Value::Float(9.5)));
        assert_eq!(config.raw.get("vendor_mode"), Some(&Value::Bool(true)));
    }

    #[test]
    fn rejects_non_map_non_text_key_truncated_and_trailing_payloads() {
        assert!(RadioConfig::from_cbor(&encode(&Value::Array(vec![txt("radio")]))).is_err());
        assert!(RadioConfig::from_cbor(&encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            txt("value"),
        )])))
        .is_err());

        let valid = encode(&Value::Map(vec![(txt("sf"), Value::Integer(9.into()))]));
        assert!(RadioConfig::from_cbor(&valid[..valid.len() - 1]).is_err());
        let mut trailing = valid;
        trailing.push(0);
        assert!(RadioConfig::from_cbor(&trailing).is_err());
    }

    #[test]
    fn put_updates_match_shared_canonical_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/lci_radio_config.json"
        );
        let document: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read lci_radio_config.json"),
        )
        .expect("parse lci_radio_config.json");

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
            let update = RadioConfigUpdate::try_from_values(values)
                .unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
            let expected = hex::decode(vector["encoded_hex"].as_str().unwrap()).unwrap();
            assert_eq!(update.to_cbor().unwrap(), expected, "{}", vector["name"]);
        }
    }

    fn json_value(value: &serde_json::Value) -> Value {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(value) => Value::Bool(*value),
            serde_json::Value::Number(value) if value.is_i64() => {
                Value::Integer(value.as_i64().unwrap().into())
            }
            serde_json::Value::Number(value) => Value::Float(value.as_f64().unwrap()),
            serde_json::Value::String(value) => Value::Text(value.clone()),
            _ => panic!("unsupported radio-config vector value: {value}"),
        }
    }

    #[test]
    fn update_validates_standard_fields_atomically() {
        let mut update = RadioConfigUpdate::new();
        update.set_sf(10).unwrap();
        update.set_tx_power_dbm(17).unwrap();
        update.set_freq_mhz(906.875).unwrap();
        update.set_bw_khz(125).unwrap();
        update.set_cr("4/5").unwrap();
        update.set_sync_word("0x34").unwrap();

        for (key, value) in [
            ("sf", Value::Integer(13.into())),
            ("freq_mhz", Value::Float(f64::NAN)),
            ("bw_khz", Value::Integer(0.into())),
            ("cr", txt("5/6")),
            ("tx_power_dbm", Value::Float(17.0)),
            ("sync_word", txt("0x1234")),
        ] {
            let before = update.values().get(key).cloned();
            assert!(update.insert(key, value).is_err(), "{key}");
            assert_eq!(update.values().get(key).cloned(), before, "{key}");
        }
    }

    #[test]
    fn update_preserves_extensions_and_enforces_server_mutation_bounds() {
        let mut update = RadioConfigUpdate::new();
        update
            .insert("vendor_mode", Value::Text("long-range".into()))
            .unwrap();
        assert_eq!(
            update.values().get("vendor_mode"),
            Some(&Value::Text("long-range".into()))
        );
        assert!(update
            .insert("tagged", Value::Tag(29, Box::new(txt("shared"))))
            .is_err());
        assert!(update
            .insert(
                "duplicate_nested",
                Value::Map(vec![(txt("x"), Value::Null), (txt("x"), Value::Null)]),
            )
            .is_err());

        let oversized = RadioConfigUpdate::try_from_values(BTreeMap::from([(
            "vendor_blob".into(),
            Value::Bytes(vec![0; 4096]),
        )]))
        .unwrap();
        assert!(oversized.to_cbor().is_err());

        let too_many = (0..65)
            .map(|index| (format!("vendor_{index}"), Value::Null))
            .collect();
        assert!(RadioConfigUpdate::try_from_values(too_many).is_err());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_fetches_radio_configuration_from_radio_path() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let payload = hex::decode("a268667265715f6d687afb408c9800000000006273660c").unwrap();
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
            assert_eq!(path, ["config", "radio"]);

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

        let config = RadioConfigClient::new().get(address).await.unwrap();
        assert_eq!(config.freq_mhz, Some(915.0));
        assert_eq!(config.sf, Some(12));
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

        let error = RadioConfigClient::new().get(address).await.unwrap_err();
        assert!(matches!(
            error,
            RadioConfigClientError::CoapResponse { ref code } if code == "4.04"
        ));
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_puts_canonical_update_to_radio_path() {
        use lichen_coap::{
            option::content_format, CoapBuilder, CoapPacket, MessageCode, MessageType,
        };
        use tokio::net::UdpSocket;

        let mut update = RadioConfigUpdate::new();
        update.set_sf(10).unwrap();
        update.set_tx_power_dbm(17).unwrap();
        let expected = hex::decode("a26273660a6c74785f706f7765725f64626d11").unwrap();
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
            assert_eq!(path, ["config", "radio"]);
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

        RadioConfigClient::new()
            .put(address, &update)
            .await
            .unwrap();
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

            let mut update = RadioConfigUpdate::new();
            update.set_sf(10).unwrap();
            let error = RadioConfigClient::new()
                .put(address, &update)
                .await
                .unwrap_err();
            assert!(matches!(error, RadioConfigClientError::CoapResponse { .. }));
            server_task.await.unwrap();
        }
    }
}
