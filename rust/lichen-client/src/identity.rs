// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Client and wire model for the read-only `/config/identity` resource.

use serde::{Deserialize, Serialize};

use crate::Error;

/// IPv6 addresses derived from a node's public identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAddresses {
    /// The node's always-present link-local address, when provisioned.
    #[serde(default)]
    pub link_local: Option<String>,
    /// The node's native `0200::/8` application address, when provisioned.
    #[serde(default)]
    pub primary: Option<String>,
}

/// A node's read-only `GET /config/identity` document.
///
/// Every field is optional because an unprovisioned node returns an empty map,
/// and constrained nodes may expose only the identity material they have.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Node EUI-64 rendered as `0x` followed by sixteen hexadecimal digits.
    #[serde(default)]
    pub eui64: Option<String>,
    /// Ed25519 public key in the representation supplied by the node.
    #[serde(default)]
    pub pubkey: Option<String>,
    /// Short SHA-256 fingerprint suitable for display and comparison.
    #[serde(default)]
    pub pubkey_fingerprint: Option<String>,
    /// IPv6 addresses derived from the public key.
    #[serde(default)]
    pub addrs: Option<IdentityAddresses>,
}

impl NodeIdentity {
    /// Decode a `GET /config/identity` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// Error returned by [`IdentityClient`] operations.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum IdentityClientError {
    /// CoAP transport failed.
    Transport(lichen_coap::client::ClientError),
    /// The node returned a non-success CoAP response.
    CoapResponse {
        /// CoAP response code, such as `4.04`.
        code: String,
    },
    /// The response payload was not a valid identity document.
    Decode(Error),
}

#[cfg(feature = "tokio")]
impl core::fmt::Display for IdentityClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::CoapResponse { code } => {
                write!(f, "get identity failed: CoAP {code}")
            }
            Self::Decode(error) => write!(f, "decode error: {error}"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for IdentityClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::CoapResponse { .. } => None,
            Self::Decode(error) => Some(error),
        }
    }
}

#[cfg(feature = "tokio")]
impl From<lichen_coap::client::ClientError> for IdentityClientError {
    fn from(error: lichen_coap::client::ClientError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(feature = "tokio")]
impl From<Error> for IdentityClientError {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

/// High-level client for the read-only `/config/identity` resource.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct IdentityClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl IdentityClient {
    /// Create a client with no active peer backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch and decode a node's identity document.
    pub async fn get(
        &mut self,
        node: std::net::SocketAddr,
    ) -> Result<NodeIdentity, IdentityClientError> {
        let response = self.coap.get(node, crate::paths::CONFIG_IDENTITY).await?;
        if !response.is_success() {
            return Err(IdentityClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(NodeIdentity::from_cbor(&response.payload)?)
    }

    /// Clear all remembered 5.03 backoff state.
    pub fn clear_all_backoffs(&mut self) {
        self.coap.clear_all_backoffs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn decodes_shared_identity_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/lci_identity.json"
        );
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read lci_identity.json"))
                .expect("parse lci_identity.json");

        for vector in document["vectors"]
            .as_array()
            .expect("vectors must be an array")
            .iter()
            .filter(|vector| vector["op"] == "get")
        {
            let encoded = hex::decode(
                vector["encoded_hex"]
                    .as_str()
                    .expect("GET vector has encoded_hex"),
            )
            .expect("encoded_hex is valid hexadecimal");
            let decoded = NodeIdentity::from_cbor(&encoded)
                .unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
            let input = &vector["input"];

            assert_eq!(decoded.eui64.as_deref(), input["eui64"].as_str());
            assert_eq!(decoded.pubkey.as_deref(), input["pubkey"].as_str());
            assert_eq!(
                decoded.pubkey_fingerprint.as_deref(),
                input["pubkey_fingerprint"].as_str()
            );
            assert_eq!(
                decoded
                    .addrs
                    .as_ref()
                    .and_then(|addresses| addresses.link_local.as_deref()),
                input["addrs"]["link_local"].as_str()
            );
            assert_eq!(
                decoded
                    .addrs
                    .as_ref()
                    .and_then(|addresses| addresses.primary.as_deref()),
                input["addrs"]["primary"].as_str()
            );
        }
    }

    #[test]
    fn rejects_non_map_identity_payload() {
        let mut encoded = Vec::new();
        ciborium::into_writer(&["not", "an", "identity"], &mut encoded).unwrap();
        assert!(NodeIdentity::from_cbor(&encoded).is_err());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_fetches_identity_from_the_identity_path() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let payload = hex::decode("a165657569363472307830303131323233333434353536363737")
            .expect("valid test payload");
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut request_bytes = [0u8; 1280];
            let (length, peer) = server.recv_from(&mut request_bytes).await.unwrap();
            let request = CoapPacket::from_bytes(&request_bytes[..length]).unwrap();
            assert_eq!(request.code(), MessageCode::GET);

            let path: Vec<&str> = request
                .options()
                .map(|option| option.unwrap())
                .filter(|option| option.is_uri_path())
                .map(|option| std::str::from_utf8(option.value).unwrap())
                .collect();
            assert_eq!(path, ["config", "identity"]);

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

        let identity = IdentityClient::new().get(address).await.unwrap();
        assert_eq!(identity.eui64.as_deref(), Some("0x0011223344556677"));
        server_task.await.unwrap();
    }
}
