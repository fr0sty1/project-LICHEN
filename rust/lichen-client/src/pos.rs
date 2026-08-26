// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Position / location domain type and SenML wire codec.
//!
//! Wire contract (spec `12-apps.md` §18.2): position is carried as a SenML
//! pack (`application/senml+cbor`, RFC 8428). When present, a base record
//! carries the source device (`bn = urn:dev:mac:<eui>:`) and fix time (`bt`),
//! followed by one record per measurement:
//!
//! ```text
//! [ {bn: "urn:dev:mac:0011223344556677:", bt: 1716742800},
//!   {n: "lat",     u: "lat", v: 37.774929},
//!   {n: "lon",     u: "lon", v: -122.419416},
//!   {n: "alt",     u: "m",   v: 10.5},
//!   {n: "hacc",    u: "m",   v: 5.0},
//!   {n: "vacc",    u: "m",   v: 10.0},
//!   {n: "speed",   u: "m/s", v: 1.2},
//!   {n: "heading", u: "deg", v: 45} ]
//! ```
//!
//! NOTE: the firmware does not yet serve the §18.2 position resources
//! (`/sensors/location`, `/pos`, `/pos/cache`); this type implements the
//! spec contract so clients are ready once the node side lands.

use lichen_core::constants::{
    SENML_LOCATION_ALT, SENML_LOCATION_HACC, SENML_LOCATION_HEADING, SENML_LOCATION_LAT,
    SENML_LOCATION_LON, SENML_LOCATION_SPEED, SENML_LOCATION_UNIT_DEG, SENML_LOCATION_UNIT_LAT,
    SENML_LOCATION_UNIT_LON, SENML_LOCATION_UNIT_M, SENML_LOCATION_UNIT_MS, SENML_LOCATION_VACC,
};
use lichen_senml::wire;
use lichen_senml::Record;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Maximum SenML pack size for a position: 8 records, each well under 64 B.
const ENC_BUF_LEN: usize = 512;
/// Upper bound on records decoded from a position pack (base + 7 fields, with
/// headroom for unexpected extras).
const DEC_MAX_RECORDS: usize = 12;

/// A geographic position, encoded on the wire as a SenML pack (spec §18.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Position {
    /// SenML base name identifying the source device, e.g.
    /// `urn:dev:mac:0011223344556677:`. See [`Position::from_eui64`].
    pub device: Option<String>,
    /// Fix time (SenML base time `bt`, Unix seconds); `None` when unknown.
    pub time: Option<u64>,
    /// Latitude in decimal degrees.
    pub lat: f64,
    /// Longitude in decimal degrees.
    pub lon: f64,
    /// Altitude in meters.
    pub alt: Option<f64>,
    /// Ground speed in m/s.
    pub speed: Option<f64>,
    /// Heading in degrees (0..360, 0 = north).
    pub heading: Option<f64>,
    /// Horizontal accuracy (CEP) in meters.
    pub hacc: Option<f64>,
    /// Vertical accuracy in meters.
    pub vacc: Option<f64>,
}

impl Position {
    /// Build a position whose SenML base name is `urn:dev:mac:<eui_hex>:`.
    pub fn from_eui64(eui_hex: &str, lat: f64, lon: f64) -> Self {
        Self {
            device: Some(format!("urn:dev:mac:{eui_hex}:")),
            time: None,
            lat,
            lon,
            alt: None,
            speed: None,
            heading: None,
            hacc: None,
            vacc: None,
        }
    }

    /// Encode as a SenML-CBOR pack (spec §18.2 `application/senml+cbor`).
    ///
    /// Rejects non-finite coordinates and latitudes outside [-90, 90] or
    /// longitudes outside [-180, 180], matching the Python and Zephyr
    /// encoders (`lichen.senml.profiles.location`, `senml_encode_location*`).
    pub fn to_senml_cbor(&self) -> Result<Vec<u8>, Error> {
        Self::validate(self.lat, SENML_LOCATION_LAT, -90.0, 90.0)?;
        Self::validate(self.lon, SENML_LOCATION_LON, -180.0, 180.0)?;
        for (name, value) in [
            (SENML_LOCATION_ALT, self.alt),
            (SENML_LOCATION_SPEED, self.speed),
            (SENML_LOCATION_HEADING, self.heading),
            (SENML_LOCATION_HACC, self.hacc),
            (SENML_LOCATION_VACC, self.vacc),
        ] {
            if let Some(value) = value {
                if !value.is_finite() {
                    return Err(Error::Encode(format!("{name} {value} is NaN or Inf")));
                }
            }
        }

        let mut recs: [Record; 8] = [const { Record::empty() }; 8];
        let mut n = 0;

        if self.device.is_some() || self.time.is_some() {
            recs[n] = Record {
                base_name: self.device.as_deref(),
                base_time: self.time.map(|t| t as f64),
                ..Record::empty()
            };
            n += 1;
        }
        recs[n] = value_record(SENML_LOCATION_LAT, SENML_LOCATION_UNIT_LAT, self.lat);
        n += 1;
        recs[n] = value_record(SENML_LOCATION_LON, SENML_LOCATION_UNIT_LON, self.lon);
        n += 1;
        if let Some(alt) = self.alt {
            recs[n] = value_record(SENML_LOCATION_ALT, SENML_LOCATION_UNIT_M, alt);
            n += 1;
        }
        if let Some(speed) = self.speed {
            recs[n] = value_record(SENML_LOCATION_SPEED, SENML_LOCATION_UNIT_MS, speed);
            n += 1;
        }
        if let Some(heading) = self.heading {
            recs[n] = value_record(SENML_LOCATION_HEADING, SENML_LOCATION_UNIT_DEG, heading);
            n += 1;
        }
        if let Some(hacc) = self.hacc {
            recs[n] = value_record(SENML_LOCATION_HACC, SENML_LOCATION_UNIT_M, hacc);
            n += 1;
        }
        if let Some(vacc) = self.vacc {
            recs[n] = value_record(SENML_LOCATION_VACC, SENML_LOCATION_UNIT_M, vacc);
            n += 1;
        }

        let mut buf = [0u8; ENC_BUF_LEN];
        let written = wire::encode(&recs[..n], &mut buf)
            .map_err(|e| Error::Encode(format!("SenML encode: {e:?}")))?;
        Ok(buf[..written].to_vec())
    }

    /// Shared coordinate validation: finite, within the inclusive range.
    fn validate(value: f64, name: &str, min: f64, max: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::Encode(format!("{name} {value} is NaN or Inf")));
        }
        if !(min..=max).contains(&value) {
            return Err(Error::Encode(format!(
                "{name} {value} out of range [{min}, {max}]"
            )));
        }
        Ok(())
    }

    /// Decode a SenML-CBOR position pack (spec §18.2).
    ///
    /// `lat` and `lon` are required; `bn` and other fields are retained when
    /// present. Base fields may appear on any record per RFC 8428.
    pub fn from_senml_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut recs = [const { Record::empty() }; DEC_MAX_RECORDS];
        let count = wire::decode(bytes, &mut recs)
            .map_err(|e| Error::Decode(format!("SenML decode: {e:?}")))?;

        Self::from_records(&recs[..count])
    }

    fn from_records(recs: &[Record<'_>]) -> Result<Self, Error> {
        let mut device = None;
        let mut time = None;
        let mut lat = None;
        let mut lon = None;
        let mut alt = None;
        let mut speed = None;
        let mut heading = None;
        let mut hacc = None;
        let mut vacc = None;

        for rec in recs {
            if let Some(bn) = rec.base_name {
                device = Some(bn.to_owned());
            }
            if let Some(bt) = rec.base_time {
                time = Some(bt as u64);
            }
            match (rec.name, rec.value) {
                (Some(SENML_LOCATION_LAT), Some(v)) => lat = Some(v),
                (Some(SENML_LOCATION_LON), Some(v)) => lon = Some(v),
                (Some(SENML_LOCATION_ALT), Some(v)) => alt = Some(v),
                (Some(SENML_LOCATION_SPEED), Some(v)) => speed = Some(v),
                (Some(SENML_LOCATION_HEADING), Some(v)) => heading = Some(v),
                (Some(SENML_LOCATION_HACC), Some(v)) => hacc = Some(v),
                (Some(SENML_LOCATION_VACC), Some(v)) => vacc = Some(v),
                _ => {}
            }
        }

        Ok(Self {
            device,
            time,
            lat: lat.ok_or_else(|| Error::Decode("SenML position missing lat".into()))?,
            lon: lon.ok_or_else(|| Error::Decode("SenML position missing lon".into()))?,
            alt,
            speed,
            heading,
            hacc,
            vacc,
        })
    }
}

/// One peer position returned by `GET /pos/cache` (spec §18.2.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PositionCacheEntry {
    /// Peer IPv6 address string.
    pub node: String,
    /// Latitude in decimal degrees.
    pub lat: f64,
    /// Longitude in decimal degrees.
    pub lon: f64,
    /// Unix timestamp associated with the received beacon.
    pub ts: f64,
    /// Altitude in metres above the WGS-84 ellipsoid, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<f64>,
    /// Whole seconds elapsed since the beacon timestamp.
    ///
    /// This is signed because a peer timestamp ahead of the receiver's clock
    /// produces a negative age.
    pub age_s: i64,
}

/// The `GET /pos/cache` response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PositionCache {
    /// Cached peer positions in the order supplied by the node.
    pub positions: Vec<PositionCacheEntry>,
}

impl PositionCache {
    /// Decode an `application/cbor` response from `GET /pos/cache`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|error| Error::Decode(error.to_string()))
    }
}

/// Result of querying or observing `/sensors/location`.
///
/// A newly started node can return an empty SenML pack before it has acquired
/// its first fix. Keeping that state distinct from a malformed non-empty pack
/// lets clients wait for the first Observe notification without treating the
/// initial response as a protocol error.
#[derive(Debug, Clone, PartialEq)]
pub enum PositionObservation {
    /// The node has no current position fix.
    Unavailable,
    /// The node supplied a current position fix.
    Fix(Position),
}

impl PositionObservation {
    /// Decode an initial query response or Observe notification.
    pub fn from_senml_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut recs = [const { Record::empty() }; DEC_MAX_RECORDS];
        let count = wire::decode(bytes, &mut recs)
            .map_err(|e| Error::Decode(format!("SenML decode: {e:?}")))?;
        if count == 0 {
            return Ok(Self::Unavailable);
        }
        Position::from_records(&recs[..count]).map(Self::Fix)
    }

    /// Return the current fix, or `None` when the node has no fix yet.
    pub fn position(&self) -> Option<&Position> {
        match self {
            Self::Unavailable => None,
            Self::Fix(position) => Some(position),
        }
    }
}

/// Client-side state for a `/sensors/location` Observe relationship.
///
/// The transport passes the initial response and subsequent notification
/// payloads to [`PositionSubscription::accept`]. This type intentionally owns
/// only application state; registration, cancellation, and Observe sequence
/// handling belong to the generic CoAP Observe transport.
#[derive(Debug, Default)]
pub struct PositionSubscription {
    latest: Option<PositionObservation>,
    updates_received: u64,
}

impl PositionSubscription {
    /// Create an empty subscription state before the initial response arrives.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode and retain one initial response or notification payload.
    ///
    /// State is unchanged when decoding fails.
    pub fn accept(&mut self, payload: &[u8]) -> Result<&PositionObservation, Error> {
        let observation = PositionObservation::from_senml_cbor(payload)?;
        self.latest = Some(observation);
        self.updates_received = self.updates_received.saturating_add(1);
        Ok(self.latest.as_ref().expect("observation was just stored"))
    }

    /// Most recently accepted observation, if the initial response arrived.
    pub fn latest(&self) -> Option<&PositionObservation> {
        self.latest.as_ref()
    }

    /// Number of successfully decoded initial responses and notifications.
    pub fn updates_received(&self) -> u64 {
        self.updates_received
    }
}

/// Error returned by [`PositionClient`] query operations.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub enum PositionClientError {
    /// CoAP transport failed.
    Transport(lichen_coap::client::ClientError),
    /// The node returned a non-success CoAP response.
    CoapResponse {
        /// CoAP response code, such as `4.04`.
        code: String,
    },
    /// The response was not a valid position observation.
    Decode(Error),
}

#[cfg(feature = "tokio")]
impl core::fmt::Display for PositionClientError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport error: {error}"),
            Self::CoapResponse { code } => write!(formatter, "position query failed: CoAP {code}"),
            Self::Decode(error) => write!(formatter, "decode error: {error}"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for PositionClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::CoapResponse { .. } => None,
            Self::Decode(error) => Some(error),
        }
    }
}

#[cfg(feature = "tokio")]
impl From<lichen_coap::client::ClientError> for PositionClientError {
    fn from(error: lichen_coap::client::ClientError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(feature = "tokio")]
impl From<Error> for PositionClientError {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

/// Stateful client for querying a peer's current position.
#[cfg(feature = "tokio")]
#[derive(Debug, Default)]
pub struct PositionClient {
    coap: lichen_coap::client::CoapClient,
}

#[cfg(feature = "tokio")]
impl PositionClient {
    /// Create a client with no active peer backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch and decode `GET /sensors/location` from a peer.
    pub async fn query(
        &mut self,
        peer: std::net::SocketAddr,
    ) -> Result<PositionObservation, PositionClientError> {
        let response = self.coap.get(peer, crate::paths::SENSORS_LOCATION).await?;
        if !response.is_success() {
            return Err(PositionClientError::CoapResponse {
                code: response.code_str(),
            });
        }
        Ok(PositionObservation::from_senml_cbor(&response.payload)?)
    }

    /// Clear all remembered 5.03 backoff state.
    pub fn clear_all_backoffs(&mut self) {
        self.coap.clear_all_backoffs();
    }
}

fn value_record<'a>(name: &'a str, unit: &'a str, value: f64) -> Record<'a> {
    Record {
        name: Some(name),
        unit: Some(unit),
        value: Some(value),
        ..Record::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the SenML field names and units mandated by spec §18.2 /
    /// appendix-senml F.3 (`bn`/`bt` base record, then
    /// `lat`/`lon`/`alt`/`speed`/`heading`/`hacc`/`vacc` with units
    /// `lat`/`lon`/`m`/`m/s`/`deg`). Decoded with the raw `lichen-senml`
    /// codec, independent of this module's mapping.
    #[test]
    fn encodes_spec_senml_shape() {
        let p = Position {
            device: Some("urn:dev:mac:0011223344556677:".into()),
            time: Some(1_716_742_800),
            lat: 37.774929,
            lon: -122.419416,
            alt: Some(10.5),
            speed: Some(1.2),
            heading: Some(45.0),
            hacc: Some(5.0),
            vacc: Some(10.0),
        };
        let bytes = p.to_senml_cbor().unwrap();

        let mut recs = [const { Record::empty() }; DEC_MAX_RECORDS];
        let n = wire::decode(&bytes, &mut recs).unwrap();

        assert_eq!(recs[0].base_name, Some("urn:dev:mac:0011223344556677:"));
        assert_eq!(recs[0].base_time, Some(1_716_742_800.0));

        let find = |name: &str| recs[..n].iter().find(|r| r.name == Some(name));
        let lat = find(SENML_LOCATION_LAT).expect("lat record");
        assert_eq!(
            (lat.unit, lat.value),
            (Some(SENML_LOCATION_UNIT_LAT), Some(37.774929))
        );
        let lon = find(SENML_LOCATION_LON).expect("lon record");
        assert_eq!(
            (lon.unit, lon.value),
            (Some(SENML_LOCATION_UNIT_LON), Some(-122.419416))
        );
        let alt = find(SENML_LOCATION_ALT).expect("alt record");
        assert_eq!(
            (alt.unit, alt.value),
            (Some(SENML_LOCATION_UNIT_M), Some(10.5))
        );
        let speed = find(SENML_LOCATION_SPEED).expect("speed record");
        assert_eq!(
            (speed.unit, speed.value),
            (Some(SENML_LOCATION_UNIT_MS), Some(1.2))
        );
        let heading = find(SENML_LOCATION_HEADING).expect("heading record");
        assert_eq!(
            (heading.unit, heading.value),
            (Some(SENML_LOCATION_UNIT_DEG), Some(45.0))
        );
        let hacc = find(SENML_LOCATION_HACC).expect("hacc record");
        assert_eq!(
            (hacc.unit, hacc.value),
            (Some(SENML_LOCATION_UNIT_M), Some(5.0))
        );
        let vacc = find(SENML_LOCATION_VACC).expect("vacc record");
        assert_eq!(
            (vacc.unit, vacc.value),
            (Some(SENML_LOCATION_UNIT_M), Some(10.0))
        );
    }

    /// Oracle: an explicitly built spec-shaped SenML pack (independent of the
    /// encoder under test) decodes into the expected [`Position`] fields.
    #[test]
    fn decodes_spec_senml() {
        let recs = [
            Record {
                base_name: Some("urn:dev:mac:aabb:"),
                base_time: Some(1_716_742_800.0),
                ..Record::empty()
            },
            value_record(SENML_LOCATION_LAT, SENML_LOCATION_UNIT_LAT, 37.0),
            value_record(SENML_LOCATION_LON, SENML_LOCATION_UNIT_LON, -122.0),
            value_record(SENML_LOCATION_ALT, SENML_LOCATION_UNIT_M, 5.0),
        ];
        let mut buf = [0u8; ENC_BUF_LEN];
        let n = wire::encode(&recs, &mut buf).unwrap();

        let p = Position::from_senml_cbor(&buf[..n]).unwrap();
        assert_eq!(p.device.as_deref(), Some("urn:dev:mac:aabb:"));
        assert_eq!(p.time, Some(1_716_742_800));
        assert_eq!(p.lat, 37.0);
        assert_eq!(p.lon, -122.0);
        assert_eq!(p.alt, Some(5.0));
        assert_eq!(p.speed, None);
        assert_eq!(p.heading, None);
        assert_eq!(p.hacc, None);
        assert_eq!(p.vacc, None);
    }

    /// A full position survives an encode/decode round trip unchanged.
    #[test]
    fn round_trips() {
        let p = Position {
            device: Some("urn:dev:mac:dead:".into()),
            time: Some(42),
            lat: 1.5,
            lon: -2.5,
            alt: Some(3.5),
            speed: Some(0.0),
            heading: Some(359.0),
            hacc: Some(2.0),
            vacc: Some(5.0),
        };
        let bytes = p.to_senml_cbor().unwrap();
        assert_eq!(Position::from_senml_cbor(&bytes).unwrap(), p);
    }

    /// A pack without `lat` is not a valid position and must be rejected.
    #[test]
    fn decode_missing_lat_errors() {
        let recs = [
            Record {
                base_name: Some("urn:dev:mac:x:"),
                ..Record::empty()
            },
            value_record(SENML_LOCATION_LON, SENML_LOCATION_UNIT_LON, 1.0),
        ];
        let mut buf = [0u8; ENC_BUF_LEN];
        let n = wire::encode(&recs, &mut buf).unwrap();
        assert!(Position::from_senml_cbor(&buf[..n]).is_err());
    }

    #[test]
    fn decodes_position_without_base_name() {
        let recs = [
            value_record(SENML_LOCATION_LAT, SENML_LOCATION_UNIT_LAT, 37.0),
            value_record(SENML_LOCATION_LON, SENML_LOCATION_UNIT_LON, -122.0),
        ];
        let mut buf = [0u8; ENC_BUF_LEN];
        let n = wire::encode(&recs, &mut buf).unwrap();

        let position = Position::from_senml_cbor(&buf[..n]).unwrap();
        assert_eq!(position.device, None);
        assert_eq!((position.lat, position.lon), (37.0, -122.0));
    }

    #[test]
    fn empty_pack_is_an_unavailable_observation() {
        let observation = PositionObservation::from_senml_cbor(&[0x80]).unwrap();
        assert_eq!(observation, PositionObservation::Unavailable);
        assert_eq!(observation.position(), None);
    }

    #[test]
    fn subscription_decodes_shared_observe_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/position_observe.json"
        );
        let document: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).expect("read position_observe.json"),
        )
        .expect("parse position_observe.json");
        let vector = &document["vectors"][0];

        let mut subscription = PositionSubscription::new();
        let initial = hex::decode(
            vector["initial_response_hex"]
                .as_str()
                .expect("initial response hex"),
        )
        .expect("valid initial response hex");
        assert_eq!(
            subscription.accept(&initial).unwrap(),
            &PositionObservation::Unavailable
        );

        let expected = [
            (37.774929, -122.419416, None),
            (37.7751, -122.4193, Some(32.5)),
            (48.2049, 16.371, None),
        ];
        for (encoded, (lat, lon, alt)) in vector["notification_payloads_hex"]
            .as_array()
            .expect("notification payloads")
            .iter()
            .zip(expected)
        {
            let payload = hex::decode(encoded.as_str().expect("notification hex"))
                .expect("valid notification hex");
            let position = subscription
                .accept(&payload)
                .unwrap()
                .position()
                .expect("notification contains a fix");
            assert_eq!((position.lat, position.lon, position.alt), (lat, lon, alt));
        }

        assert_eq!(subscription.updates_received(), 4);
        assert!(subscription
            .latest()
            .and_then(PositionObservation::position)
            .is_some());
    }

    #[test]
    fn subscription_keeps_state_when_notification_is_invalid() {
        let valid = Position {
            device: None,
            time: None,
            lat: 1.0,
            lon: 2.0,
            alt: None,
            speed: None,
            heading: None,
            hacc: None,
            vacc: None,
        }
        .to_senml_cbor()
        .unwrap();
        let mut subscription = PositionSubscription::new();
        subscription.accept(&valid).unwrap();

        assert!(subscription.accept(&[0xff]).is_err());
        assert_eq!(subscription.updates_received(), 1);
        let latest = subscription.latest().unwrap().position().unwrap();
        assert_eq!((latest.lat, latest.lon), (1.0, 2.0));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_queries_peer_location_resource() {
        use lichen_coap::{CoapBuilder, CoapPacket, MessageCode, MessageType};
        use tokio::net::UdpSocket;

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let expected = Position {
            device: Some("urn:dev:mac:0011223344556677:".into()),
            time: Some(1_716_742_800),
            lat: 37.774929,
            lon: -122.419416,
            alt: Some(10.5),
            speed: None,
            heading: None,
            hacc: None,
            vacc: None,
        };
        let payload = expected.to_senml_cbor().unwrap();

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
            assert_eq!(path, ["sensors", "location"]);

            let mut response_bytes = [0u8; 1024];
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

        let observation = PositionClient::new().query(address).await.unwrap();
        assert_eq!(observation, PositionObservation::Fix(expected));
        server_task.await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn client_reports_non_success_response_code() {
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

        let error = PositionClient::new().query(address).await.unwrap_err();
        assert!(matches!(
            error,
            PositionClientError::CoapResponse { code } if code == "4.04"
        ));
        server_task.await.unwrap();
    }
}
