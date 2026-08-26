// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Node status, neighbor, and routing-table domain types with CBOR wire codecs.
//!
//! Wire contract (firmware `lichen/subsys/lichen/coap/coap_status.c`,
//! `lichen_coap_encode_status_cbor` / `lichen_coap_encode_neighbors_cbor`):
//!
//! - `GET /status` : `{uptime_s, [battery_pct], [battery_mv], mem_free_kb,
//!   time{...}, dodag{...}, radio{...}}`.
//! - `GET /status/neighbors` : `{neighbors: [{addr, rssi_dbm, snr_db, etx,
//!   last_seen_s, trust}]}`.
//! - `GET /status/routes` : `{routes: [{prefix, via, metric, lifetime_s}],
//!   default_route}`.
//!
//! Several radio/link metrics are transported as integers scaled by 10
//! (`duty_cycle_pct`, `snr_db`, `etx`); the accessor methods return the real
//! value.

use serde::{Deserialize, Serialize};

use crate::Error;

/// A node's `GET /status` snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Seconds since boot.
    pub uptime_s: u64,
    /// Battery charge percent, when the board reports it.
    #[serde(default)]
    pub battery_pct: Option<u32>,
    /// Battery voltage in millivolts, when the board reports it.
    #[serde(default)]
    pub battery_mv: Option<u32>,
    /// Free heap in kibibytes.
    pub mem_free_kb: u64,
    /// Wall-clock / time-source status.
    pub time: TimeStatus,
    /// RPL DODAG membership.
    pub dodag: Dodag,
    /// Radio counters.
    pub radio: RadioStatus,
}

impl NodeStatus {
    /// Decode a `GET /status` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// Time-provider status nested in [`NodeStatus`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeStatus {
    /// Whether the node currently has valid wall-clock time.
    pub wall_clock_valid: bool,
    /// Unix seconds, present only when `wall_clock_valid`.
    #[serde(default)]
    pub unix_time: Option<u64>,
    /// Time source class (e.g. `gnss`, `network`), when known.
    #[serde(default)]
    pub source_class: Option<String>,
    /// Time source name, when known.
    #[serde(default)]
    pub source_name: Option<String>,
    /// Seconds since the time was last refreshed.
    pub age_s: u64,
}

/// RPL DODAG membership nested in [`NodeStatus`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dodag {
    /// Whether the node has joined a DODAG.
    pub joined: bool,
    /// RPL rank (`0xffff`-style sentinel when not joined).
    pub rank: u64,
    /// Preferred parent IPv6 address, when there is one.
    #[serde(default)]
    pub parent: Option<String>,
    /// DODAG root IPv6 address, when known.
    #[serde(default)]
    pub root: Option<String>,
}

/// Radio counters nested in [`NodeStatus`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RadioStatus {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    /// Duty cycle percent scaled by 10 (`125` = 12.5 %). See
    /// [`duty_cycle_pct`](Self::duty_cycle_pct).
    #[serde(rename = "duty_cycle_pct")]
    pub duty_cycle_pct_x10: u64,
}

impl RadioStatus {
    /// Duty cycle as a percentage.
    pub fn duty_cycle_pct(&self) -> f64 {
        self.duty_cycle_pct_x10 as f64 / 10.0
    }
}

/// One entry of the `GET /status/neighbors` list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Neighbor {
    /// Neighbor IPv6 address string.
    pub addr: String,
    /// Last-heard RSSI in dBm.
    pub rssi_dbm: i32,
    /// SNR scaled by 10 (`75` = 7.5 dB). See [`snr_db`](Self::snr_db).
    #[serde(rename = "snr_db")]
    pub snr_db_x10: i32,
    /// ETX scaled by 10 (`12` = 1.2). See [`etx`](Self::etx).
    #[serde(rename = "etx")]
    pub etx_x10: u32,
    /// Seconds since the neighbor was last heard.
    pub last_seen_s: u64,
    /// Link-key trust level: `none`, `tofu`, `dane`, `verified`, ...
    pub trust: String,
}

impl Neighbor {
    /// SNR in dB.
    pub fn snr_db(&self) -> f64 {
        self.snr_db_x10 as f64 / 10.0
    }

    /// Expected transmission count.
    pub fn etx(&self) -> f64 {
        self.etx_x10 as f64 / 10.0
    }
}

/// The `GET /status/neighbors` response envelope: `{neighbors: [...]}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Neighbors {
    pub neighbors: Vec<Neighbor>,
}

impl Neighbors {
    /// Decode a `GET /status/neighbors` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// One entry in the `GET /status/routes` routing table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Destination IPv6 prefix in CIDR notation.
    pub prefix: String,
    /// Link-local IPv6 address of the next hop.
    pub via: String,
    /// Route metric reported by the node.
    pub metric: u64,
    /// Remaining route lifetime in seconds.
    pub lifetime_s: u64,
}

/// The `GET /status/routes` response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routes {
    /// Installed routes, in the order reported by the node.
    pub routes: Vec<Route>,
    /// Default next hop, or `None` when the node has no default route.
    #[serde(default)]
    pub default_route: Option<String>,
}

impl Routes {
    /// Decode a `GET /status/routes` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

/// Queue latency/drop statistics from `GET /status/queues`.
///
/// Wire contract (firmware `lichen/apps/gateway/src/status_cbor.c`,
/// `lichen_gateway_encode_queues_cbor`): a 5-element CBOR map with keys
/// `packets_queued`, `dropped_deadline`, `dropped_full`, `max_latency_ms`,
/// `avg_latency_ms`, per spec/appendix-bufferbloat.md "Measuring Queue
/// Latency".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueStats {
    /// Total packets accepted into the TX queue.
    pub packets_queued: u64,
    /// Packets dropped because their deadline expired before TX.
    #[serde(rename = "dropped_deadline")]
    pub dropped_deadline: u64,
    /// Packets dropped because the queue was full and preemption failed.
    #[serde(rename = "dropped_full")]
    pub dropped_full: u64,
    /// Worst-case time a packet spent in the queue, in milliseconds.
    #[serde(rename = "max_latency_ms")]
    pub max_latency_ms: u64,
    /// Smoothed average queue time (EWMA alpha 1/8), in milliseconds.
    #[serde(rename = "avg_latency_ms")]
    pub avg_latency_ms: u64,
}

impl QueueStats {
    /// Decode a `GET /status/queues` CBOR response.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn txt(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn encode(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    /// Oracle: a CBOR map built with the firmware's exact `/status` keys and
    /// nesting (uptime_s, battery_*, mem_free_kb, time{...}, dodag{...},
    /// radio{rx_*,tx_*,rx_errors,duty_cycle_pct,capacity{txq_*,fwd_*}}),
    /// independent of the struct's serde mapping.
    #[test]
    fn status_decodes_firmware_map() {
        let wire = Value::Map(vec![
            (txt("uptime_s"), Value::Integer(3600u64.into())),
            (txt("battery_pct"), Value::Integer(88u64.into())),
            (txt("battery_mv"), Value::Integer(3900u64.into())),
            (txt("mem_free_kb"), Value::Integer(42u64.into())),
            (
                txt("time"),
                Value::Map(vec![
                    (txt("wall_clock_valid"), Value::Bool(true)),
                    (txt("unix_time"), Value::Integer(1_716_742_800u64.into())),
                    (txt("source_class"), txt("gnss")),
                    (txt("age_s"), Value::Integer(5u64.into())),
                ]),
            ),
            (
                txt("dodag"),
                Value::Map(vec![
                    (txt("joined"), Value::Bool(true)),
                    (txt("rank"), Value::Integer(256u64.into())),
                    (txt("parent"), txt("fd00::1")),
                ]),
            ),
            (
                txt("radio"),
                Value::Map(vec![
                    (txt("rx_packets"), Value::Integer(10u64.into())),
                    (txt("tx_packets"), Value::Integer(7u64.into())),
                    (txt("rx_errors"), Value::Integer(1u64.into())),
                    (txt("duty_cycle_pct"), Value::Integer(125u64.into())),
                    (
                        txt("capacity"),
                        Value::Map(vec![
                            (txt("txq_used"), Value::Integer(2u64.into())),
                            (txt("txq_cap"), Value::Integer(4u64.into())),
                            (txt("fwd_used"), Value::Integer(1u64.into())),
                            (txt("fwd_cap"), Value::Integer(8u64.into())),
                        ]),
                    ),
                ]),
            ),
        ]);

        let s = NodeStatus::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(s.uptime_s, 3600);
        assert_eq!(s.battery_pct, Some(88));
        assert_eq!(s.battery_mv, Some(3900));
        assert_eq!(s.mem_free_kb, 42);
        assert!(s.time.wall_clock_valid);
        assert_eq!(s.time.unix_time, Some(1_716_742_800));
        assert_eq!(s.time.source_class.as_deref(), Some("gnss"));
        assert_eq!(s.time.source_name, None);
        assert_eq!(s.time.age_s, 5);
        assert!(s.dodag.joined);
        assert_eq!(s.dodag.rank, 256);
        assert_eq!(s.dodag.parent.as_deref(), Some("fd00::1"));
        assert_eq!(s.dodag.root, None);
        assert_eq!(s.radio.tx_packets, 7);
        assert_eq!(s.radio.duty_cycle_pct_x10, 125);
        assert_eq!(s.radio.duty_cycle_pct(), 12.5);
    }

    /// A node without a battery omits `battery_pct`/`battery_mv`; those must
    /// decode to `None`, not error.
    #[test]
    fn status_without_battery_is_none() {
        let wire = Value::Map(vec![
            (txt("uptime_s"), Value::Integer(1u64.into())),
            (txt("mem_free_kb"), Value::Integer(1u64.into())),
            (
                txt("time"),
                Value::Map(vec![
                    (txt("wall_clock_valid"), Value::Bool(false)),
                    (txt("age_s"), Value::Integer(0u64.into())),
                ]),
            ),
            (
                txt("dodag"),
                Value::Map(vec![
                    (txt("joined"), Value::Bool(false)),
                    (txt("rank"), Value::Integer(65535u64.into())),
                ]),
            ),
            (
                txt("radio"),
                Value::Map(vec![
                    (txt("rx_packets"), Value::Integer(0u64.into())),
                    (txt("tx_packets"), Value::Integer(0u64.into())),
                    (txt("rx_errors"), Value::Integer(0u64.into())),
                    (txt("duty_cycle_pct"), Value::Integer(0u64.into())),
                    (
                        txt("capacity"),
                        Value::Map(vec![
                            (txt("txq_used"), Value::Integer(0u64.into())),
                            (txt("txq_cap"), Value::Integer(4u64.into())),
                            (txt("fwd_used"), Value::Integer(0u64.into())),
                            (txt("fwd_cap"), Value::Integer(8u64.into())),
                        ]),
                    ),
                ]),
            ),
        ]);

        let s = NodeStatus::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(s.battery_pct, None);
        assert_eq!(s.battery_mv, None);
        assert_eq!(s.time.unix_time, None);
        assert!(!s.dodag.joined);
    }

    /// Oracle: firmware `/status/neighbors` envelope with the exact per-entry
    /// keys, including the x10-scaled `snr_db`/`etx`.
    #[test]
    fn neighbors_decode_firmware_envelope() {
        let wire = Value::Map(vec![(
            txt("neighbors"),
            Value::Array(vec![Value::Map(vec![
                (txt("addr"), txt("fd00::2")),
                (txt("rssi_dbm"), Value::Integer((-92i64).into())),
                (txt("snr_db"), Value::Integer(75u64.into())),
                (txt("etx"), Value::Integer(12u64.into())),
                (txt("last_seen_s"), Value::Integer(30u64.into())),
                (txt("trust"), txt("tofu")),
            ])]),
        )]);

        let ns = Neighbors::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(ns.neighbors.len(), 1);
        let n = &ns.neighbors[0];
        assert_eq!(n.addr, "fd00::2");
        assert_eq!(n.rssi_dbm, -92);
        assert_eq!(n.snr_db_x10, 75);
        assert_eq!(n.snr_db(), 7.5);
        assert_eq!(n.etx_x10, 12);
        assert_eq!(n.etx(), 1.2);
        assert_eq!(n.last_seen_s, 30);
        assert_eq!(n.trust, "tofu");
    }

    /// An empty neighbor table is valid and yields an empty list.
    #[test]
    fn neighbors_empty() {
        let wire = Value::Map(vec![(txt("neighbors"), Value::Array(vec![]))]);
        let ns = Neighbors::from_cbor(&encode(&wire)).unwrap();
        assert!(ns.neighbors.is_empty());
    }

    /// Decode every canonical `/status/routes` vector and compare it with the
    /// independently represented JSON input document.
    #[test]
    fn routes_decode_canonical_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test/vectors/lci_routing_table.json"
        )))
        .unwrap();

        for vector in vectors["vectors"].as_array().unwrap() {
            let encoded = hex::decode(vector["encoded_hex"].as_str().unwrap()).unwrap();
            let routes = Routes::from_cbor(&encoded).unwrap();
            let expected: Routes = serde_json::from_value(vector["input"].clone()).unwrap();
            assert_eq!(routes, expected, "vector {}", vector["name"]);
        }
    }

    #[test]
    fn routes_rejects_non_envelope_payload() {
        let wire = Value::Array(vec![]);
        assert!(Routes::from_cbor(&encode(&wire)).is_err());
    }

    /// Oracle: a CBOR map built with the firmware's exact `/status/queues`
    /// keys (`lichen_gateway_encode_queues_cbor`), independent of the
    /// struct's serde mapping.
    #[test]
    fn queue_stats_decode_firmware_map() {
        let wire = Value::Map(vec![
            (txt("packets_queued"), Value::Integer(120u64.into())),
            (txt("dropped_deadline"), Value::Integer(3u64.into())),
            (txt("dropped_full"), Value::Integer(7u64.into())),
            (txt("max_latency_ms"), Value::Integer(950u64.into())),
            (txt("avg_latency_ms"), Value::Integer(88u64.into())),
        ]);

        let q = QueueStats::from_cbor(&encode(&wire)).unwrap();
        assert_eq!(q.packets_queued, 120);
        assert_eq!(q.dropped_deadline, 3);
        assert_eq!(q.dropped_full, 7);
        assert_eq!(q.max_latency_ms, 950);
        assert_eq!(q.avg_latency_ms, 88);
    }
}
