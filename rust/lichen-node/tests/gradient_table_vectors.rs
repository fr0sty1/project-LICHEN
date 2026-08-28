// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::str::FromStr;

use lichen_node::{GradientEntry, GradientSource, GradientTable};
use serde::Deserialize;

#[derive(Deserialize)]
struct Document {
    vectors: VectorGroups,
}

#[derive(Deserialize)]
struct VectorGroups {
    table_operations: Vec<TableOperationVector>,
}

#[derive(Deserialize)]
struct TableOperationVector {
    name: String,
    #[serde(default)]
    max_entries: usize,
    #[serde(default)]
    operations: Vec<Operation>,
    #[serde(default)]
    expected_remaining: Vec<String>,
    #[serde(default)]
    expected_evicted: Vec<String>,
}

#[derive(Deserialize)]
struct Operation {
    op: String,
    dest: String,
    #[serde(default)]
    next_hop: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

fn address(value: &str) -> [u8; 16] {
    Ipv6Addr::from_str(value)
        .expect("canonical IPv6 address")
        .octets()
}

#[test]
fn canonical_lookup_promotes_entry_before_lru_eviction() {
    let document: Document = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/gradient_table.json"
    )))
    .expect("gradient-table vectors parse");
    let vector = document
        .vectors
        .table_operations
        .iter()
        .find(|vector| vector.name == "lru_eviction_order")
        .expect("canonical LRU vector exists");
    let mut table = GradientTable::new(vector.max_entries);

    for (sequence, operation) in vector.operations.iter().enumerate() {
        let destination = address(&operation.dest);
        match operation.op.as_str() {
            "update" => {
                let source = match operation.source.as_deref() {
                    Some("announce") => GradientSource::Announce,
                    other => panic!("unsupported gradient source: {other:?}"),
                };
                assert!(table.update(
                    GradientEntry {
                        destination,
                        next_hop: address(operation.next_hop.as_deref().expect("update next hop")),
                        hop_count: 1,
                        seq_num: sequence as u16,
                        source,
                        expires_ms: 10_000,
                        coords: None,
                    },
                    sequence as u32,
                ));
            }
            "lookup" => assert!(table.lookup(&destination, sequence as u32).is_some()),
            other => panic!("unsupported gradient operation: {other}"),
        }
    }

    let remaining: BTreeSet<_> = table.iter().map(|entry| entry.destination).collect();
    let expected_remaining: BTreeSet<_> = vector
        .expected_remaining
        .iter()
        .map(|value| address(value))
        .collect();
    let expected_evicted: BTreeSet<_> = vector
        .expected_evicted
        .iter()
        .map(|value| address(value))
        .collect();

    assert_eq!(remaining, expected_remaining);
    assert!(expected_evicted.is_disjoint(&remaining));
}
