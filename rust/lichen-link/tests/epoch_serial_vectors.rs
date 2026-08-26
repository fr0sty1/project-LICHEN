// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! 24-bit serial `(epoch << 16) | seqnum` vs `epoch_rollover.json`.

use lichen_link::logical_counter;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/epoch_rollover.json");

fn visit_counters(value: &Value, visit: &mut impl FnMut(u8, u16, u32)) {
    match value {
        Value::Object(map) => {
            if let (Some(epoch), Some(seqnum), Some(counter)) = (
                map.get("epoch").and_then(Value::as_u64),
                map.get("seqnum").and_then(Value::as_u64),
                map.get("counter").and_then(Value::as_u64),
            ) {
                visit(epoch as u8, seqnum as u16, counter as u32);
            }
            for child in map.values() {
                visit_counters(child, visit);
            }
        }
        Value::Array(items) => {
            for child in items {
                visit_counters(child, visit);
            }
        }
        _ => {}
    }
}

#[test]
fn epoch_rollover_counters_match_24bit_serial() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let mut n = 0;
    visit_counters(&document, &mut |epoch, seqnum, counter| {
        assert_eq!(
            logical_counter(epoch, seqnum),
            counter,
            "epoch={epoch} seqnum={seqnum}"
        );
        n += 1;
    });
    assert!(n >= 10, "expected many counter triples, got {n}");
}
