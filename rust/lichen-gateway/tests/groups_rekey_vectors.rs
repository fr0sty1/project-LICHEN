// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_gateway::membership::Group;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/groups_rekey.json");

#[test]
fn rekey_vector_increments_epoch() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    assert_eq!(document["grace_s"].as_u64().unwrap(), 3600);
    let case = &document["vectors"][0];
    let mut group = Group::new(
        "team-alpha".into(),
        "Team Alpha".into(),
        "ff35:0040::1".into(),
        "0200::1111".into(),
        1716742800,
    );
    let removed = case["removed_member"].as_str().unwrap();
    group.members.push(removed.to_string());
    assert_eq!(
        u64::from(group.key_epoch),
        case["initial_epoch"].as_u64().unwrap()
    );
    group.rekey(Some(removed));
    assert_eq!(
        u64::from(group.key_epoch),
        case["after_removal_epoch"].as_u64().unwrap()
    );
    assert!(!group.members.iter().any(|m| m == removed));
}
