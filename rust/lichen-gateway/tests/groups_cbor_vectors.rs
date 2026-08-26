// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_gateway::membership::Group;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/groups_cbor.json");

#[test]
fn groups_cbor_vectors_populate_domain_type() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    let mut saw_group = false;
    let mut saw_list = false;
    for case in document["vectors"].as_array().unwrap() {
        match case["kind"].as_str().unwrap() {
            "group" => {
                let payload = &case["payload"];
                let owner = payload["owner"].as_str().unwrap().to_string();
                let mut group = Group::new(
                    payload["id"].as_str().unwrap().to_string(),
                    payload["name"].as_str().unwrap().to_string(),
                    payload["mcast"].as_str().unwrap().to_string(),
                    owner,
                    payload["created"].as_u64().unwrap(),
                );
                group.admins = payload["admins"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                group.members = payload["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                group.key_id = payload["key_id"].as_str().map(str::to_string);
                group.key_epoch = payload["key_epoch"].as_u64().unwrap() as u32;
                assert_eq!(group.id, "team-alpha");
                assert_eq!(group.member_count(), 3);
                assert!(group.members.contains(&group.owner));
                saw_group = true;
            }
            "list" => {
                let groups = case["payload"]["groups"].as_array().unwrap();
                assert_eq!(groups.len(), 2);
                assert_eq!(groups[0]["members"], 3);
                saw_list = true;
            }
            other => panic!("unknown kind {other}"),
        }
    }
    assert!(saw_group && saw_list);
}
